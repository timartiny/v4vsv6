package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/alexflint/go-arg"
	"github.com/miekg/dns"
)

var (
	infoLogger  *log.Logger
	errorLogger *log.Logger
)

type NoRDBitFlags struct {
	InputFile  string `arg:"--input,required" help:"(Required) File to read \"domain,ip\" inputs from"`
	SourceIP   string `arg:"--source-ip" help:"Address to send queries from" default:"192.12.240.40"`
	Threads    int    `arg:"--threads" help:"Number of goroutines to use for queries" default:"1000"`
	Timeout    int    `arg:"--timeout" help:"Number of seconds to wait for DNS and TLS connections" default:"5"`
	OutputFile string `arg:"--output,required" help:"(Required) Path to the file to save results to"`
}

type CensorshipCode uint

const (
	Unknown CensorshipCode = iota
	ResolverResolveError
	ResolverDialError
	ResolverReadError
	ReturnedAdditionals
	ReturnedInvalidRecord
	ReturnedValidRecord
)

type DNSResult struct {
	Resolver string
	Domain   string
	Record   string
	RCode    int
	CCode    CensorshipCode
	Answers  []net.IP
}

type Result struct {
	Resolver    string         `json:"resolver"`
	Domain      string         `json:"domain"`
	Record      string         `json:"record"`
	RCode       int            `json:"r_code"`
	CCode       CensorshipCode `json:"c_code"`
	Explanation string         `json:"explanation"`
}

func setupArgs() NoRDBitFlags {
	var ret NoRDBitFlags
	arg.MustParse(&ret)

	return ret
}

func resolveDomain(
	resolverIP net.IP,
	dialer net.Dialer,
	domain string,
	record string,
	timeout time.Duration,
) DNSResult {
	resolverAddr := resolverIP.String() + ":53"
	if resolverIP.To4() == nil {
		resolverAddr = "[" + resolverIP.String() + "]:53"
	}
	dnsResult := DNSResult{
		Resolver: resolverIP.String(),
		Domain:   domain,
		Record:   record,
		RCode:    -1,
	}
	m := &dns.Msg{
		// no recursion desired
		MsgHdr: dns.MsgHdr{
			Authoritative:     false,
			AuthenticatedData: false,
			CheckingDisabled:  false,
			RecursionDesired:  false,
			Opcode:            dns.OpcodeQuery,
		},
		Question: make([]dns.Question, 1),
	}
	// record request
	var qtype uint16
	switch record {
	case "A":
		qtype = dns.TypeA
	case "AAAA":
		qtype = dns.TypeAAAA
	default:
		errorLogger.Fatalf("Unimplemented record type: %s\n", record)
	}

	m.Question[0] = dns.Question{
		Name:   dns.Fqdn(domain),
		Qtype:  qtype,
		Qclass: uint16(dns.ClassINET),
	}
	m.Id = dns.Id()
	dnsQuery, err := m.Pack()
	if err != nil {
		errorLogger.Printf(
			"Error creating UDP packet for domain: %s (resolver: %s)\n",
			domain,
			resolverAddr,
		)
		errorLogger.Println(err)
		return dnsResult
	}
	func() {
		conn, err := dialer.Dial("udp", resolverAddr)
		if err != nil {
			// errorLogger.Printf(
			// 	"Error creating UDP socket(?): %s\n",
			// 	resolverAddr,
			// )
			// errorLogger.Println(err)
			dnsResult.CCode = ResolverDialError
			return
		}

		defer conn.Close()

		conn.Write(dnsQuery)
		conn.SetReadDeadline(time.Now().Add(timeout))
		resp := make([]byte, 1024)
		_, err = conn.Read(resp)
		if err != nil {
			// errorLogger.Printf(
			// 	"Error reading from %s for %s\n", resolverAddr, domain,
			// )
			// errorLogger.Println(err)
			dnsResult.CCode = ResolverReadError
			return
		}
		var r dns.Msg
		err = r.Unpack(resp)
		if err != nil {
			fmt.Printf(
				"Error Parsing response for %s from %s\n", domain, resolverAddr,
			)
			return
		}
		dnsResult.RCode = r.Rcode
		if dnsResult.RCode != 0 {
			dnsResult.CCode = ResolverResolveError
			return
		}
		if len(r.Answer) > 0 {
			for _, answer := range r.Answer {
				lastTab := strings.LastIndex(answer.String(), "\t")
				strIP := answer.String()[lastTab+1:]
				ip := net.ParseIP(strIP)
				if ip != nil {
					dnsResult.Answers = append(dnsResult.Answers, ip)
				}
			}
			// Actually returned Records, so use that to determine censorship
			return
		}
		// no Answers were given so see if they returned additionals or
		// authorities
		if len(r.Ns) > 0 || len(r.Extra) > 0 {
			dnsResult.CCode = ReturnedAdditionals
		}
	}()

	return dnsResult
}

func tlsLookup(
	domain string, ips []net.IP, timeout time.Duration,
) CensorshipCode {
	config := tls.Config{ServerName: domain}
	for _, ip := range ips {
		ret := func() CensorshipCode {
			dialConn, err := net.DialTimeout(
				"tcp", net.JoinHostPort(ip.String(), "443"), timeout,
			)
			if err != nil {
				return ReturnedInvalidRecord
			}
			tlsConn := tls.Client(dialConn, &config)
			defer tlsConn.Close()
			err = tlsConn.Handshake()
			if err != nil {
				return ReturnedInvalidRecord
			}
			// Leaf Cert
			err = tlsConn.ConnectionState().PeerCertificates[0].VerifyHostname(domain)
			if err != nil {
				return ReturnedInvalidRecord
			} else {
				return ReturnedValidRecord
			}
		}()
		if ret == ReturnedValidRecord {
			return ret
		}
	}

	return ReturnedInvalidRecord
}

func inputWorker(
	sourceIP net.IP,
	timeout time.Duration,
	inputChan <-chan string,
	resultChan chan<- DNSResult,
	wg *sync.WaitGroup,
) {
	defer wg.Done()

	for input := range inputChan {
		udpAddr := &net.UDPAddr{
			IP: sourceIP,
		}
		dialer := net.Dialer{
			LocalAddr: udpAddr,
		}
		records := []string{"A", "AAAA"}
		splitInput := strings.Split(input, ",")
		domain := splitInput[0]
		resolverIP := net.ParseIP(splitInput[1])
		if sourceIP.To4() == nil {
			// source IP is v6 so resolvers need to be v6
			if resolverIP.To4() != nil {
				errorLogger.Printf(
					"Got IPv4 Resolver for IPv6 source IP: %s\n", input,
				)
				errorLogger.Println("Skipping this entry")
				continue
			}
		} else {
			// source IP is v4 so resolvers need to be v6
			if resolverIP.To4() == nil {
				errorLogger.Printf(
					"Got IPv6 Resolver for IPv4 source IP: %s\n", input,
				)
				errorLogger.Println("Skipping this entry")
				continue
			}
		}

		for _, record := range records {
			dnsResult := resolveDomain(
				resolverIP,
				dialer,
				domain,
				record,
				timeout,
			)
			if dnsResult.CCode == Unknown {
				// still need to determine censorship
				if len(dnsResult.Answers) <= 0 {
					// didn't get any answers though, so there's nothing to do
					// errorLogger.Printf(
					// 	"Got CCode of Unknown with no Answers for %s "+
					// 		"resolving %s\n",
					// 	dnsResult.Resolver,
					// 	dnsResult.Domain,
					// )
				} else {
					dnsResult.CCode = tlsLookup(domain, dnsResult.Answers, timeout)
				}
			}
			resultChan <- dnsResult
		}
	}
}

func saveResults(
	resultChan <-chan DNSResult,
	oFilename string,
	timeout int,
	wg *sync.WaitGroup,
) {
	defer wg.Done()
	oFile, err := os.Create(oFilename)
	if err != nil {
		errorLogger.Printf("Error creating file: %s\n", oFilename)
		errorLogger.Fatalln(err)
	}
	defer oFile.Close()

	for dnsResult := range resultChan {
		var result Result
		result.Domain = dnsResult.Domain
		result.Resolver = dnsResult.Resolver
		result.RCode = dnsResult.RCode
		result.CCode = dnsResult.CCode
		result.Record = dnsResult.Record
		switch result.CCode {
		case Unknown:
			result.Explanation = "Unusual Circumstance where c_code is never modified"
		case ResolverDialError:
			result.Explanation = "Failed to make udp socket to resolver"
		case ResolverResolveError:
			result.Explanation = "Resolver encountered error resolving domain, see r_code"
		case ResolverReadError:
			result.Explanation = fmt.Sprintf(
				"Resolver didn't respond during timeout window (%d seconds)",
				timeout,
			)
		case ReturnedAdditionals:
			result.Explanation = "Resolver returned Additionals and/or Authorities"
		case ReturnedInvalidRecord:
			result.Explanation = fmt.Sprintf(
				"Resolver returned %s record, but it failed the TLS check",
				result.Record,
			)
		case ReturnedValidRecord:
			result.Explanation = fmt.Sprintf(
				"Resolver returned %s record, and it passed the TLS check",
				result.Record,
			)
		}
		bBytes, err := json.Marshal(&result)
		if err != nil {
			errorLogger.Printf("Error marshaling result: %v\n", result)
			errorLogger.Fatalln(err)
		}
		oFile.Write(bBytes)
		oFile.WriteString("\n")
	}
}

func lineCounter(fileName string) int {
	file, err := os.Open(fileName)
	if err != nil {
		errorLogger.Printf("Error opening input file: %s\n", fileName)
		errorLogger.Fatalln(err)
	}

	defer file.Close()
	fileScanner := bufio.NewScanner(file)
	lineCount := 0
	for fileScanner.Scan() {
		lineCount++
	}
	return lineCount
}

func main() {
	infoLogger = log.New(
		os.Stderr,
		"INFO: ",
		log.Ldate|log.Ltime|log.Lshortfile,
	)
	errorLogger = log.New(
		os.Stderr,
		"ERROR: ",
		log.Ldate|log.Ltime|log.Lshortfile,
	)
	args := setupArgs()
	connTimeout := time.Second * time.Duration(args.Timeout)
	sourceIP := net.ParseIP(args.SourceIP)
	if sourceIP == nil {
		errorLogger.Fatalf("Invalid Source IP: %s\n", args.SourceIP)
	}

	var workersWG sync.WaitGroup
	var saveResultsWG sync.WaitGroup
	inputChan := make(chan string)
	resultChan := make(chan DNSResult)
	saveResultsWG.Add(1)
	go saveResults(resultChan, args.OutputFile, args.Timeout, &saveResultsWG)

	infoLogger.Printf("Spawning domain workers")
	for w := uint(0); w < uint(args.Threads); w++ {
		workersWG.Add(1)
		go inputWorker(
			sourceIP,
			connTimeout,
			inputChan,
			resultChan,
			&workersWG,
		)
	}

	inputLines := lineCounter(args.InputFile)
	inputFile, _ := os.Open(args.InputFile)
	scanner := bufio.NewScanner(inputFile)
	lineCount := 0
	lastReportedPercentage := -1
	for scanner.Scan() {
		line := scanner.Text()
		lineCount++
		currPercentage := int(100 * (float64(lineCount) / float64(inputLines)))
		if currPercentage > lastReportedPercentage {
			infoLogger.Printf(
				"[%3d%%] Read %d lines of %d\n",
				currPercentage,
				lineCount,
				inputLines,
			)
			lastReportedPercentage = currPercentage
		}
		inputChan <- line
	}

	close(inputChan)
	infoLogger.Println(
		"Waiting for workers to finish",
	)
	workersWG.Wait()
	close(resultChan)
	infoLogger.Printf(
		"Waiting for results to be written to %s\n", args.OutputFile,
	)
	saveResultsWG.Wait()
}
