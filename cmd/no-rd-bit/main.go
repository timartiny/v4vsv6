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
	Resolvers  string `arg:"--resolvers,required" help:"(Required) Path to file containing list of Resolvers to query"`
	Domains    string `arg:"--domains,required" help:"(Required) Path to the file containing domains to issue A and AAAA record requests to"`
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

func readResolvers(resolversFile string, sourceIP net.IP) []net.IP {
	f, err := os.Open(resolversFile)
	if err != nil {
		errorLogger.Printf("Error opening resolver file: %s\n", resolversFile)
		errorLogger.Fatalln(err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var sourceAF int
	if sourceIP.To4() == nil {
		sourceAF = 6
	} else {
		sourceAF = 4
	}

	var ret []net.IP

	for scanner.Scan() {
		line := scanner.Text()
		ip := net.ParseIP(line)
		if ip != nil {
			if sourceAF == 4 {
				if ip.To4() == nil {
					errorLogger.Printf(
						"IP: %s has incorrect Address Family, must match AF "+
							"of source IP: %s, skipping\n",
						ip.String(),
						sourceIP.String(),
					)
					continue
				}
			} else {
				if ip.To4() != nil {
					errorLogger.Printf(
						"IP: %s has incorrect Address Family, must match AF "+
							"of source IP: %s, skipping\n",
						ip.String(),
						sourceIP.String(),
					)
					continue
				}
			}
			ret = append(ret, ip)
		}
	}

	return ret
}

func readDomains(domainFile string) []string {
	f, err := os.Open(domainFile)
	if err != nil {
		errorLogger.Printf("Error opening resolver file: %s\n", domainFile)
		errorLogger.Fatalln(err)
	}
	defer f.Close()

	var domains []string

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		domains = append(domains, line)
	}

	return domains
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
				errorLogger.Printf("Failed in dial conn for %s\n", domain)
				return ReturnedInvalidRecord
			}
			tlsConn := tls.Client(dialConn, &config)
			defer tlsConn.Close()
			err = tlsConn.Handshake()
			if err != nil {
				errorLogger.Printf("Failed in tls handshake for %s\n", domain)
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

func resolverWorker(
	domains []string,
	sourceIP net.IP,
	timeout time.Duration,
	resolverChan <-chan net.IP,
	resultChan chan<- DNSResult,
	wg *sync.WaitGroup,
) {
	defer wg.Done()

	for resolverIP := range resolverChan {
		infoLogger.Printf(
			"Running no rd scan for resolver: %s\n",
			resolverIP.String(),
		)
		udpAddr := &net.UDPAddr{
			IP: sourceIP,
		}
		dialer := net.Dialer{
			LocalAddr: udpAddr,
		}
		records := []string{"A", "AAAA"}

		for _, domain := range domains {
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
						errorLogger.Printf(
							"Got CCode of Unknown with no Answers for %s "+
								"resolving %s\n",
							dnsResult.Resolver,
							dnsResult.Domain,
						)
					} else {
						dnsResult.CCode = tlsLookup(domain, dnsResult.Answers, timeout)
					}
				}
				resultChan <- dnsResult
			}
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

// const (
// 	Unknown CensorshipCode = iota
// 	ResolverError
// 	ReturnedAdditionals
// 	ReturnedInvalidRecord
// 	ReturnedValidRecord
// )

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
	resolvers := readResolvers(args.Resolvers, sourceIP)
	if len(resolvers) <= 0 {
		errorLogger.Fatalln("Got no valid resolvers")
	}
	infoLogger.Printf("Got %d resolvers\n", len(resolvers))

	domains := readDomains(args.Domains)
	infoLogger.Printf("Got %d domains\n", len(domains))

	var workersWG sync.WaitGroup
	var saveResultsWG sync.WaitGroup
	resolverChan := make(chan net.IP)
	resultChan := make(chan DNSResult)
	saveResultsWG.Add(1)
	go saveResults(resultChan, args.OutputFile, args.Timeout, &saveResultsWG)

	infoLogger.Printf("Spawning resolver workers")
	for w := uint(0); w < uint(args.Threads); w++ {
		workersWG.Add(1)
		go resolverWorker(
			domains,
			sourceIP,
			connTimeout,
			resolverChan,
			resultChan,
			&workersWG,
		)
	}

	for _, resolver := range resolvers {
		resolverChan <- resolver
	}

	close(resolverChan)
	infoLogger.Println(
		"Waiting for resolvers (and any follow up TLS conns) to finish",
	)
	workersWG.Wait()
	close(resultChan)
	infoLogger.Printf(
		"Waiting for results to be written to %s\n", args.OutputFile,
	)
	saveResultsWG.Wait()
}
