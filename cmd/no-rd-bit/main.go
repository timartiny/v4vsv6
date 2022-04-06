package main

import (
	"bufio"
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

// // If we want to add a response, do it here
// type Result struct {
// 	ip   net.IP
// 	err  error
// 	resp []byte
// }

// func sendDnsProbe(ip net.IP, domain string, timeout time.Duration, verbose bool, queryType uint16, sourceIP string) (Result, error) {
// 	m := &dns.Msg{
// 		MsgHdr: dns.MsgHdr{
// 			Authoritative:     false,
// 			AuthenticatedData: false,
// 			CheckingDisabled:  false,
// 			RecursionDesired:  true,
// 			Opcode:            dns.OpcodeQuery,
// 		},
// 		Question: make([]dns.Question, 1),
// 	}
// 	m.Question[0] = dns.Question{
// 		Name:   dns.Fqdn(domain),
// 		Qtype:  queryType,
// 		Qclass: uint16(dns.ClassINET),
// 	}
// 	m.Id = dns.Id()

// 	out, err := m.Pack()
// 	if err != nil {
// 		if verbose {
// 			fmt.Printf("%s - Error creating UDP packet: %v\n", ip.String(), err)
// 		}
// 		return Result{}, err
// 	}
// 	addr := ip.String() + ":53"
// 	if ip.To16() != nil {
// 		addr = "[" + ip.String() + "]:53"
// 	}
// 	udpAddr := &net.UDPAddr{
// 		IP: net.ParseIP(sourceIP),
// 	}
// 	dialer := net.Dialer{
// 		LocalAddr: udpAddr,
// 	}

// 	conn, err := dialer.Dial("udp", addr)
// 	if err != nil {
// 		if verbose {
// 			fmt.Printf("%s - Error creating UDP socket(?): %v\n", ip.String(), err)
// 		}
// 		return Result{}, err
// 	}

// 	defer conn.Close()

// 	conn.Write(out)
// 	if verbose {
// 		fmt.Printf("Sent %s - %s - %s\n", ip.String(), domain, hex.EncodeToString(out))
// 	}

// 	if timeout == 0 {
// 		return Result{ip: ip}, nil
// 	}

// 	conn.SetReadDeadline(time.Now().Add(timeout))
// 	resp := make([]byte, 1024)
// 	n, err := conn.Read(resp)
// 	if err != nil {
// 		if verbose {
// 			fmt.Printf("%s - ReadErr: %v\n", ip.String(), err)
// 		}
// 		return Result{}, err
// 	}

// 	var r dns.Msg
// 	err = r.Unpack(resp)
// 	if err != nil {
// 		if verbose {
// 			fmt.Printf("%s - ParseErr: %v\n", ip.String(), err)
// 		}
// 		return Result{
// 			ip:   ip,
// 			err:  err,
// 			resp: resp[:n],
// 		}, err
// 	}
// 	if verbose {

// 		ans := "??"
// 		if res, ok := dns.RcodeToString[r.Rcode]; ok {
// 			ans = res
// 		}
// 		if len(r.Answer) > 0 {
// 			// Take first answer
// 			ans += ": " + r.Answer[0].String()
// 		}
// 		fmt.Printf("%s - Response (%d bytes): %s - %s\n", ip.String(), n, hex.EncodeToString(resp[:n]), ans)
// 		//fmt.Printf("%s\n", r.String())
// 	}

// 	return Result{
// 		ip:   ip,
// 		err:  nil,
// 		resp: resp[:n]}, nil
// }

// func dnsWorker(baseDomain string, prefixIP bool, timeout time.Duration, queryType uint16, sourceIP string, verbose, v6Addresses bool, ips <-chan net.IP, wg *sync.WaitGroup) {
// 	defer wg.Done()

// 	for ip := range ips {

// 		domain := baseDomain
// 		if prefixIP {
// 			if v6Addresses {
// 				domain = strings.ReplaceAll(ip.String(), ":", "-") + "." + baseDomain
// 			} else {
// 				domain = strings.Replace(ip.String(), ".", "-", 3) + "." + baseDomain
// 			}
// 		}
// 		sendDnsProbe(ip, domain, timeout, verbose, queryType, sourceIP)
// 	}
// }

// func main() {

// 	baseDomain := flag.String("domain", "v6.tlsfingerprint.io", "Domain to use")
// 	recordType := flag.String("record", "A", "Type of record to request")
// 	sourceIP := flag.String("source-ip", "192.12.240.40", "Address to send requests from")
// 	prefixIP := flag.Bool("prefix", true, "If we should encode the resolver IP in our query")
// 	nWorkers := flag.Uint("workers", 50, "Number worker threads")
// 	timeout := flag.Duration("timeout", 5*time.Second, "Duration to wait for DNS response")
// 	verbose := flag.Bool("verbose", true, "Verbose prints sent/received DNS packets/info")
// 	v6Addresses := flag.Bool("v6-addresses", false, "Whether to expect v6 addresses as input")

// 	flag.Parse()

// 	jobs := make(chan net.IP, *nWorkers*10)
// 	var wg sync.WaitGroup
// 	var dnsType uint16
// 	if *recordType == "A" {
// 		dnsType = dns.TypeA
// 	} else if *recordType == "AAAA" {
// 		dnsType = dns.TypeAAAA
// 	}

// 	for w := uint(0); w < *nWorkers; w++ {
// 		wg.Add(1)
// 		go dnsWorker(*baseDomain, *prefixIP, *timeout, dnsType, *sourceIP, *verbose, *v6Addresses, jobs, &wg)
// 	}

// 	nJobs := 0
// 	scanner := bufio.NewScanner(os.Stdin)
// 	for scanner.Scan() {
// 		line := scanner.Text()
// 		jobs <- net.ParseIP(line)
// 		nJobs += 1
// 	}
// 	close(jobs)

// 	if err := scanner.Err(); err != nil {
// 		log.Println(err)
// 	}

// 	wg.Wait()
// }

var (
	infoLogger  *log.Logger
	errorLogger *log.Logger
)

type NoRDBitFlags struct {
	Resolvers string `arg:"--resolvers,required" help:"(Required) Path to file containing list of Resolvers to query"`
	Domains   string `arg:"--domains,required" help:"(Required) Path to the file containing domains to issue A and AAAA record requests to"`
	SourceIP  string `arg:"--source-ip" help:"Address to send queries from" default:"192.12.240.40"`
	Threads   int    `arg:"--threads" help:"Number of goroutines to use for queries" default:"1000"`
	Timeout   int    `arg:"--timeout" help:"Number of seconds to wait for DNS and TLS connections" default:"5"`
}

type DNSResult struct {
	Resolver string
	Domain   string
	RCode    int
	Answers  []net.IP
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
	resolverAddr string,
	dialer net.Dialer,
	domain string,
	timeout time.Duration,
) DNSResult {
	dnsResult := DNSResult{
		Resolver: resolverAddr,
		Domain:   domain,
		RCode:    -1,
	}
	m := &dns.Msg{
		// no recursion desired
		MsgHdr: dns.MsgHdr{
			Authoritative:     false,
			AuthenticatedData: false,
			CheckingDisabled:  false,
			RecursionDesired:  true,
			Opcode:            dns.OpcodeQuery,
		},
		Question: make([]dns.Question, 1),
	}
	// A record request
	m.Question[0] = dns.Question{
		Name:   dns.Fqdn(domain),
		Qtype:  dns.TypeA,
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
			errorLogger.Printf(
				"Error creating UDP socket(?): %s\n",
				resolverAddr,
			)
			errorLogger.Println(err)
			return
		}

		defer conn.Close()

		conn.Write(dnsQuery)
		conn.SetReadDeadline(time.Now().Add(timeout))
		resp := make([]byte, 1024)
		_, err = conn.Read(resp)
		if err != nil {
			errorLogger.Printf(
				"Error reading from %s for %s\n", resolverAddr, domain,
			)
			errorLogger.Println(err)
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
		if len(r.Answer) > 0 {
			for _, answer := range r.Answer {
				lastTab := strings.LastIndex(answer.String(), "\t")
				strIP := answer.String()[lastTab+1:]
				ip := net.ParseIP(strIP)
				if ip != nil {
					dnsResult.Answers = append(dnsResult.Answers, ip)
				}
			}
		}
	}()

	return dnsResult
}

func resolverWorker(
	domains []string,
	sourceIP net.IP,
	timeout time.Duration,
	resolverChan <-chan net.IP,
	wg *sync.WaitGroup,
) {
	defer wg.Done()

	for resolverIP := range resolverChan {
		infoLogger.Printf(
			"Running no rd scan for resolver: %s\n",
			resolverIP.String(),
		)
		resolverAddr := resolverIP.String() + ":53"
		if resolverIP.To4() == nil {
			resolverAddr = "[" + resolverIP.String() + "]:53"
		}
		udpAddr := &net.UDPAddr{
			IP: sourceIP,
		}
		dialer := net.Dialer{
			LocalAddr: udpAddr,
		}

		for _, domain := range domains {
			resolveDomain(resolverAddr, dialer, domain, timeout)
		}
	}
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
	resolvers := readResolvers(args.Resolvers, sourceIP)
	if len(resolvers) <= 0 {
		errorLogger.Fatalln("Got no valid resolvers")
	}
	infoLogger.Printf("Got %d resolvers\n", len(resolvers))

	domains := readDomains(args.Domains)
	infoLogger.Printf("Got %d domains\n", len(domains))

	var workersWG sync.WaitGroup
	resolverChan := make(chan net.IP)

	infoLogger.Printf("Spawning resolver workers")
	for w := uint(0); w < uint(args.Threads); w++ {
		workersWG.Add(1)
		go resolverWorker(
			domains, sourceIP, connTimeout, resolverChan, &workersWG,
		)
	}

	for _, resolver := range resolvers {
		resolverChan <- resolver
	}

	close(resolverChan)
	workersWG.Wait()
}
