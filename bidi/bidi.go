package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// If we want to add a response, do it here
type Result struct {
	ip   net.IP
	err  error
	resp []byte
}

func sendDnsProbe(ip net.IP, name string, timeout time.Duration, verbose bool, shouldRead bool) (Result, error) {
	m := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Authoritative:     false,
			AuthenticatedData: false,
			CheckingDisabled:  false,
			RecursionDesired:  true,
			Opcode:            dns.OpcodeQuery,
		},
		Question: make([]dns.Question, 1),
	}
	m.Question[0] = dns.Question{
		Name:   dns.Fqdn(name),
		Qtype:  dns.TypeTXT,
		Qclass: uint16(0x0003), // chaos (CH)
	}
	m.Id = dns.Id()

	out, err := m.Pack()
	if err != nil {
		if verbose {
			log.Printf("%s - Error creating UDP packet: %v\n", ip.String(), err)
		}
		return Result{}, err
	}
	addr := ip.String() + ":53"
	if ip.To16() != nil {
		addr = "[" + ip.String() + "]:53"
	}

	conn, err := net.Dial("udp", addr)
	if err != nil {
		if verbose {
			log.Printf("%s - Error creating UDP socket(?): %v\n", ip.String(), err)
		}
		return Result{}, err
	}

	defer conn.Close()

	conn.Write(out)
	if verbose {
		log.Printf("Sent %s - %s\n", ip.String(), hex.EncodeToString(out))
	}

	if timeout == 0 {
		return Result{ip: ip}, nil
	}

	if shouldRead {
		conn.SetReadDeadline(time.Now().Add(timeout))
		resp := make([]byte, 1024)
		n, err := conn.Read(resp)
		if err != nil {
			if verbose {
				log.Printf("%s - ReadErr: %v\n", ip.String(), err)
			}
			return Result{}, err
		}

		var r dns.Msg
		err = r.Unpack(resp)
		if err != nil {
			if verbose {
				log.Printf("%s - ParseErr: %v\n", ip.String(), err)
			}
			return Result{
				ip:   ip,
				err:  err,
				resp: resp[:n],
			}, err
		}
		if verbose {

			ans := "??"
			if res, ok := dns.RcodeToString[r.Rcode]; ok {
				ans = res
			}
			if len(r.Answer) > 0 {
				// Take first answer
				ans += ": " + r.Answer[0].String()
			}
			log.Printf("%s - Response (%d bytes): %s - %s\n", ip.String(), n, hex.EncodeToString(resp[:n]), ans)
			//fmt.Printf("%s\n", r.String())
		}

		return Result{
			ip:   ip,
			err:  nil,
			resp: resp[:n]}, nil
	} else {
		return Result{ip: ip}, nil
	}
}

func dnsWorker(wait time.Duration, verbose bool, shouldRead bool, ips <-chan string, domains []string, wg *sync.WaitGroup) {
	defer wg.Done()

	for ip := range ips {
		addr := net.ParseIP(ip)
		if verbose {
			log.Printf("Sending to %v...\n", addr)
		}

		for _, domain := range domains {
			_, err := sendDnsProbe(addr, domain, wait, verbose, shouldRead)
			if shouldRead {
				// We expect a result (TODO)
				if err != nil {
					log.Printf("Result %s,%s - error: %v\n", ip, domain, err)
				} else {
					log.Printf("RESULT %s,%s\n", ip, domain)
				}
			} else {
				// No results in this thread; pcap gets results, we just send
			}
			// Wait here???
			if !shouldRead {
				time.Sleep(wait)
			}
		}
	}
}

func getDomains(fname string) ([]string, error) {

	f, err := os.Open(fname)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func main() {

	nWorkers := flag.Uint("workers", 50, "Number worker threads")
	wait := flag.Duration("wait", 5*time.Second, "Duration to wait for DNS response")
	verbose := flag.Bool("verbose", true, "Verbose prints sent/received DNS packets/info")
	domainf := flag.String("domains", "domains.txt", "File with a list of domains to test")

	flag.Parse()

	// Parse domains
	domains, err := getDomains(*domainf)
	if err != nil {
		log.Println(err)
		return
	}
	log.Printf("Read %d domains\n", len(domains))

	ips := make(chan string, *nWorkers*10)
	var wg sync.WaitGroup

	for w := uint(0); w < *nWorkers; w++ {
		wg.Add(1)
		go dnsWorker(*wait, *verbose, false, ips, domains, &wg)
	}

	nJobs := 0
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		ips <- line
		nJobs += 1
	}
	close(ips)

	if err := scanner.Err(); err != nil {
		log.Println(err)
	}

	wg.Wait()
}
