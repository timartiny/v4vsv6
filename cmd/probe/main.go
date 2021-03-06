package main

import (
	"bufio"
	"encoding/hex"
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

type ProbeFlags struct {
	BaseDomain             string `arg:"--domain" help:"Domain to query for" default:"v6.tlsfingerprint.io"`
	RecordType             string `arg:"--record" help:"Type of DNS record to request" default:"A"`
	SourceIP               string `arg:"--source-ip" help:"Local Address to send requests from" default:"192.12.240.40"`
	Prefix                 bool   `arg:"--prefix" help:"If we should encode the resolver IP in our query" default:"false"`
	Workers                uint   `arg:"--workers" help:"Number of worker threads" default:"1000"`
	Timeout                int    `arg:"--timeout" help:"Duration to wait for DNS response" default:"5"`
	Verbose                bool   `arg:"--verbose" help:"Print sent/received DNS packets/info" default:"true"`
	V6Addresses            bool   `arg:"--v6-addresses" help:"Whether to prefix v6 addresses with dashes instead of colons" default:"false"`
	NumberOfIndexedQueries int    `arg:"--num-indexed-queries" help:"Number of queries to index and issue to each resolver, will index each query with a new lowercase letter" default:"0"`
}

// If we want to add a response, do it here
type Result struct {
	ip   net.IP
	err  error
	resp []byte
}

func sendDnsProbe(ip net.IP, domain string, timeout time.Duration, verbose bool, queryType uint16, sourceIP string) (Result, error) {
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
		Name:   dns.Fqdn(domain),
		Qtype:  queryType,
		Qclass: uint16(dns.ClassINET),
	}
	m.Id = dns.Id()

	out, err := m.Pack()
	if err != nil {
		if verbose {
			fmt.Printf("%s - Error creating UDP packet: %v\n", ip.String(), err)
		}
		return Result{}, err
	}
	addr := ip.String() + ":53"
	if ip.To16() != nil {
		addr = "[" + ip.String() + "]:53"
	}
	udpAddr := &net.UDPAddr{
		IP: net.ParseIP(sourceIP),
	}
	dialer := net.Dialer{
		LocalAddr: udpAddr,
	}

	conn, err := dialer.Dial("udp", addr)
	if err != nil {
		if verbose {
			fmt.Printf("%s - Error creating UDP socket(?): %v\n", ip.String(), err)
		}
		return Result{}, err
	}

	defer conn.Close()

	conn.Write(out)
	if verbose {
		fmt.Printf("Sent %s - %s - %s\n", ip.String(), domain, hex.EncodeToString(out))
	}

	if timeout == 0 {
		return Result{ip: ip}, nil
	}

	conn.SetReadDeadline(time.Now().Add(timeout))
	resp := make([]byte, 1024)
	n, err := conn.Read(resp)
	if err != nil {
		if verbose {
			fmt.Printf("%s - ReadErr: %v\n", ip.String(), err)
		}
		return Result{}, err
	}

	var r dns.Msg
	err = r.Unpack(resp)
	if err != nil {
		if verbose {
			fmt.Printf("%s - ParseErr: %v\n", ip.String(), err)
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
		fmt.Printf("%s - Response (%d bytes): %s - %s\n", ip.String(), n, hex.EncodeToString(resp[:n]), ans)
		//fmt.Printf("%s\n", r.String())
	}

	return Result{
		ip:   ip,
		err:  nil,
		resp: resp[:n]}, nil
}

func dnsWorker(
	baseDomain string,
	prefixIP bool,
	timeout time.Duration,
	queryType uint16,
	sourceIP string,
	verbose,
	v6Addresses bool,
	indexedQueries int,
	ips <-chan net.IP,
	wg *sync.WaitGroup,
) {
	defer wg.Done()

	numLoops := indexedQueries
	if numLoops == 0 {
		numLoops = 1
	}
	for ip := range ips {

		domain := baseDomain
		for i := 0; i < numLoops; i++ {
			if prefixIP {
				if v6Addresses {
					domain = strings.ReplaceAll(ip.String(), ":", "-")
				} else {
					domain = strings.Replace(ip.String(), ".", "-", 3)
				}

				if indexedQueries > 0 {
					// index query with alpha characters a-z
					domain += "_" + string(i+97) // convert our iteration to a-z
				}

				domain += "." + baseDomain
			}
			sendDnsProbe(ip, domain, timeout, verbose, queryType, sourceIP)
		}
	}
}

func setupArgs() ProbeFlags {
	var ret ProbeFlags
	arg.MustParse(&ret)

	return ret
}

func main() {
	args := setupArgs()
	timeout := time.Second * time.Duration(args.Timeout)
	if args.NumberOfIndexedQueries > 26 {
		log.Fatalln(
			"Currently only at most 26 indexed queries are supported, cause",
		)
	}

	jobs := make(chan net.IP, args.Workers*10)
	var wg sync.WaitGroup
	var dnsType uint16
	if args.RecordType == "A" {
		dnsType = dns.TypeA
	} else if args.RecordType == "AAAA" {
		dnsType = dns.TypeAAAA
	}

	for w := uint(0); w < args.Workers; w++ {
		wg.Add(1)
		go dnsWorker(
			args.BaseDomain,
			args.Prefix,
			timeout,
			dnsType,
			args.SourceIP,
			args.Verbose,
			args.V6Addresses,
			args.NumberOfIndexedQueries,
			jobs,
			&wg,
		)
	}

	nJobs := 0
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		jobs <- net.ParseIP(line)
		nJobs += 1
	}
	close(jobs)

	if err := scanner.Err(); err != nil {
		log.Println(err)
	}

	wg.Wait()
}
