package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
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

func sendDnsProbe(ip net.IP, timeout time.Duration, verbose bool) (Result, error) {
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
		Name:   dns.Fqdn("version.bind"),
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
}

func dnsWorker(timeout time.Duration, verbose bool, iplines <-chan string, wg *sync.WaitGroup) {
	defer wg.Done()

	for line := range iplines {
		ips := strings.Fields(line)
		v4 := net.ParseIP(ips[1])
		v6 := net.ParseIP(ips[0])
		//cc := ips[2]

		v4res, err4 := sendDnsProbe(v4, timeout, verbose)
		v6res, err6 := sendDnsProbe(v6, timeout, verbose)

		if err4 != nil || err6 != nil || len(v4res.resp) <= 2 || len(v6res.resp) <= 2 {
			log.Printf("RESULT %s - error\n", line)
			log.Printf("%v: %+v\n", v4, err4)
			log.Printf("%v: %+v\n", v6, err6)
		} else {

			v4data := v4res.resp[2:]
			v6data := v6res.resp[2:]

			if bytes.Equal(v4data, v6data) {
				fmt.Printf("RESULT %s - same %s\n", line, hex.EncodeToString(v4data))
			} else {
				fmt.Printf("RESULT %s - diff:\n", line)
				fmt.Printf("%v: %s\n", v4, hex.EncodeToString(v4data))
				fmt.Printf("%v: %s\n", v6, hex.EncodeToString(v6data))
			}
		}

	}
}

func main() {

	nWorkers := flag.Uint("workers", 50, "Number worker threads")
	timeout := flag.Duration("timeout", 5*time.Second, "Duration to wait for DNS response")
	verbose := flag.Bool("verbose", true, "Verbose prints sent/received DNS packets/info")

	flag.Parse()

	jobs := make(chan string, *nWorkers*10)
	var wg sync.WaitGroup

	for w := uint(0); w < *nWorkers; w++ {
		wg.Add(1)
		go dnsWorker(*timeout, *verbose, jobs, &wg)
	}

	nJobs := 0
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		jobs <- line
		nJobs += 1
	}
	close(jobs)

	if err := scanner.Err(); err != nil {
		log.Println(err)
	}

	wg.Wait()
}
