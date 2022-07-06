package main

import (
	"bufio"
	"flag"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

// Result provides a result type for printing. If we want to add a response, do
// it here
type Result struct {
	ip   net.IP
	err  error
	resp []byte
}

type prober interface {
	registerFlags()

	sendProbe(ip net.IP, name string, lAddr string, timeout time.Duration, verbose bool) (*Result, error)

	handlePcap(iface string)

	shouldRead() bool
}

func worker(p prober, wait time.Duration, verbose bool, lAddr string, ips <-chan string, domains []string, wg *sync.WaitGroup) {
	defer wg.Done()

	for ip := range ips {
		addr := net.ParseIP(ip)
		if verbose {
			log.Printf("Sending to %v...\n", addr)
		}

		for _, domain := range domains {
			_, err := p.sendProbe(addr, domain, lAddr, wait, verbose)
			if err != nil {
				log.Printf("Result %s,%s - error: %v\n", ip, domain, err)
				continue
			} else if p.shouldRead() {
				// We expect the sendProbe to report a result if shouldRead is true
				log.Printf("RESULT %s,%s\n", ip, domain)
			} else {
				// No results in this thread; pcap gets results, we just send
			}

			// Wait here
			time.Sleep(wait)
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

	var probers = map[string]prober{
		dnsProbeTypeName:  &dnsProber{innerShouldRead: false},
		httpProbeTypeName: &httpProber{},
	}

	nWorkers := flag.Uint("workers", 50, "Number worker threads")
	wait := flag.Duration("wait", 5*time.Second, "Duration to wait for DNS response")
	verbose := flag.Bool("verbose", true, "Verbose prints sent/received DNS packets/info")
	domainf := flag.String("domains", "domains.txt", "File with a list of domains to test")
	iface := flag.String("iface", "eth0", "Interface to listen on")
	lAddr := flag.String("laddr", "", "Local address to send packets from - unset uses default interface.")
	proberType := flag.String("type", "dns", "probe type to send")

	for _, p := range probers {
		p.registerFlags()
	}

	flag.Parse()

	var p prober
	var ok bool
	if p, ok = probers[*proberType]; !ok {
		panic("unknown probe type")
	}

	if hp, ok := p.(*httpProber); ok {
		hp.device = *iface
	}

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
		// go dnsWorker(*wait, *verbose, false, *lAddr, ips, domains, &wg)
		go worker(p, *wait, *verbose, *lAddr, ips, domains, &wg)
	}

	go p.handlePcap(*iface)

	nJobs := 0
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		ips <- line
		nJobs++
	}
	close(ips)

	if err := scanner.Err(); err != nil {
		log.Println(err)
	}

	wg.Wait()
}
