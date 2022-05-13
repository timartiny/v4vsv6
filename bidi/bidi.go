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

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/miekg/dns"
)

// If we want to add a response, do it here
type Result struct {
	ip   net.IP
	err  error
	resp []byte
}

func getUdpPayload(packet gopacket.Packet) (out []byte) {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		return udp.Payload
	}
	return
}

func handlePacket(packet gopacket.Packet) {

	/*
		decoded := []gopacket.LayerType{}
		if err := parser.DecodeLayers(packet.Data(), &deocded); err != nil {

			fmt.Fprintf(os.Stderr, "Could not decode layers: %v\n", err)
			return
		}*/
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}
	udp, _ := udpLayer.(*layers.UDP)

	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return
	}
	dns, _ := dnsLayer.(*layers.DNS)
	questions := dns.Questions
	answers := dns.Answers
	if len(questions) < 1 {
		return
	}

	var ipAddr net.IP
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		ip6Layer := packet.Layer(layers.LayerTypeIPv6)
		if ip6Layer == nil {
			return
		}
		ip6, _ := ip6Layer.(*layers.IPv6)
		ipAddr = ip6.SrcIP
	} else {
		ip4, _ := ipLayer.(*layers.IPv4)
		ipAddr = ip4.SrcIP
	}
	log.Printf("RESULT %s %s, %s %d answers: %s\n",
		ipAddr, questions[0].Name, dns.ResponseCode, len(answers), hex.EncodeToString(udp.Payload))
}

func handlePcap(iface string) {

	if handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter("udp src port 53"); err != nil { // optional
		panic(err)
	} else {
		/*
			var eth layers.Ethernet
			var ip4 layers.IPv4
			var ip6 layers.IPv6
			var udp layers.UDP
			var dns layers.DNS
			parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &udp, &dns)

		*/
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			handlePacket(packet)
		}
	}

}

func sendDnsProbe(ip net.IP, name string, qType uint16, lAddr string, timeout time.Duration, verbose bool, shouldRead bool) (Result, error) {
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
		Qtype:  qType,
		Qclass: uint16(0x0001), // IN
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

	//conn, err := net.Dial("udp", addr)
	var d net.Dialer
	if lAddr != "" {
		d.LocalAddr, _ = net.ResolveUDPAddr("ip", lAddr)
	}
	conn, err := d.Dial("udp", addr)
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

func dnsWorker(wait time.Duration, verbose bool, shouldRead bool, qType uint16, lAddr string, ips <-chan string, domains []string, wg *sync.WaitGroup) {
	defer wg.Done()

	for ip := range ips {
		addr := net.ParseIP(ip)
		if verbose {
			log.Printf("Sending to %v...\n", addr)
		}

		for _, domain := range domains {
			_, err := sendDnsProbe(addr, domain, qType, lAddr, wait, verbose, shouldRead)
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
	iface := flag.String("iface", "eth0", "Interface to listen on")
	qTypeUint := flag.Uint("qtype", 1, "Type of Query to send (1 = A / 28 = AAAA)")
	lAddr := flag.String("laddr", "", "Local address to send packets from - unset uses default interface.")

	flag.Parse()

	var qType = uint16(*qTypeUint)

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
		go dnsWorker(*wait, *verbose, false, qType, *lAddr, ips, domains, &wg)
	}

	go handlePcap(*iface)

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
