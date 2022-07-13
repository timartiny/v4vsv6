package main

import (
	"encoding/hex"
	"flag"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/miekg/dns"
)

const dnsProbeTypeName = "dns"

type dnsProber struct {
	qType           uint
	innerShouldRead bool
}

func (p *dnsProber) shouldRead() bool {
	return p.innerShouldRead
}

func (p *dnsProber) registerFlags() {
	flag.UintVar(&p.qType, "qtype", 1, "[DNS] Type of Query to send (1 = A / 28 = AAAA)")
	flag.BoolVar(&p.innerShouldRead, "dnsRead", false, "[DNS] Should DNS queries wait to read response")
}

func (p *dnsProber) handlePcap(iface string) {

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
			p.handlePacket(packet)
		}
	}

}

func (p *dnsProber) handlePacket(packet gopacket.Packet) {
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

func (p *dnsProber) sendProbe(ip net.IP, name string, lAddr string, timeout time.Duration, verbose bool) (*Result, error) {
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
		Qtype:  uint16(p.qType),
		Qclass: uint16(0x0001), // IN
	}
	m.Id = dns.Id()

	out, err := m.Pack()
	if err != nil {
		if verbose {
			log.Printf("%s - Error creating UDP packet: %v\n", ip.String(), err)
		}
		return nil, err
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
		return nil, err
	}

	defer conn.Close()

	conn.Write(out)
	if verbose {
		log.Printf("Sent %s - %s\n", ip.String(), hex.EncodeToString(out))
	}

	if timeout == 0 {
		return &Result{ip: ip}, nil
	}

	if p.shouldRead() {
		conn.SetReadDeadline(time.Now().Add(timeout))
		resp := make([]byte, 1024)
		n, err := conn.Read(resp)
		if err != nil {
			if verbose {
				log.Printf("%s - ReadErr: %v\n", ip.String(), err)
			}
			return nil, err
		}

		var r dns.Msg
		err = r.Unpack(resp)
		if err != nil {
			if verbose {
				log.Printf("%s - ParseErr: %v\n", ip.String(), err)
			}
			return &Result{
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

		return &Result{
			ip:   ip,
			err:  nil,
			resp: resp[:n]}, nil
	}

	return &Result{ip: ip}, nil
}
