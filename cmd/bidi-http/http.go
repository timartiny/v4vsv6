package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/routing"
)

const httpProbeTypeName = "http"
const httpUserAgent = "curl/7.81.0"
const httpFmtStr = "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\n\r\n"

type httpProber struct {
	device string
	seed   int64
}

func (p *httpProber) registerFlags() {
	flag.Int64Var(&p.seed, "seed", int64(time.Now().Nanosecond()), "[HTTP] seed for random elements of generated packets")
}

func (p *httpProber) shouldRead() bool {
	return false
}

func (p *httpProber) sendProbe(ip net.IP, name string, lAddr string, timeout time.Duration, verbose bool) (*Result, error) {

	r := rand.New(rand.NewSource(p.seed))

	// Open device
	handle, err := pcap.OpenLive(p.device, 1500, false, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	localIface, err := net.InterfaceByName(p.device)
	if err != nil {
		return nil, fmt.Errorf("bad device name: \"%s\"", p.device)
	}

	var localIP = net.ParseIP(lAddr)
	if localIP == nil {
		addrs, err := localIface.Addrs()
		if len(addrs) == 0 || err != nil {
			return nil, fmt.Errorf("unable to get local addr")
		}
		localIP, _, err = net.ParseCIDR(addrs[0].String())
		if err != nil {
			return nil, fmt.Errorf("unable to get local cidr")
		}
	}

	if localIP == nil {
		return nil, fmt.Errorf("unable to parse local IP addr: \"%s\"", lAddr)
	}

	router, err := routing.New()
	if err != nil {
		return nil, err
	}

	// ignore gateway, but adopt preferred source if no lAddr was specified.
	remoteIface, _, preferredSrc, err := router.RouteWithSrc(localIface.HardwareAddr, localIP, ip)
	if lAddr == "" {
		localIP = preferredSrc
	}

	eth := layers.Ethernet{
		SrcMAC: localIface.HardwareAddr,
		DstMAC: remoteIface.HardwareAddr,
		// DstMAC:       net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD},
		EthernetType: layers.EthernetTypeIPv4,
	}

	// Used for loopback interface
	lo := layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		EthernetType: layers.EthernetTypeIPv4,
	}

	var base gopacket.SerializableLayer = &eth
	if p.device == "lo" {
		base = &lo
	}

	// Fill out IP header with source and dest
	// TODO JMWAMPLE: v6 layer handle
	ipLayer := layers.IPv4{
		SrcIP:    localIP,
		DstIP:    ip,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}

	// Pick a random source port between 1000 and 65535
	randPort := (r.Int31() % 64535) + 1000

	// Fill TCP layer details
	tcpLayer := layers.TCP{
		SrcPort: layers.TCPPort(randPort),
		DstPort: layers.TCPPort(80),
		PSH:     true,
		ACK:     true,
		Window:  502,
		Seq:     r.Uint32(),
		Ack:     r.Uint32(),
	}

	rawBytes := []byte(fmt.Sprintf(httpFmtStr, name, httpUserAgent))
	// rawBytes := []byte{0xAA, 0xBB, 0xCC}

	// And create the packet with the layers
	options := gopacket.SerializeOptions{
		FixLengths: true,
		// ComputeChecksums: true,
	}
	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options,
		base,
		&ipLayer,
		&tcpLayer,
		gopacket.Payload(rawBytes),
	)
	outgoingPacket := buffer.Bytes()

	// Send our packet
	err = handle.WritePacketData(outgoingPacket)
	if err != nil {
		return nil, err
	}

	if verbose {
		log.Printf("Sent %s - %s\n", ip.String(), hex.EncodeToString(outgoingPacket))
		// log.Printf("Sent %s - %s\n", ip.String(), hex.EncodeToString(outgoingPacket))
	}

	return &Result{ip: ip}, nil
}

func (p *httpProber) handlePcap(iface string) {

	if handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter("tcp src port 80"); err != nil { // optional
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			p.handlePacket(packet)
		}
	}

}

func (p *httpProber) handlePacket(packet gopacket.Packet) {

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

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}
	tcp, _ := tcpLayer.(*layers.TCP)

	// log.Printf("RESULT %s %s, %s %d answers: %s\n",
	// 	ipAddr, questions[0].Name, dns.ResponseCode, len(answers), hex.EncodeToString(tcp.Payload))

	if tcp.NextLayerType() != 0 {
		log.Printf("RESULT HTTP %s %v", ipAddr, tcp.RST)
	} else {
		log.Printf("RESULT HTTP")
	}
}
