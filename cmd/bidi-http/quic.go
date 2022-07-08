package main

import (
	"encoding/hex"
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

const quicProbeTypeName = "quic"

type quicProber struct {
	device string
	seed   int64
}

func (p *quicProber) buildPaylaod(name string) ([]byte, error) {
	var fulldata = "cd0000000108000102030405060705635f636964004103981c36a7ed78716be9711ba498b7ed868443bb2e0c514d4d848eadcc7a00d25ce9f9afa483978088de836be68c0b32a24595d7813ea5414a9199329a6d9f7f760dd8bb249bf3f53d9a77fbb7b395b8d66d7879a51fe59ef9601f79998eb3568e1fdc789f640acab3858a82ef2930fa5ce14b5b9ea0bdb29f4572da85aa3def39b7efafffa074b9267070d50b5d07842e49bba3bc787ff295d6ae3b514305f102afe5a047b3fb4c99eb92a274d244d60492c0e2e6e212cef0f9e3f62efd0955e71c768aa6bb3cd80bbb3755c8b7ebee32712f40f2245119487021b4b84e1565e3ca31967ac8604d4032170dec280aeefa095d08b3b7241ef6646a6c86e5c62ce08be099"

	return hex.DecodeString(fulldata)
}

func (p *quicProber) registerFlags() {
}

func (p *quicProber) shouldRead() bool {
	return false
}

func (p *quicProber) sendProbe(ip net.IP, name string, lAddr string, timeout time.Duration, verbose bool) (*Result, error) {

	var useV4 = ip.To4() != nil

	r := rand.New(rand.NewSource(p.seed))

	// Open device
	handle, err := pcap.OpenLive(p.device, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	localIface, err := net.InterfaceByName(p.device)
	if err != nil {
		return nil, fmt.Errorf("bad device name: \"%s\"", p.device)
	}

	var localIP = net.ParseIP(lAddr)

	router, err := routing.New()
	if err != nil {
		return nil, err
	}

	// ignore gateway, but adopt preferred source if unsuitable lAddr was specified.
	remoteIface, _, preferredSrc, err := router.RouteWithSrc(localIface.HardwareAddr, localIP, ip)
	if err != nil || remoteIface == nil {
		return nil, fmt.Errorf("failed to get remote iface: %s", err)
	}

	if localIP == nil {
		localIP = preferredSrc
	} else if useV4 && preferredSrc.To4() == nil {
		localIP = preferredSrc
	} else if !useV4 && preferredSrc.To4() != nil {
		localIP = preferredSrc
	}

	// Create the Ethernet Layer
	var ethType layers.EthernetType
	if useV4 {
		ethType = layers.EthernetTypeIPv4
	} else {
		ethType = layers.EthernetTypeIPv6
	}
	eth := layers.Ethernet{
		SrcMAC:       localIface.HardwareAddr,
		DstMAC:       remoteIface.HardwareAddr,
		EthernetType: ethType,
	}

	// Fill out IP header with source and dest
	var ipLayer gopacket.SerializableLayer
	if useV4 {
		if localIP.To4() == nil {
			return nil, fmt.Errorf("v6 src for v4 dst")
		}
		ipLayer = &layers.IPv4{
			SrcIP:    localIP,
			DstIP:    ip,
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolUDP,
		}
	} else {
		if localIP.To4() != nil {
			return nil, fmt.Errorf("v4 src for v6 dst")
		}
		ipLayer = &layers.IPv6{
			SrcIP:      localIP,
			DstIP:      ip,
			Version:    6,
			HopLimit:   64,
			NextHeader: layers.IPProtocolUDP,
		}
	}

	// Pick a random source port between 1000 and 65535
	randPort := (r.Int31() % 64535) + 1000

	// Fill UDP layer details
	tcpLayer := layers.UDP{
		SrcPort: layers.UDPPort(randPort),
		DstPort: layers.UDPPort(443),
	}

	// // Fill out request bytes
	rawBytes, err := p.buildPaylaod(name)
	if err != nil {
		return nil, fmt.Errorf("this shouldn't happen: %s", err)
	}
	// rawBytes := []byte{0xaa, 0xbb, 0xcc}

	// And create the packet with the layers
	options := gopacket.SerializeOptions{
		FixLengths: true,
		// ComputeChecksums: true,
	}
	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options,
		&eth,
		ipLayer,
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

func (p *quicProber) handlePcap(iface string) {

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

func (p *quicProber) handlePacket(packet gopacket.Packet) {

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
		log.Printf("RESULT QUIC %s %v", ipAddr, tcp.RST)
	} else {
		log.Printf("RESULT QUIC")
	}
}
