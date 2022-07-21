package main

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

// const httpUserAgent = "curl/7.81.0"
const httpUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
const httpProbeTypeName = "http"
const httpFmtStr = "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\n\r\n"

type httpProber struct {
	device string
	seed   int64
	r      *rand.Rand

	// sendSynAndAck sends a syn and an ack packet as a pseudo prelude to a TCP
	// session in order to trigger censorship responses from middlebloxes expecting
	// and tracking some subset of the TCP flow state.
	sendSynAndAck bool
	synDelay      time.Duration
}

func (p *httpProber) registerFlags() {
}

func (p *httpProber) shouldRead() bool {
	return false
}

func (p *httpProber) buildPayload(name string) ([]byte, error) {
	// Fill out request bytes
	return []byte(fmt.Sprintf(httpFmtStr, name, httpUserAgent)), nil

}

func (p *httpProber) sendProbe(ip net.IP, name string, lAddr string, verbose bool) (*Result, error) {
	out, err := p.buildPayload(name)
	if err != nil {
		return nil, fmt.Errorf("failed to build tls payload: %s", err)
	}

	addr := net.JoinHostPort(ip.String(), "80")
	return sendTCP(addr, out, lAddr, p.device, p.r, p.sendSynAndAck, verbose)
}

/*
func (p *httpProber) sendProbe(ip net.IP, name string, lAddr string, verbose bool) (*Result, error) {

	var useV4 = ip.To4() != nil
	options := gopacket.SerializeOptions{
		FixLengths: true,
		// ComputeChecksums: true,
	}

	// Open device
	handle, err := pcap.OpenLive(p.device, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("failed to open \"%s\" - %s", p.device, err)
	}
	defer handle.Close()

	localIface, err := net.InterfaceByName(p.device)
	if err != nil {
		return nil, fmt.Errorf("bad device name: \"%s\"", p.device)
	}

	remoteIface, localIP, err := getDstMacAndSrcIP(localIface, lAddr, ip)
	if err != nil {
		return nil, err
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
			Protocol: layers.IPProtocolTCP,
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
			NextHeader: layers.IPProtocolTCP,
		}
	}

	// Pick a random source port between 1000 and 65535
	randPort := (p.r.Int31() % 64535) + 1000
	seq := p.r.Uint32()
	ack := p.r.Uint32()
	if p.sendSynAndAck {

		log.Println("sending synack")

		// Fill TCP layer details
		tcpSyn := layers.TCP{
			SrcPort: layers.TCPPort(randPort),
			DstPort: layers.TCPPort(80),
			SYN:     true,
			Window:  502,
			Seq:     seq,
			Ack:     0,
		}

		buffer := gopacket.NewSerializeBuffer()
		gopacket.SerializeLayers(buffer, options,
			&eth,
			ipLayer,
			&tcpSyn,
		)
		outgoingPacket := buffer.Bytes()

		// Send our packet
		err = handle.WritePacketData(outgoingPacket)
		if err != nil {
			return nil, err
		}
		time.Sleep(p.synDelay)

		tcpAck := layers.TCP{
			SrcPort: layers.TCPPort(randPort),
			DstPort: layers.TCPPort(80),
			ACK:     true,
			Window:  502,
			Seq:     seq + 1,
			Ack:     ack,
		}
		buffer = gopacket.NewSerializeBuffer()
		gopacket.SerializeLayers(buffer, options,
			&eth,
			ipLayer,
			&tcpAck,
		)
		outgoingPacket = buffer.Bytes()

		// Send our packet
		err = handle.WritePacketData(outgoingPacket)
		if err != nil {
			return nil, err
		}

	}

	// Fill TCP layer details
	tcpLayer := layers.TCP{
		SrcPort: layers.TCPPort(randPort),
		DstPort: layers.TCPPort(80),
		ACK:     true,
		Window:  502,
		Seq:     seq + 1,
		Ack:     ack,
	}

	// Fill out request bytes
	rawBytes := []byte(fmt.Sprintf(httpFmtStr, name, httpUserAgent))

	// And create the packet with the layers
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
*/

func (p *httpProber) handlePcap(iface string) {
	f, _ := os.Create("http.pcap")
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(1600, layers.LinkTypeEthernet)
	defer f.Close()

	if handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter("tcp src port 80"); err != nil { // optional
		panic(err)
	} else {
		defer handle.Close()

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			// p.handlePacket(packet)
			w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
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
