package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	mrand "math/rand"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const httpProbeTypeName = "http"
const httpUserAgent = "curl/7.81.0"
const httpSharedHeaderFmtStr = ``
const httpFmtStr = `GET / HTTP/1.1
Host:  %s
User-Agent: %s
Accept: */*

`

type httpProber struct {
	device string
}

func (p *httpProber) registerFlags() {
}

func (p *httpProber) shouldRead() bool {
	return false
}

func (p *httpProber) sendProbe(ip net.IP, name string, lAddr string, timeout time.Duration, verbose bool) (*Result, error) {
	// Open device
	handle, err := pcap.OpenLive(p.device, 1500, false, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	iface, err := net.InterfaceByName(p.device)
	if err != nil {
		return nil, fmt.Errorf("bad device name: \"%s\"", p.device)
	}

	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD},
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

	var localIP = net.ParseIP(lAddr)
	if localIP == nil {
		addrs, err := iface.Addrs()
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

	// Fill out IP header with source and dest
	// TODO JMWAMPLE: v6 layer handle
	ipLayer := layers.IPv4{
		SrcIP:    localIP,
		DstIP:    ip,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}

	// Fill TCP layer details
	tcpLayer := layers.TCP{
		SrcPort: layers.TCPPort(getRandInt(1000, 65535)),
		DstPort: layers.TCPPort(80),
		SYN:     true,
		ACK:     true,
		// Seq: 0,
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

	fmt.Println(base)
	fmt.Println(ipLayer)
	fmt.Println(tcpLayer)
	fmt.Println(hex.EncodeToString(outgoingPacket))

	// Send our packet
	err = handle.WritePacketData(outgoingPacket)
	if err != nil {
		return nil, err
	}

	// ipl := layers.IPv4{
	// 	Version:  4,
	// 	TTL:      64,
	// 	SrcIP:    net.IP{1, 3, 3, 7},
	// 	DstIP:    net.IP{127, 0, 0, 1},
	// 	Protocol: layers.IPProtocolUDP,
	// }

	// udp := layers.UDP{
	// 	SrcPort: 9000,
	// 	DstPort: 9000,
	// }
	// udp.SetNetworkLayerForChecksum(&ipl)

	// // Create a properly formed packet, just with
	// // empty details. Should fill out MAC addresses,
	// // IP addresses, etc.
	// buffer := gopacket.NewSerializeBuffer()
	// options := gopacket.SerializeOptions{
	// 	// ComputeChecksums: true,
	// 	// FixLengths:       true,
	// }
	// gopacket.SerializeLayers(buffer, options,
	// 	base,
	// 	&ipl,
	// 	&udp,
	// 	gopacket.Payload(rawBytes),
	// )
	// outgoingPacket := buffer.Bytes()
	// // Send our packet
	// err = handle.WritePacketData(outgoingPacket)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// if verbose {
	// 	log.Printf("Sent %s - %s\n%v\n%v\n", ip.String(), hex.EncodeToString(outgoingPacket), tcpLayer, &ipLayer)
	// 	// log.Printf("Sent %s - %s\n", ip.String(), hex.EncodeToString(outgoingPacket))
	// }

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

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Get padding of length [minLen, maxLen).
// Distributed in pseudogaussian style.
// Padded using symbol '#'. Known plaintext attacks, anyone?
func getRandPadding(minLen int, maxLen int, smoothness int) string {
	paddingLen := 0
	for j := 0; j < smoothness; j++ {
		paddingLen += getRandInt(minLen, maxLen)
	}
	paddingLen = paddingLen / smoothness

	return strings.Repeat("#", paddingLen)
}

// Tries to get crypto random int in range [min, max]
// In case of crypto failure -- return insecure pseudorandom
func getRandInt(min int, max int) int {
	// I can't believe Golang is making me do that
	// Flashback to awful C/C++ libraries
	diff := max - min
	if diff < 0 {
		min = max
		diff *= -1
	} else if diff == 0 {
		return min
	}
	var v int64
	err := binary.Read(rand.Reader, binary.LittleEndian, &v)
	if v < 0 {
		v *= -1
	}
	if err != nil {
		v = mrand.Int63()
	}
	return min + int(v%int64(diff+1))
}

// returns random duration between min and max in milliseconds
func getRandomDuration(min int, max int) time.Duration {
	return time.Millisecond * time.Duration(getRandInt(min, max))
}
