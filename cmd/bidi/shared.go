package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/routing"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func getDstMacAndSrcIP(localIface *net.Interface, lAddr string, dstIP net.IP) (*net.Interface, net.IP, error) {
	var useV4 = dstIP.To4() != nil

	var localIP = net.ParseIP(lAddr)
	if useV4 && localIP.To4() == nil {
		localIP = nil
	} else if !useV4 && localIP.To4() != nil {
		localIP = nil
	}

	router, err := routing.New()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to init routing: %s", err)
	}

	// ignore gateway, but adopt preferred source if unsuitable lAddr was specified.
	remoteIface, _, preferredSrc, err := router.RouteWithSrc(localIface.HardwareAddr, localIP, dstIP)
	if err != nil || remoteIface == nil {
		return nil, nil, fmt.Errorf("failed to get remote iface: %s", err)
	}

	// If the specified local IP is unset or the wrong IP version for the target
	// substitute the preferred source.
	if localIP == nil {
		localIP = preferredSrc
	}

	return remoteIface, localIP, nil
}

func sendUDP(dst string, payload []byte, lAddr string, verbose bool) (*Result, error) {
	var d net.Dialer
	if lAddr != "" {
		d.LocalAddr, _ = net.ResolveUDPAddr("ip", lAddr)
	}

	conn, err := d.Dial("udp", dst)
	if err != nil {
		return nil, fmt.Errorf("%s - error creating UDP socket(?): %v", dst, err)
	}
	defer conn.Close()

	conn.Write(payload)
	if verbose {
		log.Printf("Sent %s - %s\n", dst, hex.EncodeToString(payload))
	}

	// cannot possibly err if we have already used the addr to dial
	host, _, _ := net.SplitHostPort(dst)
	ip := net.ParseIP(host)
	return &Result{ip: ip}, nil
}

func sendTCP(dst string, payload []byte, lAddr, device string, r *rand.Rand, sendSynAck, verbose bool) (*Result, error) {

	host, portStr, err := net.SplitHostPort(dst)
	if err != nil {
		return nil, fmt.Errorf("failed to parse \"ip:port\": %s - %s", dst, err)
	}
	port, _ := strconv.Atoi(portStr)

	ip := net.ParseIP(host)

	var useV4 = ip.To4() != nil
	options := gopacket.SerializeOptions{
		FixLengths: true,
		// ComputeChecksums: true,
	}

	localIface, err := net.InterfaceByName(device)
	if err != nil {
		return nil, fmt.Errorf("bad device name: \"%s\"", device)
	}

	_, localIP, err := getDstMacAndSrcIP(localIface, lAddr, ip)
	if err != nil {
		return nil, err
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
	randPort := (r.Int31() % 64535) + 1000
	seq := r.Uint32()
	ack := r.Uint32()

	// build syn and ack payloads incase we are sending syn and ack
	synBuf, err := getSyn(uint32(randPort), uint32(port), seq, options)
	if err != nil {
		return nil, err
	}
	ackBuf, err := getAck(uint32(randPort), uint32(port), seq+1, ack, options)
	if err != nil {
		return nil, err
	}

	// Fill TCP  Payload layer details
	tcpLayer := layers.TCP{
		SrcPort: layers.TCPPort(randPort),
		DstPort: layers.TCPPort(port),
		PSH:     true,
		ACK:     true,
		Window:  502,
		Seq:     seq + 1,
		Ack:     ack,
	}

	ipHeaderBuf := gopacket.NewSerializeBuffer()
	err = ipLayer.SerializeTo(ipHeaderBuf, options)
	if err != nil {
		return nil, err
	}

	tcpPayloadBuf := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(tcpPayloadBuf, options, &tcpLayer, gopacket.Payload(payload))
	if err != nil {
		return nil, err
	}

	// XXX end of packet creation

	// XXX send packet
	if useV4 {
		packetConn, err := net.ListenPacket("ip4:tcp", "")
		if err != nil {
			return nil, err
		}
		ipHeader, err := ipv4.ParseHeader(ipHeaderBuf.Bytes())
		if err != nil {
			return nil, err
		}
		rawConn, err := ipv4.NewRawConn(packetConn)
		if err != nil {
			return nil, err
		}

		if sendSynAck {
			err = rawConn.WriteTo(ipHeader, synBuf, nil)
			if err != nil {
				return nil, err
			}

			err = rawConn.WriteTo(ipHeader, ackBuf, nil)
			if err != nil {
				return nil, err
			}
		}

		err = rawConn.WriteTo(ipHeader, tcpPayloadBuf.Bytes(), nil)
		if err != nil {
			return nil, err
		}
	} else {
		packetConn, err := net.ListenPacket("ip6:tcp", "")
		if err != nil {
			return nil, err
		}
		var ipHeader *ipv6.ControlMessage
		err = ipHeader.Parse(ipHeaderBuf.Bytes())
		if err != nil {
			return nil, err
		}
		pktConn := ipv6.NewPacketConn(packetConn)
		if pktConn == nil {
			return nil, fmt.Errorf("unable to create IPv6 packet conn")
		}

		if sendSynAck {
			_, err = pktConn.WriteTo(synBuf, ipHeader, nil)
			if err != nil {
				return nil, err
			}

			_, err = pktConn.WriteTo(ackBuf, ipHeader, nil)
			if err != nil {
				return nil, err
			}
		}

		_, err = pktConn.WriteTo(tcpPayloadBuf.Bytes(), ipHeader, nil)
		if err != nil {
			return nil, err
		}
	}

	if verbose {
		log.Printf("Sent %s - %s\n", ip.String(), hex.EncodeToString(payload))
	}

	return &Result{ip: ip}, nil
}

func getSyn(srcPort, dstPort, seq uint32, options gopacket.SerializeOptions) ([]byte, error) {
	synLayer := layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
		Window:  502,
		Seq:     seq,
		Ack:     0,
	}

	tcpPayloadBuf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(tcpPayloadBuf, options, &synLayer)
	if err != nil {
		return nil, err
	}
	return tcpPayloadBuf.Bytes(), nil
}
func getAck(srcPort, dstPort, seq, ack uint32, options gopacket.SerializeOptions) ([]byte, error) {

	ackLayer := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		ACK:     true,
		Window:  502,
		Seq:     seq,
		Ack:     ack,
	}

	tcpPayloadBuf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(tcpPayloadBuf, options, ackLayer)
	if err != nil {
		return nil, err
	}
	return tcpPayloadBuf.Bytes(), nil
}
