package main

import (
	"fmt"
	"net"

	"github.com/google/gopacket/routing"
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
