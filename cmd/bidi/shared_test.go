package main

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// This test does weird things when the host machine has virtualbox interfaces
// (e.g. vboxnet0) on the host. It throws some error about the device being out
// of order. otherwise test should pass.
func TestRoutingBasic(t *testing.T) {
	localIface, err := net.InterfaceByName("lo")
	require.Nil(t, err)

	hw, ip, err := getDstMacAndSrcIP(localIface, "127.0.0.1", net.ParseIP("127.0.0.1"))
	require.Nil(t, err)
	require.Equal(t, "127.0.0.1", ip.String())
	require.Equal(t, "lo", hw.Name)

	hw, ip, err = getDstMacAndSrcIP(localIface, "::1", net.ParseIP("::1"))
	require.Nil(t, err)
	require.Equal(t, "::1", ip.String())
	require.Equal(t, "lo", hw.Name)
}

func TestRoutingMixedPreferred(t *testing.T) {
	localIface, err := net.InterfaceByName("lo")
	require.Nil(t, err)

	hw, ip, err := getDstMacAndSrcIP(localIface, "127.0.0.1", net.ParseIP("::1"))
	require.Nil(t, err)
	require.Equal(t, "::1", ip.String())
	require.Equal(t, "lo", hw.Name)

	hw, ip, err = getDstMacAndSrcIP(localIface, "::1", net.ParseIP("127.0.0.1"))
	require.Nil(t, err)
	require.Equal(t, "127.0.0.1", ip.String())
	require.Equal(t, "lo", hw.Name)
}
