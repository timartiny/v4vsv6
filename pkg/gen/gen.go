package gen

import (
	"errors"
	"io"
	"net"
)

var (
	// ErrNoSubnets is returned when an operation attempts to access a CCMap
	// with no subnets associated wth the provided CC.
	ErrNoSubnets = errors.New("no subnets available")
)

// RandomAddr uses the provided random reader to select a random address
// from a provided subnet.
func RandomAddr(rdr io.Reader, subnet *net.IPNet) *net.IP {
	var addr net.IP

	bytes := []byte{}
	r := make([]byte, len(subnet.Mask))
	_, err := rdr.Read(r)
	if err != nil {
		return nil
	}
	for i, b := range subnet.Mask {
		addrByte := (subnet.IP[i] & b) | (^b & r[i])
		bytes = append(bytes, addrByte)
	}
	addr = net.IP(bytes)
	return &addr
}
