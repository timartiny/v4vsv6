package main

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTLSLen(t *testing.T) {

	b, _ := hex.DecodeString("6578616d706c652e756c666865696d2e6e6574")
	require.Equal(t, 19, len(b))
	require.Equal(t, "0013", fmt.Sprintf("%04x", len(b)))
}

// func TestTLSPayload(t *testing.T) {
// 	p := &tlsProber{
// 		seed: 01234,
// 	}

// 	expected := "16030100f8010000f40303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000813021303130100ff010000a30000001800160000136578616d706c652e756c666865696d2e6e6574000b000403000102000a00160014001d0017001e0019001801000101010201030104002300000016000000170000000d001e001c040305030603080708080809080a080b080408050806040105010601002b0003020304002d00020101003300260024001d0020358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254"

// 	hostname := "example.ulfheim.net"
// 	payload, err := p.buildPaylaod(hostname)
// 	require.Nil(t, err)
// 	require.Equal(t, expected, hex.EncodeToString(payload))
// }
