package main

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncryptInitial(t *testing.T) {

	input, _ := hex.DecodeString("060040ee010000ea0303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000006130113021303010000bb0000001800160000136578616d706c652e756c666865696d2e6e6574000a00080006001d001700180010000b00090870696e672f312e30000d00140012040308040401050308050501080606010201003300260024001d0020358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254002d00020101002b00030203040039003103048000fff7040480a0000005048010000006048010000007048010000008010a09010a0a01030b01190f05635f636964")
	expectedCT := "1c36a7ed78716be9711ba498b7ed868443bb2e0c514d4d848eadcc7a00d25ce9f9afa483978088de836be68c0b32a24595d7813ea5414a9199329a6d9f7f760dd8bb249bf3f53d9a77fbb7b395b8d66d7879a51fe59ef9601f79998eb3568e1fdc789f640acab3858a82ef2930fa5ce14b5b9ea0bdb29f4572da85aa3def39b7efafffa074b9267070d50b5d07842e49bba3bc787ff295d6ae3b514305f102afe5a047b3fb4c99eb92a274d244d60492c0e2e6e212cef0f9e3f62efd0955e71c768aa6bb3cd80bbb3755c8b7ebee32712f40f2245119487021b4b84e1565e3ca31967ac8604d4032170dec280aeefa095d08"
	expectedTag := "b3b7241ef6646a6c86e5c62ce08be099"

	result, tag, err := quicEncryptInitial([]byte{}, input, 0)
	require.Nil(t, err)
	require.Equal(t, expectedCT, hex.EncodeToString(result))
	require.Equal(t, expectedTag, hex.EncodeToString(tag))
}

func TestGenerateKeyMaterial(t *testing.T) {

	input, _ := hex.DecodeString("0001020304050607")
	expectedKey := "b14b918124fda5c8d79847602fa3520b"
	expectedIV := "ddbc15dea80925a55686a7df"

	km, err := generateKeyMaterial(input)

	t.Logf("key: %s", hex.EncodeToString(km.key))
	t.Logf("iv: %s", hex.EncodeToString(km.iv))
	t.Logf("hpk: %s", hex.EncodeToString(km.hpk))

	require.Nil(t, err)
	require.Equal(t, expectedKey, hex.EncodeToString(km.key))
	require.Equal(t, expectedIV, hex.EncodeToString(km.iv))
}
