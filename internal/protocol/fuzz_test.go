package protocol

import (
	"bytes"
	"crypto/ed25519"
	"net/netip"
	"testing"
)

// Story 6 fuzz targets: frame, JSON payload, probe frames, and endpoint
// classification must never panic or allocate unboundedly on arbitrary input.

var fuzzPeerKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, 32)).Public().(ed25519.PublicKey)

// FuzzParseEnvelope drives the control-envelope parser with arbitrary bytes.
func FuzzParseEnvelope(f *testing.F) {
	// Seed with the frozen valid and invalid control-envelope frames.
	f.Add([]byte("ANAT\x01\x00\x00\x00\x00\x00\x00\x00\x00"))
	f.Add([]byte("XXXX"))
	f.Add([]byte("ANAT"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = ParseEnvelope(data, fuzzPeerKey)
	})
}

// FuzzParseEnrollment drives the enrollment parsers with arbitrary bytes.
func FuzzParseEnrollment(f *testing.F) {
	var ch [32]byte
	f.Add([]byte("challenge"))
	f.Add([]byte{0x00, 0x00, 0x00, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseEnrollChallenge(data, fuzzPeerKey)
		_, _ = ParseEnrollRequest(data, ch)
		_, _ = ParseEnrollResult(data, fuzzPeerKey)
	})
}

// FuzzParseProbe drives all probe frame parsers with arbitrary bytes.
func FuzzParseProbe(f *testing.F) {
	f.Add([]byte("ARM1"))
	f.Add([]byte("WAN1"))
	f.Add([]byte("ACK1"))
	f.Add([]byte("RCT1"))
	f.Add([]byte("RDY1"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseProbeArm(data)
		_, _ = ParseProviderFrame(data)
		_, _ = ParseProbeACK(data, fuzzPeerKey)
		_, _ = ParseProbeReceipt(data, fuzzPeerKey)
	})
}

// FuzzStrictJSON drives the strict JSON decoder with arbitrary bytes.
func FuzzStrictJSON(f *testing.F) {
	f.Add([]byte(`{"a":1,"b":"x"}`))
	f.Add([]byte(`{"a":1,"a":2}`))
	f.Add([]byte(`[1,2,3]`))
	f.Add([]byte(`{"a":9223372036854775808}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = ValidateStrictJSON(data, nil)
		_, _ = DecodeStrictJSON(data, nil)
	})
}

// FuzzClassifyEndpoint drives the endpoint classification with arbitrary
// strings (which may or may not parse as IPs).
func FuzzClassifyEndpoint(f *testing.F) {
	f.Add([]byte("198.51.100.7"))
	f.Add([]byte("100.64.0.1"))
	f.Add([]byte("::ffff:10.0.0.1"))
	f.Add([]byte("2001:db8::1"))
	f.Add([]byte("not-an-ip"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if ip, err := netip.ParseAddr(string(data)); err == nil {
			_ = ClassifyIP(ip)
			_ = IsGlobalEndpoint(ip)
		}
	})
}
