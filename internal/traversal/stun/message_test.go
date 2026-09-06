// Story 1 RED: bounded STUN RFC 8489 message codec. Malformed lengths,
// unknown comprehension-required attributes, XOR-MAPPED-ADDRESS, ERROR-CODE
// 300, and the FINGERPRINT/MESSAGE-INTEGRITY boundary must all be handled
// with bounded, non-panicking behavior. Golden vectors are the RFC 5769
// sample request / IPv4 response / IPv6 response, cross-verified against an
// independent Python reference implementation before being pinned here.
package stun

import (
	"errors"
	"net/netip"
	"testing"
)

// rfc5769Request is the RFC 5769 §2.1 sample Binding request (108 bytes).
// Note the USERNAME attribute is padded with 0x20 in the published vector;
// the value length field is 9 ("evtj:h6vY").
const rfc5769Request = "" +
	"000100582112a442b7e7a701bc34d686fa87dfae" +
	"802200105354554e207465737420636c69656e74" +
	"002400046e0001ff" +
	"80290008932ff9b151263b36" +
	"000600096576746a3a68367659202020" +
	"000800149aeaa70cbfd8cb56781ef2b5b2d3f249c1b571a2" +
	"80280004e57a3bcf"

// rfc5769IPv4Response is the RFC 5769 §2.2 sample IPv4 response (80 bytes):
// mapped address 192.0.2.1:32853.
const rfc5769IPv4Response = "" +
	"0101003c2112a442b7e7a701bc34d686fa87dfae" +
	"8022000b7465737420766563746f7220" +
	"002000080001a147e112a643" +
	"000800142b91f599fd9e90c38c7489f92af9ba53f06be7d7" +
	"80280004c07d4c96"

// rfc5769IPv6Response is the RFC 5769 §2.3 sample IPv6 response (88 bytes):
// mapped address 2001:db8:1234:5678:11:2233:4455:6677 port 32853.
const rfc5769IPv6Response = "" +
	"010100482112a442b7e7a701bc34d686fa87dfae" +
	"8022000b7465737420766563746f7220" +
	"002000140002a1470113a9faa5d3f179bc25f4b5bed2b9d9" +
	"00080014a382954e4be67bf11784c97c8292c275bfe3ed41" +
	"80280004c8fb0b4c"

// rfc5769Password is the short-term credential for all RFC 5769 vectors.
const rfc5769Password = "VOkJxbRl1RmTxUk/WvJxBt"

func hexDecode(hex string) ([]byte, error) {
	out := make([]byte, len(hex)/2)
	for i := 0; i < len(out); i++ {
		hi, ok := hexVal(hex[2*i])
		if !ok {
			return nil, errors.New("bad hex digit")
		}
		lo, ok := hexVal(hex[2*i+1])
		if !ok {
			return nil, errors.New("bad hex digit")
		}
		out[i] = hi<<4 | lo
	}
	return out, nil
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func hexEncode(data []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 2*len(data))
	for i, b := range data {
		out[2*i] = digits[b>>4]
		out[2*i+1] = digits[b&0x0f]
	}
	return string(out)
}

func mustHex(t *testing.T, hex string) []byte {
	t.Helper()
	out, err := hexDecode(hex)
	if err != nil {
		t.Fatalf("bad golden hex: %v", err)
	}
	return out
}

func TestParseRFC5769SampleRequest(t *testing.T) {
	raw := mustHex(t, rfc5769Request)
	msg, err := ParseMessage(raw)
	if err != nil {
		t.Fatalf("ParseMessage(rfc5769 request) = %v", err)
	}
	if msg.Type != MessageTypeBindingRequest {
		t.Fatalf("type = %#04x, want binding request %#04x", msg.Type, MessageTypeBindingRequest)
	}
	if got := msg.TransactionID; got != [12]byte{0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae} {
		t.Fatalf("transaction id = %x", got)
	}
	software, ok := msg.Get(AttrSoftware)
	if !ok || string(software) != "STUN test client" {
		t.Fatalf("SOFTWARE = %q (ok=%v)", software, ok)
	}
	username, ok := msg.Get(AttrUsername)
	if !ok || string(username) != "evtj:h6vY" {
		t.Fatalf("USERNAME = %q (ok=%v), want evtj:h6vY", username, ok)
	}
	priority, ok := msg.Get(AttrPriority)
	if !ok || len(priority) != 4 || priority[0] != 0x6e {
		t.Fatalf("PRIORITY = %x (ok=%v)", priority, ok)
	}
	iceControlled, ok := msg.Get(AttrIceControlled)
	if !ok || len(iceControlled) != 8 {
		t.Fatalf("ICE-CONTROLLED = %x (ok=%v)", iceControlled, ok)
	}
	if len(msg.UnknownComprehensionRequired()) != 0 {
		t.Fatalf("unknown comprehension-required = %v, want none", msg.UnknownComprehensionRequired())
	}
}

func TestVerifyRFC5769MessageIntegrityAndFingerprint(t *testing.T) {
	raw := mustHex(t, rfc5769Request)
	msg, err := ParseMessage(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ok, err := msg.VerifyMessageIntegrity([]byte(rfc5769Password))
	if err != nil {
		t.Fatalf("VerifyMessageIntegrity: %v", err)
	}
	if !ok {
		t.Fatal("MESSAGE-INTEGRITY did not verify against RFC 5769 password")
	}
	ok, err = msg.VerifyFingerprint()
	if err != nil {
		t.Fatalf("VerifyFingerprint: %v", err)
	}
	if !ok {
		t.Fatal("FINGERPRINT did not verify")
	}
}

func TestParseRFC5769IPv4Response(t *testing.T) {
	raw := mustHex(t, rfc5769IPv4Response)
	msg, err := ParseMessage(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if msg.Type != MessageTypeBindingSuccess {
		t.Fatalf("type = %#04x, want binding success", msg.Type)
	}
	addr, err := msg.XORMappedAddress()
	if err != nil {
		t.Fatalf("XORMappedAddress: %v", err)
	}
	want := netip.MustParseAddrPort("192.0.2.1:32853")
	if addr != want {
		t.Fatalf("mapped = %v, want %v", addr, want)
	}
	if ok, err := msg.VerifyMessageIntegrity([]byte(rfc5769Password)); err != nil || !ok {
		t.Fatalf("integrity verify = %v, %v", ok, err)
	}
	if ok, err := msg.VerifyFingerprint(); err != nil || !ok {
		t.Fatalf("fingerprint verify = %v, %v", ok, err)
	}
}

func TestParseRFC5769IPv6Response(t *testing.T) {
	raw := mustHex(t, rfc5769IPv6Response)
	msg, err := ParseMessage(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	addr, err := msg.XORMappedAddress()
	if err != nil {
		t.Fatalf("XORMappedAddress: %v", err)
	}
	want := netip.MustParseAddrPort("[2001:db8:1234:5678:11:2233:4455:6677]:32853")
	if addr != want {
		t.Fatalf("mapped = %v, want %v", addr, want)
	}
	if ok, err := msg.VerifyMessageIntegrity([]byte(rfc5769Password)); err != nil || !ok {
		t.Fatalf("integrity verify = %v, %v", ok, err)
	}
	if ok, err := msg.VerifyFingerprint(); err != nil || !ok {
		t.Fatalf("fingerprint verify = %v, %v", ok, err)
	}
}

func TestMarshalRoundTripMatchesGolden(t *testing.T) {
	// A request with normal zero padding must marshal byte-identically to the
	// RFC 5769 construction. Golden bytes were produced by the independent
	// Python reference (same header/attrs/MI/FPR layout, zero padding).
	const golden = "" +
		"000100582112a442b7e7a701bc34d686fa87dfae" +
		"802200105354554e207465737420636c69656e74" +
		"002400046e0001ff" +
		"80290008932ff9b151263b36" +
		"000600096576746a3a68367659000000" +
		"000800147907c2d2edbfea480e4c76d82962d5c3742af9e3" +
		"80280004e352928d"

	msg := NewBindingRequest([12]byte{0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae})
	msg.Add(AttrSoftware, []byte("STUN test client"))
	msg.Add(AttrPriority, []byte{0x6e, 0x00, 0x01, 0xff})
	msg.Add(AttrIceControlled, []byte{0x93, 0x2f, 0xf9, 0xb1, 0x51, 0x26, 0x3b, 0x36})
	msg.Add(AttrUsername, []byte("evtj:h6vY"))
	if err := msg.AddMessageIntegrity([]byte(rfc5769Password)); err != nil {
		t.Fatalf("AddMessageIntegrity: %v", err)
	}
	if err := msg.AddFingerprint(); err != nil {
		t.Fatalf("AddFingerprint: %v", err)
	}
	raw, err := msg.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if got := hexEncode(raw); got != golden {
		t.Fatalf("marshal mismatch:\n got %s\nwant %s", got, golden)
	}
	// Re-parse the marshaled bytes and verify both integrity and fingerprint.
	parsed, err := ParseMessage(raw)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if ok, err := parsed.VerifyMessageIntegrity([]byte(rfc5769Password)); err != nil || !ok {
		t.Fatalf("re-parsed integrity = %v, %v", ok, err)
	}
	if ok, err := parsed.VerifyFingerprint(); err != nil || !ok {
		t.Fatalf("re-parsed fingerprint = %v, %v", ok, err)
	}
}

func TestMalformedLengthsRejected(t *testing.T) {
	good := mustHex(t, rfc5769Request)
	badCookie := append([]byte(nil), good...)
	badCookie[4], badCookie[5], badCookie[6], badCookie[7] = 0x00, 0x00, 0x00, 0x01
	badLength := append([]byte(nil), good...)
	badLength[2], badLength[3] = 0x00, 0x59 // 89: not a multiple of 4
	tests := []struct {
		name string
		raw  []byte
		want error
	}{
		{"empty", nil, ErrTruncated},
		{"short header", good[:19], ErrTruncated},
		{"header only", good[:20], ErrTruncated},
		{"length field exceeds buffer", good[:20+10], ErrTruncated},
		{"declared length not multiple of 4", badLength, ErrMalformed},
		{"attribute overruns message", good[:20+20], ErrTruncated},
		{"bad magic cookie", badCookie, ErrBadCookie},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseMessage(tt.raw)
			if !errors.Is(err, tt.want) {
				t.Fatalf("ParseMessage = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestUnknownComprehensionRequiredReported(t *testing.T) {
	// 0x0025 is comprehension-required (top bit clear) and unknown to the
	// codec; 0x8025 is comprehension-optional and must be ignored silently.
	msg := NewBindingRequest([12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
	msg.Add(AttributeType(0x0025), []byte{1, 2, 3, 4})
	msg.Add(AttributeType(0x8025), []byte{5, 6, 7, 8})
	raw, err := msg.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	parsed, err := ParseMessage(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	unknown := parsed.UnknownComprehensionRequired()
	if len(unknown) != 1 || unknown[0] != AttributeType(0x0025) {
		t.Fatalf("unknown comprehension-required = %v, want [0x0025]", unknown)
	}
}

func TestErrorCode300DecodeEncode(t *testing.T) {
	// Error response with ERROR-CODE 300 Try Alternate and an
	// ALTERNATE-SERVER attribute (RFC 8489 §10).
	msg := NewErrorResponse([12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, 300, "Try Alternate")
	alternate := netip.MustParseAddrPort("203.0.113.9:3478")
	if err := msg.AddAlternateServer(alternate); err != nil {
		t.Fatalf("AddAlternateServer: %v", err)
	}
	raw, err := msg.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	parsed, err := ParseMessage(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.Type != MessageTypeBindingError {
		t.Fatalf("type = %#04x, want binding error", parsed.Type)
	}
	code, reason, err := parsed.ErrorCode()
	if err != nil {
		t.Fatalf("ErrorCode: %v", err)
	}
	if code != 300 || reason != "Try Alternate" {
		t.Fatalf("error code = %d %q, want 300 Try Alternate", code, reason)
	}
	gotAlt, err := parsed.AlternateServer()
	if err != nil {
		t.Fatalf("AlternateServer: %v", err)
	}
	if gotAlt != alternate {
		t.Fatalf("alternate server = %v, want %v", gotAlt, alternate)
	}
}

func TestFingerprintMustBeLast(t *testing.T) {
	// A message with FINGERPRINT in the middle (another attribute after it)
	// is malformed per RFC 8489 §14.7.
	msg := NewBindingRequest([12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
	msg.Add(AttrSoftware, []byte("x"))
	if err := msg.AddFingerprint(); err != nil {
		t.Fatalf("AddFingerprint: %v", err)
	}
	msg.Add(AttrSoftware, []byte("y"))
	raw, err := msg.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := ParseMessage(raw); !errors.Is(err, ErrMalformed) {
		t.Fatalf("ParseMessage = %v, want ErrMalformed", err)
	}
}

func TestOversizeMessageRejected(t *testing.T) {
	// A header whose declared length exceeds the codec bound must be
	// rejected without allocation. The 16-bit field can express 65535, which
	// is not a multiple of 4 (RFC 8489 §5), so the malformed-length gate
	// fires; the defensive > MaxMessageSize check keeps ErrOversize for
	// callers that impose a tighter bound (e.g. the TCP frame reader).
	raw := make([]byte, 24)
	raw[0], raw[1] = 0x00, 0x01 // binding request
	raw[2], raw[3] = 0xff, 0xff // length 65535
	raw[4], raw[5], raw[6], raw[7] = 0x21, 0x12, 0xa4, 0x42
	if _, err := ParseMessage(raw); !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrOversize) {
		t.Fatalf("ParseMessage = %v, want ErrMalformed or ErrOversize", err)
	}
}

func TestMessageIntegrityBoundaryEnforced(t *testing.T) {
	// Attributes after MESSAGE-INTEGRITY other than FINGERPRINT must be
	// ignored by the integrity verification (RFC 8489 §14.5), and a second
	// MESSAGE-INTEGRITY attribute is malformed.
	msg := NewBindingRequest([12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
	msg.Add(AttrSoftware, []byte("a"))
	if err := msg.AddMessageIntegrity([]byte("key")); err != nil {
		t.Fatalf("AddMessageIntegrity: %v", err)
	}
	if err := msg.AddMessageIntegrity([]byte("key")); err == nil {
		t.Fatal("second AddMessageIntegrity succeeded, want error")
	}
	msg.Add(AttrSoftware, []byte("b"))
	raw, err := msg.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	parsed, err := ParseMessage(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// The trailing SOFTWARE attribute sits after MESSAGE-INTEGRITY (without
	// FINGERPRINT); verification must still cover exactly the bytes up to the
	// integrity attribute.
	ok, err := parsed.VerifyMessageIntegrity([]byte("key"))
	if err != nil {
		t.Fatalf("VerifyMessageIntegrity: %v", err)
	}
	if !ok {
		t.Fatal("integrity did not verify across boundary")
	}
	if ok, err := parsed.VerifyMessageIntegrity([]byte("wrong")); err != nil || ok {
		t.Fatalf("wrong key verify = %v, %v, want false", ok, err)
	}
}

func TestXORMappedAddressRoundTrip(t *testing.T) {
	for _, want := range []netip.AddrPort{
		netip.MustParseAddrPort("192.0.2.1:32853"),
		netip.MustParseAddrPort("[2001:db8:1234:5678:11:2233:4455:6677]:32853"),
		netip.MustParseAddrPort("10.0.0.1:3478"),
	} {
		msg := NewBindingRequest([12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
		if err := msg.AddXORMappedAddress(want); err != nil {
			t.Fatalf("AddXORMappedAddress(%v): %v", want, err)
		}
		raw, err := msg.Marshal()
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		parsed, err := ParseMessage(raw)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		got, err := parsed.XORMappedAddress()
		if err != nil {
			t.Fatalf("XORMappedAddress: %v", err)
		}
		if got != want {
			t.Fatalf("mapped = %v, want %v", got, want)
		}
	}
}

func TestDuplicateXORMappedAddressRejected(t *testing.T) {
	// Two XOR-MAPPED-ADDRESS attributes in one message are malformed
	// (RFC 8489 §14.2 rules for multiple occurrences).
	msg := NewBindingRequest([12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
	if err := msg.AddXORMappedAddress(netip.MustParseAddrPort("192.0.2.1:32853")); err != nil {
		t.Fatalf("first AddXORMappedAddress: %v", err)
	}
	if err := msg.AddXORMappedAddress(netip.MustParseAddrPort("192.0.2.2:3478")); !errors.Is(err, ErrDuplicateAddressAttr) {
		t.Fatalf("second AddXORMappedAddress = %v, want ErrDuplicateAddressAttr", err)
	}
}

func TestTransactionIDLengthAndUniqueness(t *testing.T) {
	a, err := NewTransactionID()
	if err != nil {
		t.Fatalf("NewTransactionID: %v", err)
	}
	b, err := NewTransactionID()
	if err != nil {
		t.Fatalf("NewTransactionID: %v", err)
	}
	if a == b {
		t.Fatal("two transaction ids are identical")
	}
	if a == [12]byte{} {
		t.Fatal("transaction id is all zero")
	}
}
