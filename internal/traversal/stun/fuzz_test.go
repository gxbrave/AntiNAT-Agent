// Fuzz targets: the codec and TCP frame reader must never panic on
// arbitrary input (Story 6: fuzz never panics). Exactly one Fuzz* target
// exists so `go test -fuzz=Fuzz` matches unambiguously; it exercises both
// the bounded message parser and the frame reader on the same corpus.
package stun

import (
	"bytes"
	"testing"
)

// FuzzMessage feeds arbitrary bytes to ParseMessage and readFrame. Neither
// may panic; every outcome must be a classified error or a valid message.
func FuzzMessage(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte("garbage"))
	f.Add(mustFuzzSeed(rfc5769Request))
	f.Add(mustFuzzSeed(rfc5769IPv4Response))
	f.Add(mustFuzzSeed(rfc5769IPv6Response))
	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := ParseMessage(data)
		if err == nil {
			if msg == nil {
				t.Fatal("ParseMessage returned nil message with nil error")
			}
			// A successfully parsed message must re-marshal without panic.
			wire, err := msg.Marshal()
			if err != nil {
				t.Fatalf("re-marshal of parsed message: %v", err)
			}
			if len(wire) < HeaderSize {
				t.Fatalf("re-marshaled message too short: %d", len(wire))
			}
		} else if err != ErrTruncated && err != ErrMalformed && err != ErrBadCookie && err != ErrOversize &&
			err != ErrNoIntegrity && err != ErrNoFingerprint && err != ErrIntegrityMismatch &&
			err != ErrFingerprintMismatch && err != ErrUnknownFamily && err != ErrDuplicateAddressAttr {
			t.Fatalf("unexpected parse error: %v", err)
		}
		// Frame reader must tolerate the same bytes (it may treat a
		// truncated tail as a partial frame and report no error).
		_, _ = readFrame(bytes.NewReader(data), MaxMessageSize)
	})
}

func mustFuzzSeed(hex string) []byte {
	out, err := hexDecode(hex)
	if err != nil {
		panic(err)
	}
	return out
}
