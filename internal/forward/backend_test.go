// Story 3 RED: the Backend target type must parse and validate an IPv4
// literal:port target (v1 Forwards are IPv4-only; v6/hostname targets are
// rejected). Hot update is Story 4.
package forward

import (
	"net/netip"
	"testing"
)

func TestNewBackendRejectsInvalidTarget(t *testing.T) {
	for _, target := range []string{
		"",
		"nope",
		"host:80",
		"127.0.0.1",
		"127.0.0.1:notaport",
		"10.0.0.1:70000",
		"[::1]:80",
		"::1",
	} {
		if _, err := NewBackend(target); err == nil {
			t.Errorf("NewBackend(%q) unexpectedly succeeded", target)
		}
	}
}

func TestBackendTargetRoundTrip(t *testing.T) {
	backend, err := NewBackend("127.0.0.1:8080")
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}
	want := netip.MustParseAddrPort("127.0.0.1:8080")
	if got := backend.Target(); got != want {
		t.Fatalf("Target() = %v, want %v", got, want)
	}
}
