package protocol

import (
	"net/netip"
	"testing"
)

func TestSpecialUseIPv4PrefixesAreNotGlobalEndpoints(t *testing.T) {
	for _, raw := range []string{
		"192.0.0.1",
		"192.31.196.1",
		"192.52.193.1",
		"192.88.99.1",
		"192.175.48.1",
	} {
		ip := netip.MustParseAddr(raw)
		if IsGlobalEndpoint(ip) {
			t.Errorf("%s classified as global", raw)
		}
	}
}
