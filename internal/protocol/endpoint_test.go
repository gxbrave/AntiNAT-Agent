package protocol

import (
	"net/netip"
	"testing"
)

// Story 4 RED: explicit endpoint/network classification, not
// IsGlobalUnicast alone. Every class in the table must be classified and the
// probe/global predicates must follow the frozen contract.

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return a
}

func TestClassifyIPTable(t *testing.T) {
	cases := []struct {
		ip    string
		class EndpointClass
	}{
		{"0.0.0.0", ClassUnspecified},
		{"0.0.0.1", ClassReserved},
		{"127.0.0.1", ClassLoopback},
		{"127.255.255.255", ClassLoopback},
		{"10.0.0.5", ClassRFC1918},
		{"10.255.255.255", ClassRFC1918},
		{"172.16.0.1", ClassRFC1918},
		{"172.31.255.255", ClassRFC1918},
		{"192.168.1.1", ClassRFC1918},
		{"172.15.0.1", ClassGlobalUnicast}, // just below RFC1918 range
		{"172.32.0.1", ClassGlobalUnicast}, // just above RFC1918 range
		{"100.64.0.1", ClassCGNAT},
		{"100.127.255.255", ClassCGNAT},
		{"100.63.0.1", ClassGlobalUnicast},  // just below CGNAT
		{"100.128.0.1", ClassGlobalUnicast}, // just above CGNAT
		{"169.254.1.1", ClassLinkLocal},
		{"169.254.255.255", ClassLinkLocal},
		{"198.18.0.1", ClassBenchmark},
		{"198.19.255.255", ClassBenchmark},
		{"192.0.2.1", ClassDocumentation},    // TEST-NET-1
		{"198.51.100.7", ClassDocumentation}, // TEST-NET-2 (golden vector)
		{"203.0.113.9", ClassDocumentation},  // TEST-NET-3
		{"224.0.0.1", ClassMulticast},
		{"239.255.255.255", ClassMulticast},
		{"240.0.0.1", ClassReserved},
		{"255.255.255.255", ClassReserved},
		{"8.8.8.8", ClassGlobalUnicast},
		{"198.51.100.7", ClassDocumentation},
		{"::1", ClassLoopback},
		{"::ffff:10.0.0.1", ClassIPv4MappedIPv6},
		{"::ffff:8.8.8.8", ClassIPv4MappedIPv6},
		{"fe80::1", ClassLinkLocal},
		{"fc00::1", ClassRFC1918}, // ULA is private address space
		{"ff02::1", ClassMulticast},
		{"2001:db8::1", ClassDocumentation},
		{"2001:4860:4860::8888", ClassGlobalUnicast},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.ip, func(t *testing.T) {
			got := ClassifyIP(mustAddr(t, tc.ip))
			if got != tc.class {
				t.Fatalf("ClassifyIP(%s) = %v, want %v", tc.ip, got, tc.class)
			}
		})
	}
}

func TestEndpointClassString(t *testing.T) {
	for _, c := range []EndpointClass{
		ClassUnspecified, ClassLoopback, ClassRFC1918, ClassCGNAT,
		ClassLinkLocal, ClassBenchmark, ClassDocumentation, ClassMulticast,
		ClassReserved, ClassGlobalUnicast, ClassIPv4MappedIPv6,
	} {
		if c.String() == "" || c.String() == "Class(0)" {
			t.Fatalf("class %d has no readable name", int(c))
		}
	}
}

// TestIsGlobalEndpoint pins the predicate used by probe arms and published
// candidates: documentation ranges count as global; private/CGNAT/loopback/
// link-local/benchmark/multicast/reserved/unspecified do not.
func TestIsGlobalEndpoint(t *testing.T) {
	global := []string{
		"8.8.8.8", "1.1.1.1", "198.51.100.7", "203.0.113.9", "192.0.2.1",
	}
	for _, s := range global {
		if !IsGlobalEndpoint(mustAddr(t, s)) {
			t.Errorf("IsGlobalEndpoint(%s) = false, want true", s)
		}
	}
	notGlobal := []string{
		"0.0.0.0", "127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1",
		"100.64.0.1", "100.127.0.1", "169.254.1.1", "198.18.0.1",
		"198.19.255.255", "224.0.0.1", "239.1.1.1", "240.0.0.1",
	}
	for _, s := range notGlobal {
		if IsGlobalEndpoint(mustAddr(t, s)) {
			t.Errorf("IsGlobalEndpoint(%s) = true, want false", s)
		}
	}
	// IPv6 is never a v1 global endpoint.
	if IsGlobalEndpoint(mustAddr(t, "2001:4860:4860::8888")) {
		t.Error("IPv6 must not be a global v1 endpoint")
	}
}

// TestValidateEndpointAndPort pins the hostport validator used by config and
// domain inputs.
func TestValidateEndpointAndPort(t *testing.T) {
	ap, err := ValidateEndpoint("198.51.100.7:4444")
	if err != nil {
		t.Fatalf("valid endpoint rejected: %v", err)
	}
	if ap.Port() != 4444 {
		t.Fatalf("port mismatch: %d", ap.Port())
	}
	for _, bad := range []string{
		"", "example.com:80", "[2001:db8::1]:80", "10.0.0.1:80",
		"192.168.1.1:80", "127.0.0.1:80", "100.64.0.1:80", "0.0.0.0:80",
		"198.51.100.7", "198.51.100.7:0", "198.51.100.7:65536", "198.51.100.7:x",
	} {
		if _, err := ValidateEndpoint(bad); err == nil {
			t.Errorf("invalid endpoint %q accepted", bad)
		}
	}
}

// TestClassifyTableCompleteness guards against future enum drift: every
// EndpointClass must appear in the table for at least one address.
func TestClassifyTableCompleteness(t *testing.T) {
	seen := map[EndpointClass]bool{}
	for _, ip := range []string{
		"0.0.0.0", "127.0.0.1", "10.0.0.1", "100.64.0.1", "169.254.1.1",
		"198.18.0.1", "198.51.100.7", "224.0.0.1", "240.0.0.1", "8.8.8.8",
		"::ffff:8.8.8.8", "fe80::1", "fc00::1", "ff02::1", "2001:db8::1",
		"2001:4860:4860::8888",
	} {
		seen[ClassifyIP(mustAddr(t, ip))] = true
	}
	if len(seen) != len(allEndpointClasses()) {
		t.Fatalf("classification table covers %d classes, want %d", len(seen), len(allEndpointClasses()))
	}
}

func allEndpointClasses() []EndpointClass {
	return []EndpointClass{
		ClassUnspecified, ClassLoopback, ClassRFC1918, ClassCGNAT,
		ClassLinkLocal, ClassBenchmark, ClassDocumentation, ClassMulticast,
		ClassReserved, ClassGlobalUnicast, ClassIPv4MappedIPv6,
	}
}
