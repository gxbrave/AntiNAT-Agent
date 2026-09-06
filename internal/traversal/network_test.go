// Story 1 RED: no-v4, no-default-route, private direct source, and route
// changes must return stable capability codes; the selected direct-v4 source
// interface must itself hold a global IPv4 (v0.8 §3.1 step 1).
package traversal

import (
	"errors"
	"net/netip"
	"testing"
)

// fakeRouteTable is a deterministic RouteTable stand-in so capability
// assessment is testable without host routing state.
type fakeRouteTable struct {
	gateway    netip.Addr
	iface      string
	hasDefault bool
	addrs      []IPv4Address
}

func (f fakeRouteTable) DefaultRouteV4() (netip.Addr, string, bool, error) {
	if !f.hasDefault {
		return netip.Addr{}, "", false, nil
	}
	return f.gateway, f.iface, true, nil
}

func (f fakeRouteTable) IPv4Addresses() ([]IPv4Address, error) {
	return f.addrs, nil
}

func addr(text string) netip.Addr {
	a, err := netip.ParseAddr(text)
	if err != nil {
		panic(err)
	}
	return a
}

func TestIsGlobalV4Classification(t *testing.T) {
	tests := []struct {
		text   string
		global bool
	}{
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"203.0.113.9", false},   // TEST-NET-3 documentation
		{"198.51.100.9", false},  // TEST-NET-2 documentation
		{"192.0.2.9", false},     // TEST-NET-1 documentation
		{"192.0.0.9", false},     // IETF protocol assignments
		{"192.88.99.1", false},   // deprecated 6to4 relay anycast (RFC 7526)
		{"192.31.196.1", false},  // direct delegation AS112 (RFC 7534)
		{"192.175.48.1", false},  // direct delegation AS112 (RFC 7534)
		{"192.52.193.1", false},  // AMT default relay (RFC 7450)
		{"198.18.0.9", false},    // benchmarking
		{"10.1.2.3", false},      // RFC1918
		{"172.16.0.1", false},    // RFC1918
		{"192.168.1.1", false},   // RFC1918
		{"100.64.0.1", false},    // CGNAT RFC6598
		{"169.254.10.10", false}, // link-local
		{"127.0.0.1", false},     // loopback
		{"0.0.0.0", false},       // unspecified
		{"224.0.0.1", false},     // multicast
		{"240.1.2.3", false},     // reserved
		{"255.255.255.255", false},
	}
	for _, tt := range tests {
		got := IsGlobalV4(addr(tt.text))
		if got != tt.global {
			t.Errorf("IsGlobalV4(%s) = %v, want %v", tt.text, got, tt.global)
		}
	}
}

func TestAssessNoIPv4SourceReturnsStableCode(t *testing.T) {
	table := fakeRouteTable{hasDefault: true, iface: "eth0", gateway: addr("192.168.1.1")}
	for round := 0; round < 3; round++ {
		sel, capability, err := Assess(table)
		if !errors.Is(err, ErrV4SourceUnavailable) {
			t.Fatalf("round %d: err = %v, want ErrV4SourceUnavailable", round, err)
		}
		if capability != CapabilityV4SourceUnavailable {
			t.Fatalf("round %d: capability = %q, want %q", round, capability, CapabilityV4SourceUnavailable)
		}
		if sel.Source.IsValid() {
			t.Fatalf("round %d: unexpected source %v", round, sel.Source)
		}
	}
}

func TestAssessNoDefaultRouteReturnsStableCode(t *testing.T) {
	table := fakeRouteTable{
		hasDefault: false,
		addrs:      []IPv4Address{{Interface: "eth0", Addr: addr("192.168.1.10")}},
	}
	for round := 0; round < 3; round++ {
		_, capability, err := Assess(table)
		if !errors.Is(err, ErrV4DefaultRouteUnavailable) {
			t.Fatalf("round %d: err = %v, want ErrV4DefaultRouteUnavailable", round, err)
		}
		if capability != CapabilityV4DefaultRouteUnavailable {
			t.Fatalf("round %d: capability = %q, want %q", round, capability, CapabilityV4DefaultRouteUnavailable)
		}
	}
}

func TestAssessPrivateOnlySourceReturnsNoGlobalV4(t *testing.T) {
	table := fakeRouteTable{
		hasDefault: true,
		iface:      "eth0",
		gateway:    addr("192.168.1.1"),
		addrs: []IPv4Address{
			{Interface: "eth0", Addr: addr("192.168.1.10")},
			{Interface: "eth0", Addr: addr("100.64.0.2")},
			{Interface: "eth0", Addr: addr("169.254.3.4")},
		},
	}
	_, capability, err := Assess(table)
	if !errors.Is(err, ErrNoGlobalV4Source) {
		t.Fatalf("err = %v, want ErrNoGlobalV4Source", err)
	}
	if capability != CapabilityNoGlobalV4Source {
		t.Fatalf("capability = %q, want %q", capability, CapabilityNoGlobalV4Source)
	}
}

func TestAssessGlobalOnNonDefaultInterfaceIsNoGlobalV4(t *testing.T) {
	// direct-v4 requires the *selected* (default-route) interface itself to
	// hold a global IPv4; a global address on another interface whose traffic
	// does not egress via the default route must not be selected.
	table := fakeRouteTable{
		hasDefault: true,
		iface:      "eth0",
		gateway:    addr("192.168.1.1"),
		addrs: []IPv4Address{
			{Interface: "eth0", Addr: addr("192.168.1.10")},
			{Interface: "eth1", Addr: addr("203.0.113.7")},
		},
	}
	_, capability, err := Assess(table)
	if !errors.Is(err, ErrNoGlobalV4Source) {
		t.Fatalf("err = %v, want ErrNoGlobalV4Source", err)
	}
	if capability != CapabilityNoGlobalV4Source {
		t.Fatalf("capability = %q, want %q", capability, CapabilityNoGlobalV4Source)
	}
}

func TestAssessSelectsDeterministicGlobalSource(t *testing.T) {
	makeTable := func() fakeRouteTable {
		return fakeRouteTable{
			hasDefault: true,
			iface:      "eth0",
			gateway:    addr("192.168.1.1"),
			addrs: []IPv4Address{
				{Interface: "eth0", Addr: addr("198.51.100.9")}, // private-ish doc, must lose
				{Interface: "eth0", Addr: addr("8.8.4.4")},
				{Interface: "eth0", Addr: addr("1.1.1.1")},
			},
		}
	}
	reversed := makeTable()
	reversed.addrs = []IPv4Address{
		{Interface: "eth0", Addr: addr("1.1.1.1")},
		{Interface: "eth0", Addr: addr("8.8.4.4")},
		{Interface: "eth0", Addr: addr("198.51.100.9")},
	}
	first, capability, err := Assess(makeTable())
	if err != nil {
		t.Fatalf("first assess: %v", err)
	}
	if capability != CapabilityDirectV4Ready {
		t.Fatalf("capability = %q, want %q", capability, CapabilityDirectV4Ready)
	}
	if !first.Global {
		t.Fatal("selection must report a global source")
	}
	if first.Source != addr("1.1.1.1") || first.Interface != "eth0" {
		t.Fatalf("selection = %+v, want deterministic 1.1.1.1 on eth0", first)
	}
	second, _, err := Assess(reversed)
	if err != nil {
		t.Fatalf("reversed assess: %v", err)
	}
	if first != second {
		t.Fatalf("assess is order-dependent: %+v vs %+v", first, second)
	}
}

func TestAssessStableAcrossRepeatedCalls(t *testing.T) {
	table := fakeRouteTable{
		hasDefault: true,
		iface:      "eth0",
		gateway:    addr("192.168.1.1"),
		addrs:      []IPv4Address{{Interface: "eth0", Addr: addr("8.8.8.8")}},
	}
	want, capability, err := Assess(table)
	if err != nil {
		t.Fatalf("assess: %v", err)
	}
	for round := 0; round < 5; round++ {
		got, gotCapability, err := Assess(table)
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		if got != want || gotCapability != capability {
			t.Fatalf("round %d: unstable result %+v/%q vs %+v/%q", round, got, gotCapability, want, capability)
		}
	}
}

type failingRouteTable struct {
	fakeRouteTable
}

func (failingRouteTable) IPv4Addresses() ([]IPv4Address, error) {
	return nil, errors.New("synthetic reader failure")
}

func TestAssessPropagatesReaderFailure(t *testing.T) {
	_, capability, err := Assess(failingRouteTable{})
	if err == nil {
		t.Fatal("reader failure must surface")
	}
	if capability != "" {
		t.Fatalf("capability = %q, want empty on reader failure", capability)
	}
}
