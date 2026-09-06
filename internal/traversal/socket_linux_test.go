// Story 1 RED: /proc/net/route parsing and real-host determinism.
package traversal

import (
	"errors"
	"net"
	"testing"
)

// TestIPv4AddressesAcceptsMappedInput is the F1 regression: IPv6-enabled
// hosts report interface IPv4 addresses as 16-byte IPv4-mapped addresses
// (::ffff:x.x.x.x). netip.AddrFromSlice returns those in IPv6 form
// (Is4In6, not Is4), so the Is4 gate must run after Unmap or every IPv4
// address is silently dropped and IPv4Addresses() returns [].
func TestIPv4AddressesAcceptsMappedInput(t *testing.T) {
	mapped := net.IPv4(192, 168, 6, 99) // 16-byte ::ffff:192.168.6.99
	if len(mapped) != 16 {
		t.Fatalf("fixture must be 16 bytes, got %d", len(mapped))
	}
	got, ok := usableV4(mapped)
	if !ok || got != addr("192.168.6.99") {
		t.Fatalf("usableV4(%v) = %v, %v; want 192.168.6.99, true", mapped, got, ok)
	}
	if got.Is4In6() {
		t.Fatalf("usableV4(%v) = %v, want unmapped canonical IPv4", mapped, got)
	}
	// The plain 4-byte form must keep working too.
	got, ok = usableV4(net.IP{192, 168, 6, 99})
	if !ok || got != addr("192.168.6.99") {
		t.Fatalf("usableV4(4-byte) = %v, %v; want 192.168.6.99, true", got, ok)
	}
}

func TestUsableV4RejectsNonV4(t *testing.T) {
	for name, fixture := range map[string]net.IP{
		"real ipv6":   net.ParseIP("fe80::5069:bbff:febb:bbbb"),
		"unspecified": {},
		"nil":         nil,
	} {
		_, ok := usableV4(fixture)
		if ok {
			t.Fatalf("%s: usableV4(%v) unexpectedly accepted", name, fixture)
		}
	}
}

func TestParseProcNetRouteDefault(t *testing.T) {
	fixture := `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	00000000	0102A8C0	0003	0	0	0	00000000	0	0	0
`
	gateway, iface, ok, err := parseProcNetRoute([]byte(fixture))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !ok {
		t.Fatal("default route not detected")
	}
	if iface != "eth0" {
		t.Fatalf("iface = %q, want eth0", iface)
	}
	// 0102A8C0 is little-endian: c0 a8 02 01 = 192.168.2.1
	if gateway != addr("192.168.2.1") {
		t.Fatalf("gateway = %v, want 192.168.2.1", gateway)
	}
}

func TestParseProcNetRouteNoDefault(t *testing.T) {
	fixture := `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	00011AA8	00000000	0001	0	0	0	00FFFFFF	0	0	0
`
	_, _, ok, err := parseProcNetRoute([]byte(fixture))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if ok {
		t.Fatal("non-default route must not count as a default route")
	}
}

func TestParseProcNetRoutePicksLowestMetric(t *testing.T) {
	fixture := `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth1	00000000	0102A8C0	0003	0	0	100	00000000	0	0	0
eth0	00000000	FE01A8C0	0003	0	0	50	00000000	0	0	0
`
	gateway, iface, ok, err := parseProcNetRoute([]byte(fixture))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !ok {
		t.Fatal("default route not detected")
	}
	if iface != "eth0" {
		t.Fatalf("iface = %q, want lowest-metric eth0", iface)
	}
	// FE01A8C0 little-endian: c0 a8 01 fe = 192.168.1.254
	if gateway != addr("192.168.1.254") {
		t.Fatalf("gateway = %v, want 192.168.1.254", gateway)
	}
}

func TestParseProcNetRouteTieBreaksByInterfaceName(t *testing.T) {
	fixture := `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth1	00000000	0102A8C0	0003	0	0	50	00000000	0	0	0
eth0	00000000	FE01A8C0	0003	0	0	50	00000000	0	0	0
`
	_, iface, ok, err := parseProcNetRoute([]byte(fixture))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !ok {
		t.Fatal("default route not detected")
	}
	if iface != "eth0" {
		t.Fatalf("tie must break lexicographically, iface = %q, want eth0", iface)
	}
}

func TestParseProcNetRouteRejectsGarbage(t *testing.T) {
	for _, fixture := range []string{
		"not a route table",
		"Iface	Destination	Gateway 	Flags\neth0	ZZZZ0000	00000000	0003\n",
	} {
		if _, _, _, err := parseProcNetRoute([]byte(fixture)); err == nil {
			t.Fatalf("garbage %q must error", fixture)
		}
	}
}

func TestParseProcNetRouteHeaderOnlyIsEmptyTable(t *testing.T) {
	_, _, ok, err := parseProcNetRoute([]byte("Iface	Destination	Gateway\n"))
	if err != nil {
		t.Fatalf("header-only table must parse: %v", err)
	}
	if ok {
		t.Fatal("header-only table must not contain a default route")
	}
}

func TestHostRouteTableDeterministic(t *testing.T) {
	table := HostRouteTable{}

	// The live host must expose its real IPv4 state. This test used to
	// skip on any Assess error, which masked the F1 regression (every
	// IPv4 address silently dropped on IPv6-enabled hosts); a host that
	// reports no non-loopback IPv4 is now a failure, not a skip.
	addrs, err := table.IPv4Addresses()
	if err != nil {
		t.Fatalf("host IPv4 addresses: %v", err)
	}
	if len(addrs) == 0 {
		t.Fatal("host must expose at least one non-loopback IPv4 address (F1 regression: IPv4-mapped addresses were silently dropped)")
	}
	for _, address := range addrs {
		if !address.Addr.Is4() {
			t.Fatalf("host address %s on %s is not canonical IPv4", address.Addr, address.Interface)
		}
	}

	// Capability sentinels (no default route, private-only sources) are
	// valid host states; the determinism contract applies regardless. A
	// genuine reader failure fails the test.
	first, capability, firstErr := Assess(table)
	if firstErr != nil && !errors.Is(firstErr, ErrV4DefaultRouteUnavailable) &&
		!errors.Is(firstErr, ErrNoGlobalV4Source) {
		t.Fatalf("host assessment failed: %v", firstErr)
	}
	for round := 0; round < 3; round++ {
		got, gotCapability, err := Assess(table)
		if !errors.Is(err, firstErr) {
			t.Fatalf("round %d: error changed %v vs %v", round, err, firstErr)
		}
		if got != first || gotCapability != capability {
			t.Fatalf("round %d: unstable host assessment %+v/%q vs %+v/%q", round, got, gotCapability, first, capability)
		}
	}
	fp1, err := Fingerprint(table)
	if err != nil {
		t.Fatal(err)
	}
	fp2, err := Fingerprint(table)
	if err != nil {
		t.Fatal(err)
	}
	if fp1 != fp2 {
		t.Fatalf("host fingerprint unstable: %q vs %q", fp1, fp2)
	}
}
