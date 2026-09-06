// Story 1 RED: the route/interface fingerprint must be stable for an
// unchanged route table and change when the default route gateway or any
// IPv4 interface address changes (v0.8 §2.3: route/interface change forces
// stale + revalidate).
package traversal

import (
	"testing"
)

func TestFingerprintStableForSameRouteTable(t *testing.T) {
	table := fakeRouteTable{
		hasDefault: true,
		iface:      "eth0",
		gateway:    addr("192.168.1.1"),
		addrs: []IPv4Address{
			{Interface: "eth0", Addr: addr("192.168.1.10")},
			{Interface: "eth1", Addr: addr("203.0.113.7")},
		},
	}
	first, err := Fingerprint(table)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	for round := 0; round < 5; round++ {
		got, err := Fingerprint(table)
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		if got != first {
			t.Fatalf("round %d: fingerprint changed %q -> %q", round, first, got)
		}
	}
}

func TestFingerprintChangesWhenAddressChanges(t *testing.T) {
	base := fakeRouteTable{
		hasDefault: true,
		iface:      "eth0",
		gateway:    addr("192.168.1.1"),
		addrs:      []IPv4Address{{Interface: "eth0", Addr: addr("192.168.1.10")}},
	}
	changed := base
	changed.addrs = []IPv4Address{{Interface: "eth0", Addr: addr("192.168.1.11")}}

	before, err := Fingerprint(base)
	if err != nil {
		t.Fatal(err)
	}
	after, err := Fingerprint(changed)
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatalf("address change must alter the fingerprint (%q)", before)
	}
}

func TestFingerprintChangesWhenGatewayChanges(t *testing.T) {
	base := fakeRouteTable{
		hasDefault: true,
		iface:      "eth0",
		gateway:    addr("192.168.1.1"),
		addrs:      []IPv4Address{{Interface: "eth0", Addr: addr("192.168.1.10")}},
	}
	changed := base
	changed.gateway = addr("192.168.1.254")

	before, err := Fingerprint(base)
	if err != nil {
		t.Fatal(err)
	}
	after, err := Fingerprint(changed)
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatalf("gateway change must alter the fingerprint (%q)", before)
	}
}

func TestFingerprintChangesWhenDefaultRouteAppears(t *testing.T) {
	noRoute := fakeRouteTable{
		hasDefault: false,
		addrs:      []IPv4Address{{Interface: "eth0", Addr: addr("192.168.1.10")}},
	}
	withRoute := noRoute
	withRoute.hasDefault = true
	withRoute.iface = "eth0"
	withRoute.gateway = addr("192.168.1.1")

	before, err := Fingerprint(noRoute)
	if err != nil {
		t.Fatal(err)
	}
	after, err := Fingerprint(withRoute)
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatalf("default-route appearance must alter the fingerprint (%q)", before)
	}
}

func TestFingerprintStableWithoutDefaultRoute(t *testing.T) {
	table := fakeRouteTable{
		hasDefault: false,
		addrs:      []IPv4Address{{Interface: "eth0", Addr: addr("192.168.1.10")}},
	}
	first, err := Fingerprint(table)
	if err != nil {
		t.Fatal(err)
	}
	for round := 0; round < 3; round++ {
		got, err := Fingerprint(table)
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		if got != first {
			t.Fatalf("round %d: fingerprint changed", round)
		}
	}
}

func TestFingerprintPropagatesReaderFailure(t *testing.T) {
	_, err := Fingerprint(failingRouteTable{})
	if err == nil {
		t.Fatal("reader failure must surface")
	}
}

func TestFingerprintIgnoresAddressOrder(t *testing.T) {
	base := fakeRouteTable{
		hasDefault: true,
		iface:      "eth0",
		gateway:    addr("192.168.1.1"),
		addrs: []IPv4Address{
			{Interface: "eth0", Addr: addr("192.168.1.10")},
			{Interface: "eth1", Addr: addr("203.0.113.7")},
		},
	}
	reversed := base
	reversed.addrs = []IPv4Address{
		{Interface: "eth1", Addr: addr("203.0.113.7")},
		{Interface: "eth0", Addr: addr("192.168.1.10")},
	}

	first, err := Fingerprint(base)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Fingerprint(reversed)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("address order must not change the fingerprint")
	}
}
