package traversal

// Story 7b RED: DefaultRouteSource returns the default-route interface's
// own IPv4 — private or global — for the gateway strategies. Assess's
// global-only rule governs direct-v4 only; behind a NAT CPE the first-hop
// gateway sees a private internal source (v0.8 §3.2), and mapping
// 127.0.0.1 instead would ask the gateway to forward its own loopback.

import (
	"errors"
	"net/netip"
	"testing"
)

func TestDefaultRouteSourceAllowsPrivateSource(t *testing.T) {
	selection, err := DefaultRouteSource(managerRouteTable())
	if err != nil {
		t.Fatalf("DefaultRouteSource: %v", err)
	}
	if selection.Source.String() != "10.0.0.2" {
		t.Fatalf("source = %s, want the private default-route address 10.0.0.2", selection.Source)
	}
	if selection.Global {
		t.Fatal("a private source must not be marked Global")
	}
	if selection.Interface != "lan0" || selection.DefaultRouteInterface != "lan0" || selection.DefaultRouteGateway.String() != "10.0.0.1" {
		t.Fatalf("selection metadata = %+v", selection)
	}
}

func TestDefaultRouteSourceMarksGlobalSource(t *testing.T) {
	rt := managerRouteTableImpl{
		addresses: []IPv4Address{{Interface: "lan0", Addr: netip.MustParseAddr("8.8.8.8")}},
	}
	selection, err := DefaultRouteSource(rt)
	if err != nil {
		t.Fatalf("DefaultRouteSource: %v", err)
	}
	if selection.Source.String() != "8.8.8.8" || !selection.Global {
		t.Fatalf("selection = %+v, want the global source marked Global", selection)
	}
}

func TestDefaultRouteSourceRefusesUnusableSources(t *testing.T) {
	for _, addr := range []string{"127.0.0.1", "169.254.9.9", "239.1.1.1", "0.0.0.0"} {
		rt := managerRouteTableImpl{
			addresses: []IPv4Address{{Interface: "lan0", Addr: netip.MustParseAddr(addr)}},
		}
		if _, err := DefaultRouteSource(rt); !errors.Is(err, ErrInternalSourceUnavailable) {
			t.Fatalf("%s: error = %v, want ErrInternalSourceUnavailable", addr, err)
		}
	}
}

func TestDefaultRouteSourceRequiresRouteAndAddresses(t *testing.T) {
	if _, err := DefaultRouteSource(managerRouteTableImpl{}); !errors.Is(err, ErrV4SourceUnavailable) {
		t.Fatalf("no addresses: error = %v, want ErrV4SourceUnavailable", err)
	}
	if _, err := DefaultRouteSource(noDefaultRouteTable{
		addresses: []IPv4Address{{Interface: "lan0", Addr: netip.MustParseAddr("10.0.0.2")}},
	}); !errors.Is(err, ErrV4DefaultRouteUnavailable) {
		t.Fatalf("no default route: error = %v, want ErrV4DefaultRouteUnavailable", err)
	}
}

func TestDefaultRouteSourcePropagatesReaderFailure(t *testing.T) {
	if _, err := DefaultRouteSource(errorRouteTable{}); err == nil {
		t.Fatal("a route-table reader failure must be surfaced, never guessed")
	}
}

func TestDefaultRouteSourceIsDeterministic(t *testing.T) {
	forward := managerRouteTableImpl{addresses: []IPv4Address{
		{Interface: "lan0", Addr: netip.MustParseAddr("10.0.0.9")},
		{Interface: "lan0", Addr: netip.MustParseAddr("10.0.0.2")},
	}}
	reversed := managerRouteTableImpl{addresses: []IPv4Address{
		{Interface: "lan0", Addr: netip.MustParseAddr("10.0.0.2")},
		{Interface: "lan0", Addr: netip.MustParseAddr("10.0.0.9")},
	}}
	first, err := DefaultRouteSource(forward)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := DefaultRouteSource(reversed)
	if err != nil {
		t.Fatalf("reversed: %v", err)
	}
	if first != second {
		t.Fatalf("address order from the reader must not matter: %+v vs %+v", first, second)
	}
}

// noDefaultRouteTable is a route table without an IPv4 default route.
type noDefaultRouteTable struct {
	addresses []IPv4Address
}

func (noDefaultRouteTable) DefaultRouteV4() (netip.Addr, string, bool, error) {
	return netip.Addr{}, "", false, nil
}

func (t noDefaultRouteTable) IPv4Addresses() ([]IPv4Address, error) { return t.addresses, nil }

// errorRouteTable fails its reader: failures are surfaced, never guessed.
type errorRouteTable struct{}

func (errorRouteTable) DefaultRouteV4() (netip.Addr, string, bool, error) {
	return netip.Addr{}, "", false, errors.New("reader down")
}

func (errorRouteTable) IPv4Addresses() ([]IPv4Address, error) {
	return nil, errors.New("reader down")
}
