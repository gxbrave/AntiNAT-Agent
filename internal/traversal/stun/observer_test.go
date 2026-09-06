package stun

// Story 7b RED: the manager's same-tuple STUN observation seam. The
// observer refuses foreign-socket observations (an observation from any
// other local socket classifies a different NAT binding); LeaseSource wires
// the shared-port registry to the manager's ListenerSource + SameTupleDialer
// contract; a lease tolerates observer-closed sockets at Release.

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/traversal"
)

// O1: no same-tuple dialer, no observation — an honest observer refuses
// rather than misattribute a foreign socket's NAT binding.
func TestManagerObserverRefusesForeignSocketObservation(t *testing.T) {
	observer := NewManagerObserver()
	_, err := observer(t.Context(), traversal.StunObserveRequest{
		Server: netip.MustParseAddrPort("127.0.0.1:9"),
		Bind:   traversal.TupleKey{Family: "ipv4", Protocol: "tcp", Address: "127.0.0.1", Port: 1234},
	})
	if !errors.Is(err, ErrNoSameTupleDialer) {
		t.Fatalf("error = %v, want ErrNoSameTupleDialer", err)
	}
}

// O2: the full same-tuple path — LeaseSource acquires the forward's
// listener, the observer dials through DialFrom while the listener holds
// the tuple, and the fake STUN server reports the LEASE's own tuple as the
// mapped address: the same-tuple property, verified end to end.
func TestManagerObserverObservesFromLeaseTuple(t *testing.T) {
	if !SharedPortSupported() {
		t.Skip("shared-port sockets need native platform evidence")
	}
	server := newFakeTCPServer(t)
	source := LeaseSource{Registry: NewSharedPortRegistry()}
	listener, actual, release, err := source.Acquire(t.Context(), "forward-stun", traversal.TupleKey{
		Family: "ipv4", Protocol: "tcp", Address: "127.0.0.1", Port: 0,
	})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer func() { _ = listener.Close() }()
	defer func() { _ = release() }()

	observer := NewManagerObserver()
	mapped, err := observer(t.Context(), traversal.StunObserveRequest{
		Server:  server.addr,
		Bind:    actual,
		Timeout: 5 * time.Second,
		Dial: func(ctx context.Context, remote string) (net.Conn, error) {
			return source.DialFrom(ctx, actual, remote)
		},
	})
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	ownTuple := netip.AddrPortFrom(netip.MustParseAddr(actual.Address), actual.Port)
	if mapped != ownTuple {
		t.Fatalf("mapped = %s, want the lease's own tuple %s (same-tuple proof)", mapped, ownTuple)
	}
}

// O3: DialFrom for a tuple the registry never acquired is refused.
func TestLeaseSourceDialFromUnknownTupleRefuses(t *testing.T) {
	if !SharedPortSupported() {
		t.Skip("shared-port sockets need native platform evidence")
	}
	source := LeaseSource{Registry: NewSharedPortRegistry()}
	_, err := source.DialFrom(t.Context(),
		traversal.TupleKey{Family: "ipv4", Protocol: "tcp", Address: "127.0.0.1", Port: 59999},
		"127.0.0.1:9")
	if !errors.Is(err, traversal.ErrStaleLease) {
		t.Fatalf("error = %v, want ErrStaleLease", err)
	}
}

// O4: the observer closes its connection after the exchange; Release must
// not report the already-closed socket as a lease failure.
func TestLeaseReleaseToleratesObserverClosedConn(t *testing.T) {
	if !SharedPortSupported() {
		t.Skip("shared-port sockets need native platform evidence")
	}
	server := newFakeTCPServer(t)
	registry := NewSharedPortRegistry()
	lease, err := registry.Acquire(t.Context(), "forward-stun", traversal.TupleKey{
		Family: "ipv4", Protocol: "tcp", Address: "127.0.0.1", Port: 0,
	})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	conn, err := lease.Dial(t.Context(), server.addr.String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("observer close: %v", err)
	}
	if err := lease.Release(); err != nil {
		t.Fatalf("Release after an observer-closed conn = %v, want nil", err)
	}
}
