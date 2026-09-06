// Story 2 RED: port 0, wildcard overlap, duplicate owner, stale release,
// second process and quick restart must all be handled atomically by the
// socket-owning PortRegistry (v0.8 §4.1: create/bind/listen inside the
// registry critical section; a tuple has exactly one listener owner; stale
// releases carry the owner generation and can never close a new owner).
package traversal

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"
)

func acquireLocalhost(t *testing.T, registry *PortRegistry, owner string, port uint16) (*Lease, error) {
	t.Helper()
	return registry.Acquire(context.Background(), owner, TupleKey{
		Family: "ipv4", Protocol: "tcp", Address: "127.0.0.1", Port: port,
	})
}

func bindConflict(t *testing.T, address *net.TCPAddr) {
	t.Helper()
	competitor, err := net.ListenTCP("tcp4", address)
	if competitor != nil {
		competitor.Close()
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("competing bind error = %v, want EADDRINUSE", err)
	}
}

func acquireUDPLocalhost(t *testing.T, registry *PortRegistry, owner string, port uint16) (*UDPLease, error) {
	t.Helper()
	return registry.AcquireUDP(context.Background(), owner, TupleKey{
		Family: "ipv4", Protocol: "udp", Address: "127.0.0.1", Port: port,
	})
}

func bindUDPConflict(t *testing.T, address *net.UDPAddr) {
	t.Helper()
	competitor, err := net.ListenUDP("udp4", address)
	if competitor != nil {
		competitor.Close()
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("competing UDP bind error = %v, want EADDRINUSE", err)
	}
}

func TestAcquireUDPOwnershipLifecycle(t *testing.T) {
	registry := NewPortRegistry()
	oldLease, err := acquireUDPLocalhost(t, registry, "udp-old", 0)
	if err != nil {
		t.Fatalf("acquire UDP: %v", err)
	}
	address := oldLease.Conn.LocalAddr().(*net.UDPAddr)
	if oldLease.Actual.Port != uint16(address.Port) || address.Port == 0 {
		t.Fatalf("UDP actual tuple = %v, socket = %v", oldLease.Actual, address)
	}
	bindUDPConflict(t, address)
	if _, err := registry.AcquireUDP(context.Background(), "overlap", TupleKey{
		Family: "ipv4", Protocol: "udp", Address: "0.0.0.0", Port: uint16(address.Port),
	}); !errors.Is(err, ErrTupleOverlap) {
		t.Fatalf("UDP wildcard overlap error = %v, want ErrTupleOverlap", err)
	}
	if err := oldLease.Release(); err != nil {
		t.Fatalf("release UDP: %v", err)
	}
	newLease, err := acquireUDPLocalhost(t, registry, "udp-new", uint16(address.Port))
	if err != nil {
		t.Fatalf("re-acquire UDP: %v", err)
	}
	defer newLease.Release()
	if err := oldLease.Release(); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("stale UDP release error = %v, want ErrStaleLease", err)
	}
	bindUDPConflict(t, address)
}

func TestTCPAndUDPSamePortDoNotOverlap(t *testing.T) {
	registry := NewPortRegistry()
	tcpLease, err := acquireLocalhost(t, registry, "tcp", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer tcpLease.Release()
	port := uint16(tcpLease.Listener.Addr().(*net.TCPAddr).Port)
	udpLease, err := acquireUDPLocalhost(t, registry, "udp", port)
	if err != nil {
		t.Fatalf("acquire UDP alongside TCP: %v", err)
	}
	defer udpLease.Release()
	if registry.Len() != 2 {
		t.Fatalf("registry length = %d, want 2", registry.Len())
	}
}

func TestAcquirePortZeroOwnsActualSocketAtomically(t *testing.T) {
	registry := NewPortRegistry()
	lease, err := acquireLocalhost(t, registry, "owner-a", 0)
	if err != nil {
		t.Fatalf("acquire port zero: %v", err)
	}
	defer lease.Release()

	actual := lease.Listener.Addr().(*net.TCPAddr)
	if actual.Port == 0 {
		t.Fatal("lease retained port 0")
	}
	if lease.Actual.Port != uint16(actual.Port) {
		t.Fatalf("lease actual port = %d, want %d", lease.Actual.Port, actual.Port)
	}
	bindConflict(t, actual)
	if got := registry.Len(); got != 1 {
		t.Fatalf("registry length = %d, want 1", got)
	}
}

func TestRejectsWildcardSpecificOverlap(t *testing.T) {
	t.Run("specific then wildcard", func(t *testing.T) {
		registry := NewPortRegistry()
		specific, err := acquireLocalhost(t, registry, "specific", 0)
		if err != nil {
			t.Fatalf("acquire specific: %v", err)
		}
		defer specific.Release()
		port := uint16(specific.Listener.Addr().(*net.TCPAddr).Port)
		_, err = registry.Acquire(context.Background(), "wildcard", TupleKey{
			Family: "ipv4", Protocol: "tcp", Address: "0.0.0.0", Port: port,
		})
		if !errors.Is(err, ErrTupleOverlap) {
			t.Fatalf("wildcard overlap error = %v, want ErrTupleOverlap", err)
		}
	})

	t.Run("wildcard then specific", func(t *testing.T) {
		registry := NewPortRegistry()
		wildcard, err := registry.Acquire(context.Background(), "wildcard", TupleKey{
			Family: "ipv4", Protocol: "tcp", Address: "0.0.0.0", Port: 0,
		})
		if err != nil {
			t.Fatalf("acquire wildcard: %v", err)
		}
		defer wildcard.Release()
		port := uint16(wildcard.Listener.Addr().(*net.TCPAddr).Port)
		_, err = acquireLocalhost(t, registry, "specific", port)
		if !errors.Is(err, ErrTupleOverlap) {
			t.Fatalf("specific overlap error = %v, want ErrTupleOverlap", err)
		}
	})
}

func TestDuplicateOwnerSameTupleRejected(t *testing.T) {
	registry := NewPortRegistry()
	first, err := acquireLocalhost(t, registry, "owner", 0)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	defer first.Release()
	port := uint16(first.Listener.Addr().(*net.TCPAddr).Port)
	if _, err := acquireLocalhost(t, registry, "owner", port); !errors.Is(err, ErrTupleOverlap) {
		t.Fatalf("duplicate owner error = %v, want ErrTupleOverlap", err)
	}
}

func TestStaleReleaseCannotCloseNewOwner(t *testing.T) {
	registry := NewPortRegistry()
	oldLease, err := acquireLocalhost(t, registry, "old-owner", 0)
	if err != nil {
		t.Fatalf("acquire old lease: %v", err)
	}
	address := oldLease.Listener.Addr().(*net.TCPAddr)
	if err := oldLease.Release(); err != nil {
		t.Fatalf("release old lease: %v", err)
	}
	newLease, err := acquireLocalhost(t, registry, "new-owner", uint16(address.Port))
	if err != nil {
		t.Fatalf("acquire new lease: %v", err)
	}
	defer newLease.Release()

	if err := oldLease.Release(); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("late old release error = %v, want ErrStaleLease", err)
	}
	bindConflict(t, address)
}

func TestReleaseAfterExternalCloseFreesTuple(t *testing.T) {
	// F1 regression: the documented delete flow is Forward.Close (closes
	// the listener) then lease.Release. Release must treat net.ErrClosed
	// as a successful close — the descriptor is provably gone — so the
	// tuple can be re-acquired. The previous behavior retained a ghost
	// registry entry that blocked delete->recreate until process restart.
	registry := NewPortRegistry()
	lease, err := acquireLocalhost(t, registry, "owner", 0)
	if err != nil {
		t.Fatal(err)
	}
	tuple := lease.Actual
	if err := lease.Listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := lease.Release(); err != nil {
		t.Fatalf("release after external close: %v", err)
	}
	if got := registry.Len(); got != 0 {
		t.Fatalf("registry length after release = %d, want 0", got)
	}
	reacquired, err := acquireLocalhost(t, registry, "owner", tuple.Port)
	if err != nil {
		t.Fatalf("re-acquire same tuple: %v", err)
	}
	defer reacquired.Release()
	if reacquired.Actual != tuple {
		t.Fatalf("re-acquired tuple = %v, want %v", reacquired.Actual, tuple)
	}
}

func TestConcurrentAcquireHasSingleOwner(t *testing.T) {
	probe, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("reserve tuple for test: %v", err)
	}
	address := probe.Addr().(*net.TCPAddr)
	probe.Close()

	registry := NewPortRegistry()
	const contenders = 16
	type acquireResult struct {
		lease *Lease
		err   error
	}
	start := make(chan struct{})
	results := make(chan acquireResult, contenders)
	for contender := 0; contender < contenders; contender++ {
		go func(owner int) {
			<-start
			lease, err := registry.Acquire(context.Background(), fmt.Sprintf("owner-%d", owner), TupleKey{
				Family: "ipv4", Protocol: "tcp", Address: "127.0.0.1", Port: uint16(address.Port),
			})
			results <- acquireResult{lease: lease, err: err}
		}(contender)
	}
	close(start)

	var winner *Lease
	for contender := 0; contender < contenders; contender++ {
		result := <-results
		if result.err == nil {
			if winner != nil {
				t.Fatal("more than one concurrent acquire succeeded")
			}
			winner = result.lease
			continue
		}
		if !errors.Is(result.err, ErrTupleOverlap) {
			t.Fatalf("losing acquire error = %v, want ErrTupleOverlap", result.err)
		}
	}
	if winner == nil {
		t.Fatal("no concurrent acquire succeeded")
	}
	defer winner.Release()
}

func TestUnsupportedTupleRejected(t *testing.T) {
	registry := NewPortRegistry()
	for name, key := range map[string]TupleKey{
		"udp":    {Family: "ipv4", Protocol: "udp", Address: "127.0.0.1"},
		"ipv6":   {Family: "ipv6", Protocol: "tcp", Address: "::1"},
		"family": {Family: "ethernet", Protocol: "tcp", Address: "127.0.0.1"},
	} {
		if _, err := registry.Acquire(context.Background(), "owner", key); !errors.Is(err, ErrUnsupportedTuple) {
			t.Fatalf("%s tuple error = %v, want ErrUnsupportedTuple", name, err)
		}
	}
}

func TestAcquireRejectsEmptyOwner(t *testing.T) {
	registry := NewPortRegistry()
	if _, err := registry.Acquire(context.Background(), "", TupleKey{
		Family: "ipv4", Protocol: "tcp", Address: "127.0.0.1",
	}); err == nil {
		t.Fatal("empty owner must be rejected")
	}
}

func TestRegistryLenAndHas(t *testing.T) {
	registry := NewPortRegistry()
	lease, err := acquireLocalhost(t, registry, "owner", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if got := registry.Len(); got != 1 {
		t.Fatalf("Len = %d, want 1", got)
	}
	if !registry.Has(lease.Actual) {
		t.Fatalf("Has(%v) = false, want true", lease.Actual)
	}
	other := lease.Actual
	other.Port++
	if registry.Has(other) {
		t.Fatalf("Has(%v) = true, want false", other)
	}
	if lease.Owner() != "owner" || lease.Generation() == 0 {
		t.Fatalf("lease identity = %q gen %d, want owner with nonzero generation", lease.Owner(), lease.Generation())
	}
	if err := lease.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	if got := registry.Len(); got != 0 {
		t.Fatalf("Len after release = %d, want 0", got)
	}
}
