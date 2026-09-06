// Story 4 RED: shared-port sockets. One tuple may hold a reuse-enabled
// listener plus connected sockets (v0.8 §4.2); duplicate listener and
// wildcard/specific overlap are rejected; stale owner releases can never
// close a new owner. The registry mirrors the P09 PortRegistry ownership
// discipline (owner, generation, atomic acquire, actual-port resolution);
// the OS bind remains the final authority across registries. Linux is
// supported per P02 evidence (tcp-shared-port-linux.json); platforms without
// native evidence gate the feature off.
package stun

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/traversal"
)

// echoTCPServer accepts connections and echoes one byte back each, until the
// listener is closed (t.Cleanup).
func echoTCPServer(t *testing.T) (addr string, done chan struct{}) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	done = make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1)
				if _, err := c.Read(buf); err != nil {
					return
				}
				_, _ = c.Write(buf)
			}(conn)
		}
	}()
	t.Cleanup(func() { listener.Close() })
	return listener.Addr().String(), done
}

// roundTrip dials remote from the given local tuple (with the platform reuse
// options), sends one byte and waits for the echo.
func roundTrip(t *testing.T, local traversal.TupleKey, remote string, reuse bool) error {
	t.Helper()
	dialer := net.Dialer{LocalAddr: &net.TCPAddr{
		IP:   net.ParseIP(local.Address),
		Port: int(local.Port),
	}}
	if reuse {
		dialer.Control = traversal.StunSharedPortControl
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp4", remote)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	if _, err := conn.Write([]byte{0x42}); err != nil {
		return err
	}
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err != nil {
		return err
	}
	if buf[0] != 0x42 {
		return errors.New("echo mismatch")
	}
	return nil
}

func TestSharedPortGate(t *testing.T) {
	// The gate must be true exactly where native evidence exists. On this
	// host (linux) the P02 spike proved listener + connected sockets share a
	// tuple deterministically; elsewhere the feature is disabled honestly.
	if !SharedPortSupported() {
		t.Skip("platform without native shared-port evidence; gate off is the expected state")
	}
	// Reached only when the platform claims support: the adapter must
	// actually create reuse-enabled sockets (the probe evidence), not just
	// report a flag.
	registry := NewSharedPortRegistry()
	lease, err := registry.Acquire(context.Background(), "gate-probe", traversal.TupleKey{
		Family: "ipv4", Protocol: "tcp", Address: "127.0.0.1", Port: 0,
	})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer lease.Release()
	if lease.Actual.Port == 0 {
		t.Fatal("lease kept port 0")
	}
}

func TestSharedPortListenerPlusConnectedSockets(t *testing.T) {
	if !SharedPortSupported() {
		t.Skip("shared-port requires native platform evidence")
	}
	registry := NewSharedPortRegistry()
	lease, err := registry.Acquire(context.Background(), "owner", traversal.TupleKey{
		Family: "ipv4", Protocol: "tcp", Address: "127.0.0.1", Port: 0,
	})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer lease.Release()

	echoA, _ := echoTCPServer(t)
	echoB, _ := echoTCPServer(t)
	// Two distinct remote 4-tuples from the SAME local tuple while the
	// listener stays open: deterministic dispatch (P02 spike evidence).
	if err := roundTrip(t, lease.Actual, echoA, true); err != nil {
		t.Fatalf("first connected socket: %v", err)
	}
	if err := roundTrip(t, lease.Actual, echoB, true); err != nil {
		t.Fatalf("second connected socket: %v", err)
	}
	// The listener must still be accepting (it was never closed).
	if err := roundTrip(t, lease.Actual, echoA, true); err != nil {
		t.Fatalf("listener tuple still usable: %v", err)
	}
}

func TestSharedPortDuplicateListenerRejected(t *testing.T) {
	if !SharedPortSupported() {
		t.Skip("shared-port requires native platform evidence")
	}
	registry := NewSharedPortRegistry()
	lease, err := registry.Acquire(context.Background(), "owner-a", traversal.TupleKey{
		Family: "ipv4", Protocol: "tcp", Address: "127.0.0.1", Port: 0,
	})
	if err != nil {
		t.Fatalf("first Acquire: %v", err)
	}
	defer lease.Release()
	_, err = registry.Acquire(context.Background(), "owner-b", lease.Actual)
	if !errors.Is(err, traversal.ErrTupleOverlap) {
		t.Fatalf("duplicate Acquire = %v, want ErrTupleOverlap", err)
	}
}

func TestSharedPortWildcardOverlapRejected(t *testing.T) {
	if !SharedPortSupported() {
		t.Skip("shared-port requires native platform evidence")
	}
	registry := NewSharedPortRegistry()
	t.Run("specific then wildcard", func(t *testing.T) {
		specific, err := registry.Acquire(context.Background(), "specific", traversal.TupleKey{
			Family: "ipv4", Protocol: "tcp", Address: "127.0.0.1", Port: 0,
		})
		if err != nil {
			t.Fatalf("specific Acquire: %v", err)
		}
		defer specific.Release()
		_, err = registry.Acquire(context.Background(), "wildcard", traversal.TupleKey{
			Family: "ipv4", Protocol: "tcp", Address: "0.0.0.0", Port: specific.Actual.Port,
		})
		if !errors.Is(err, traversal.ErrTupleOverlap) {
			t.Fatalf("wildcard over specific = %v, want ErrTupleOverlap", err)
		}
	})
	t.Run("wildcard then specific", func(t *testing.T) {
		wildcard, err := registry.Acquire(context.Background(), "wildcard", traversal.TupleKey{
			Family: "ipv4", Protocol: "tcp", Address: "0.0.0.0", Port: 0,
		})
		if err != nil {
			t.Fatalf("wildcard Acquire: %v", err)
		}
		defer wildcard.Release()
		_, err = registry.Acquire(context.Background(), "specific", traversal.TupleKey{
			Family: "ipv4", Protocol: "tcp", Address: "127.0.0.1", Port: wildcard.Actual.Port,
		})
		if !errors.Is(err, traversal.ErrTupleOverlap) {
			t.Fatalf("specific over wildcard = %v, want ErrTupleOverlap", err)
		}
	})
}

func TestSharedPortStaleOwnerClose(t *testing.T) {
	if !SharedPortSupported() {
		t.Skip("shared-port requires native platform evidence")
	}
	registry := NewSharedPortRegistry()
	first, err := registry.Acquire(context.Background(), "owner-a", traversal.TupleKey{
		Family: "ipv4", Protocol: "tcp", Address: "127.0.0.1", Port: 0,
	})
	if err != nil {
		t.Fatalf("first Acquire: %v", err)
	}
	if err := first.Release(); err != nil {
		t.Fatalf("first Release: %v", err)
	}
	second, err := registry.Acquire(context.Background(), "owner-b", first.Actual)
	if err != nil {
		t.Fatalf("second Acquire: %v", err)
	}
	defer second.Release()
	// The stale release carries the old generation and must not close the
	// new owner's listener.
	if err := first.Release(); !errors.Is(err, traversal.ErrStaleLease) {
		t.Fatalf("stale Release = %v, want ErrStaleLease", err)
	}
	echo, _ := echoTCPServer(t)
	if err := roundTrip(t, second.Actual, echo, true); err != nil {
		t.Fatalf("new owner's tuple broken by stale release: %v", err)
	}
}

func TestSharedPortReleaseClosesConnectedSockets(t *testing.T) {
	if !SharedPortSupported() {
		t.Skip("shared-port requires native platform evidence")
	}
	registry := NewSharedPortRegistry()
	lease, err := registry.Acquire(context.Background(), "owner", traversal.TupleKey{
		Family: "ipv4", Protocol: "tcp", Address: "127.0.0.1", Port: 0,
	})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	echo, _ := echoTCPServer(t)
	conn, err := lease.Dial(context.Background(), echo)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	// Complete one round trip so the connection is established, then release
	// the lease: the connected socket must be closed with it.
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write([]byte{0x42}); err != nil {
		t.Fatalf("write before release: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("read before release: %v", err)
	}
	if err := lease.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("connected socket still readable after Release")
	}

}

// connTracker accepts TCP connections, records them, and signals through
// eof when a connection observes EOF (the peer closed its side).
type connTracker struct {
	addr  string
	mu    sync.Mutex
	conns []net.Conn
	eof   chan struct{}
}

func newConnTracker(t *testing.T) *connTracker {
	t.Helper()
	tr := &connTracker{eof: make(chan struct{}, 1)}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("tracker listen: %v", err)
	}
	tr.addr = listener.Addr().String()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			tr.mu.Lock()
			tr.conns = append(tr.conns, conn)
			tr.mu.Unlock()
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1)
				if _, err := c.Read(buf); err != nil {
					select {
					case tr.eof <- struct{}{}:
					default:
					}
				}
			}(conn)
		}
	}()
	t.Cleanup(func() { listener.Close() })
	return tr
}

func (tr *connTracker) sawEOF(timeout time.Duration) bool {
	select {
	case <-tr.eof:
		return true
	case <-time.After(timeout):
		return false
	}
}

func TestSharedPortDialRacingReleaseClosesSocket(t *testing.T) {
	// A Dial in flight when Release runs must not leave an unowned socket
	// bound to the tuple: the completed dial observes the released flag,
	// closes its connection, and returns ErrStaleLease. The beforeAppend
	// seam pauses the dial deterministically at the hand-over point so the
	// race is exercised exactly, not probabilistically.
	if !SharedPortSupported() {
		t.Skip("shared-port requires native platform evidence")
	}
	registry := NewSharedPortRegistry()
	lease, err := registry.Acquire(context.Background(), "owner", traversal.TupleKey{
		Family: "ipv4", Protocol: "tcp", Address: "127.0.0.1", Port: 0,
	})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	tracker := newConnTracker(t)

	dialResult := make(chan error, 1)
	releaseDone := make(chan struct{})
	proceed := make(chan struct{})
	lease.beforeAppend = func() {
		close(releaseDone) // dial completed; waiting at the hand-over point
		<-proceed          // Release has run by the time this returns
	}
	go func() {
		_, err := lease.Dial(context.Background(), tracker.addr)
		dialResult <- err
	}()
	select {
	case <-releaseDone:
	case <-time.After(2 * time.Second):
		t.Fatal("dial never reached the hand-over point")
	}
	if err := lease.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	close(proceed)
	if err := <-dialResult; !errors.Is(err, traversal.ErrStaleLease) {
		t.Fatalf("Dial = %v, want ErrStaleLease (socket must not outlive its lease)", err)
	}
	if !tracker.sawEOF(time.Second) {
		t.Fatal("racing dial's socket was not closed after Release (leak)")
	}
	// The tuple is fully free: a new owner can acquire it again.
	second, err := registry.Acquire(context.Background(), "owner-2", lease.Actual)
	if err != nil {
		t.Fatalf("re-Acquire after race: %v", err)
	}
	_ = second.Release()
}
