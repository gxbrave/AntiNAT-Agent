package reconcile

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// TestMatchingWAN1WithoutNodeKeyFailsClosed proves a durable matching WAN1
// cannot panic or reach the provider connection when the agent has lost its
// signing key. The arm remains retryable for a later key restoration.
func TestMatchingWAN1WithoutNodeKeyFailsClosed(t *testing.T) {
	e := newProbeTestEnv(t)
	arm := e.mustArm(t)
	wan1 := r13WAN1(t, arm, e.provider)
	e.mgr.key = nil

	conn := &r13StaticConn{
		reader: bytes.NewReader(wan1),
		remote: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)},
	}
	done := make(chan struct{})
	go func() {
		e.mgr.handleIngress(conn, arm.ExpectedSourceIP, time.Second, e.forward)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("matching WAN1 without node key did not fail closed")
	}
	conn.mu.Lock()
	writeCalled := conn.writeCalled
	written := conn.writes.Len()
	conn.mu.Unlock()
	if writeCalled || written != 0 {
		t.Fatalf("matching WAN1 without node key wrote ACK bytes: called=%v bytes=%d", writeCalled, written)
	}
	select {
	case msg := <-e.sent:
		t.Fatalf("matching WAN1 without node key emitted receipt: %+v", msg)
	default:
	}
	record, found, err := e.store.LoadArmedProbe(arm.ProbeID)
	if err != nil {
		t.Fatal(err)
	}
	if !found || record.Consumed {
		t.Fatalf("matching WAN1 without node key durable state = found %v consumed %v", found, record.Consumed)
	}
}
