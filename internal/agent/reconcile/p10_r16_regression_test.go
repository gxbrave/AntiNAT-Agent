package reconcile

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
)

// R16 RED: a consumed live source fence must use the same deadline as the
// durable receipt tombstone. The previous implementation expired the in-memory
// fence at ingress+replay-window, leaving a live routing gap before the arm
// deadline+replay-window boundary.
func TestR16LiveConsumedSourceFenceUsesDurableReceiptDeadline(t *testing.T) {
	e := newProbeTestEnv(t)
	arm := e.mustArm(t)
	record, found, err := e.store.LoadArmedProbe(arm.ProbeID)
	if err != nil || !found {
		t.Fatalf("load armed probe: found=%v err=%v", found, err)
	}
	fakeNow := record.ArmedAt.Add(time.Second)
	e.mgr.clock = func() time.Time { return fakeNow }

	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		e.mgr.handleIngress(server, arm.ExpectedSourceIP, time.Second, e.forward)
		close(done)
	}()
	go func() { _, _ = client.Write(r16WAN1(t, arm, e.provider)) }()
	ack := make([]byte, 4+32+32+64)
	if _, err := readFull(client, ack); err != nil {
		t.Fatalf("read ACK1: %v", err)
	}
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("probe ingress did not finish")
	}
	select {
	case <-e.sent:
	case <-time.After(time.Second):
		t.Fatal("probe receipt was not emitted")
	}

	record, found, err = e.store.LoadArmedProbe(arm.ProbeID)
	if err != nil || !found || !record.Consumed {
		t.Fatalf("consumed durable probe: found=%v consumed=%v err=%v", found, record.Consumed, err)
	}
	e.mgr.mu.Lock()
	liveDeadline, liveFound := e.mgr.replay[arm.ProbeID]
	e.mgr.mu.Unlock()
	if !liveFound {
		t.Fatal("live replay fence was not installed")
	}
	if !liveDeadline.Equal(record.ReceiptDeadline) {
		t.Fatalf("live deadline = %v, durable deadline = %v", liveDeadline, record.ReceiptDeadline)
	}

	e.mgr.clock = func() time.Time { return record.ReceiptDeadline.Add(-time.Nanosecond) }
	if !e.mgr.hasArmedBySource(arm.ExpectedSourceIP, e.forward) {
		t.Fatal("source fence expired before durable ReceiptDeadline")
	}
	e.mgr.clock = func() time.Time { return record.ReceiptDeadline }
	if e.mgr.hasArmedBySource(arm.ExpectedSourceIP, e.forward) {
		t.Fatal("source fence survived durable ReceiptDeadline")
	}
}

func r16WAN1(t *testing.T, arm protocol.ProbeArm, provider ed25519.PrivateKey) []byte {
	t.Helper()
	var challenge [32]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		t.Fatal(err)
	}
	frame := protocol.ProviderFrame{
		ArmDigest: arm.Digest(), ProbeID: arm.ProbeID, ProviderID: arm.ProviderID,
		Activation: arm.Activation, Endpoint: arm.Endpoint, ExpiryOpaque: arm.ExpiryOpaque,
		Challenge: challenge,
	}
	frame.Signature = ed25519.Sign(provider, frame.SigningBytes())
	return append(append([]byte(nil), frame.Canonical()...), frame.Signature...)
}
