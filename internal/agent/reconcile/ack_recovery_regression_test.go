package reconcile

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
)

// ackFaultConn injects a provider-side partial write after WAN1 has been
// accepted. The second instance represents a fresh retry connection.
type ackFaultConn struct {
	reader    *bytes.Reader
	writes    bytes.Buffer
	failAfter int
	failed    bool
}

func newACKFaultConn(frame []byte, failAfter int) *ackFaultConn {
	return &ackFaultConn{reader: bytes.NewReader(frame), failAfter: failAfter}
}

func (c *ackFaultConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
func (c *ackFaultConn) Write(p []byte) (int, error) {
	if c.failAfter >= 0 && !c.failed {
		c.failed = true
		n := c.failAfter
		if n > len(p) {
			n = len(p)
		}
		if n > 0 {
			_, _ = c.writes.Write(p[:n])
		}
		return n, errors.New("injected provider write failure")
	}
	return c.writes.Write(p)
}
func (c *ackFaultConn) Close() error                     { return nil }
func (c *ackFaultConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *ackFaultConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *ackFaultConn) SetDeadline(time.Time) error      { return nil }
func (c *ackFaultConn) SetReadDeadline(time.Time) error  { return nil }
func (c *ackFaultConn) SetWriteDeadline(time.Time) error { return nil }

func TestProbeIngressReplaysACKAfterPostConsumptionPartialWrite(t *testing.T) {
	e := newProbeTestEnv(t)
	arm := e.mustArm(t)
	challenge := [32]byte{1, 2, 3, 4}
	frame := protocol.ProviderFrame{
		ArmDigest: arm.Digest(), ProbeID: arm.ProbeID, ProviderID: arm.ProviderID,
		Activation: arm.Activation, Endpoint: arm.Endpoint, ExpiryOpaque: arm.ExpiryOpaque,
		Challenge: challenge,
	}
	frame.Signature = ed25519.Sign(e.provider, frame.SigningBytes())
	raw := wan1Bytes(frame)

	first := newACKFaultConn(raw, 7)
	e.mgr.handleIngress(first, [4]byte{127, 0, 0, 1}, time.Second, e.forward)
	rec, ok, err := e.store.LoadArmedProbe(arm.ProbeID)
	if err != nil || !ok {
		t.Fatalf("load consumed probe: ok=%v err=%v", ok, err)
	}
	if !rec.Consumed || rec.ACKSent || len(rec.ACK) == 0 {
		t.Fatalf("post-failure ACK state = consumed:%v ack_sent:%v ack_len:%d", rec.Consumed, rec.ACKSent, len(rec.ACK))
	}
	if rec.ChallengeHash != frame.ChallengeHash() {
		t.Fatal("durable ACK challenge hash does not match WAN1")
	}
	rct, err := protocol.ParseProbeReceipt(rec.Receipt, e.key.PublicKey())
	if err != nil {
		t.Fatalf("durable RCT1 invalid: %v", err)
	}
	if rct.ArmDigest != arm.Digest() || rct.ChallengeHash != frame.ChallengeHash() || rct.ProviderID != arm.ProviderID {
		t.Fatalf("durable RCT1 binding mismatch: %+v", rct)
	}
	if len(rec.ACK) != 4+32+32+64 {
		t.Fatalf("durable ACK length = %d, want %d", len(rec.ACK), 4+32+32+64)
	}
	if first.writes.Len() != 7 || !bytes.Equal(first.writes.Bytes(), rec.ACK[:7]) {
		t.Fatalf("partial write = %d bytes, want durable ACK prefix %d", first.writes.Len(), 7)
	}
	if got := probeReceiptOperationID(rec.Receipt); got != rec.ReceiptMessageID {
		t.Fatalf("receipt operation id = %q, durable id = %q", got, rec.ReceiptMessageID)
	}

	changed := frame
	changed.Challenge = [32]byte{9, 8, 7, 6}
	changed.Signature = ed25519.Sign(e.provider, changed.SigningBytes())
	changedConn := newACKFaultConn(wan1Bytes(changed), -1)
	e.mgr.handleIngress(changedConn, [4]byte{127, 0, 0, 1}, time.Second, e.forward)
	if changedConn.writes.Len() != 0 {
		t.Fatalf("changed challenge received ACK bytes: %d", changedConn.writes.Len())
	}
	recAfterChanged, ok, err := e.store.LoadArmedProbe(arm.ProbeID)
	if err != nil || !ok || recAfterChanged.ACKSent {
		t.Fatalf("changed challenge altered ACK state: ok=%v err=%v sent=%v", ok, err, recAfterChanged.ACKSent)
	}

	// Rehydrate from the durable store before retrying to exercise the crash
	// boundary rather than only the in-memory replay map.
	restarted := NewProbeManager(ProbeManagerOptions{
		Store: e.store, NodeKey: e.key, Clock: time.Now,
		SendControl: func(context.Context, string, []byte) error { return nil },
	})
	defer restarted.Close()
	second := newACKFaultConn(raw, -1)
	restarted.handleIngress(second, [4]byte{127, 0, 0, 1}, time.Second, e.forward)
	if got := second.writes.Bytes(); !bytes.Equal(got, rec.ACK) {
		t.Fatalf("replayed ACK bytes differ: got %d want %d", len(got), len(rec.ACK))
	}
	if _, err := protocol.ParseProbeACK(second.writes.Bytes(), e.key.PublicKey()); err != nil {
		t.Fatalf("replayed ACK invalid: %v", err)
	}
	rec, ok, err = e.store.LoadArmedProbe(arm.ProbeID)
	if err != nil || !ok || !rec.ACKSent {
		t.Fatalf("ACK state after retry = ok:%v err:%v sent:%v", ok, err, rec.ACKSent)
	}
	select {
	case <-e.sent:
		t.Fatal("ACK replay emitted a duplicate RCT1 receipt")
	default:
	}
}
