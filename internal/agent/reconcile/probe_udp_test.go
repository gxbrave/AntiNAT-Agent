package reconcile

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/netip"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
)

func signedUDPProviderFrame(t *testing.T, arm protocol.ProbeArm, provider ed25519.PrivateKey) []byte {
	t.Helper()
	var challenge [protocol.ProbeNonceLen]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		t.Fatal(err)
	}
	frame := protocol.ProviderFrame{
		ArmDigest: arm.Digest(), ProbeID: arm.ProbeID, ProviderID: arm.ProviderID,
		Activation: arm.Activation, Endpoint: arm.Endpoint,
		ExpiryOpaque: arm.ExpiryOpaque, Challenge: challenge,
	}
	frame.Signature = ed25519.Sign(provider, frame.SigningBytes())
	return append(frame.Canonical(), frame.Signature...)
}

func TestHandleUDPProbeReturnsSocketIndependentACKAndReceipt(t *testing.T) {
	e := newProbeTestEnv(t)
	arm := e.mustArm(t)
	raw := signedUDPProviderFrame(t, arm, e.provider)
	source := netip.MustParseAddrPort("127.0.0.1:41000")

	result := e.mgr.HandleUDPProbe(e.forward, source, raw)
	if !result.Matched {
		t.Fatal("valid UDP WAN1 was not matched")
	}
	if len(result.ACK) == 0 || len(result.ACK) > len(raw) {
		t.Fatalf("ACK length = %d, request length = %d", len(result.ACK), len(raw))
	}
	if len(result.Receipt) == 0 {
		t.Fatal("receipt is empty")
	}
	frame, err := protocol.ParseProviderFrame(raw)
	if err != nil {
		t.Fatal(err)
	}
	ack, err := protocol.ParseProbeACK(result.ACK, e.key.PublicKey())
	if err != nil || ack.ArmDigest != arm.Digest() || ack.ChallengeHash != frame.ChallengeHash() {
		t.Fatalf("ACK does not bind WAN1: ack=%+v err=%v", ack, err)
	}
	receipt, err := protocol.ParseProbeReceipt(result.Receipt, e.key.PublicKey())
	if err != nil || receipt.ArmDigest != arm.Digest() || receipt.ChallengeHash != frame.ChallengeHash() || receipt.ProviderID != arm.ProviderID {
		t.Fatalf("receipt does not bind WAN1: receipt=%+v err=%v", receipt, err)
	}
	rec, ok, err := e.store.LoadArmedProbe(arm.ProbeID)
	if err != nil || !ok || !rec.Consumed || len(rec.ACK) == 0 || len(rec.Receipt) == 0 {
		t.Fatalf("durable consume missing: rec=%+v ok=%v err=%v", rec, ok, err)
	}
	if rec.ACKSent || rec.ReceiptSent {
		t.Fatalf("handler claimed unsent network actions complete: ACKSent=%v ReceiptSent=%v", rec.ACKSent, rec.ReceiptSent)
	}
	if err := e.mgr.MarkUDPProbeACKSent(result.ProbeID); err != nil {
		t.Fatal(err)
	}
	if err := e.mgr.MarkUDPProbeReceiptSent(result.ProbeID); err != nil {
		t.Fatal(err)
	}
	rec, ok, err = e.store.LoadArmedProbe(arm.ProbeID)
	if err != nil || !ok || !rec.ACKSent || !rec.ReceiptSent {
		t.Fatalf("network action completion not durable: rec=%+v ok=%v err=%v", rec, ok, err)
	}
}

func TestHandleUDPProbeReplayCapacityDropsFailClosed(t *testing.T) {
	// A full-match WAN1 that cannot be processed because the replay fence is at
	// capacity must be consumed-without-ACK (Drop) and never forwarded to the
	// business backend.
	e := newProbeTestEnvOptions(t, func(o *ProbeManagerOptions) {
		o.MaxReplayEntries = 1
	})
	first := e.mustArm(t)
	rawFirst := signedUDPProviderFrame(t, first, e.provider)
	source := netip.MustParseAddrPort("127.0.0.1:41000")
	r1 := e.mgr.HandleUDPProbe(e.forward, source, rawFirst)
	if !r1.Matched || r1.Drop || len(r1.ACK) == 0 {
		t.Fatalf("first probe expected consumed with ACK, got %+v", r1)
	}

	second := e.mustArm(t)
	rawSecond := signedUDPProviderFrame(t, second, e.provider)
	r2 := e.mgr.HandleUDPProbe(e.forward, source, rawSecond)
	if !r2.Drop || r2.Matched || len(r2.ACK) != 0 || len(r2.Receipt) != 0 {
		t.Fatalf("second probe at capacity must drop without ACK/material, got %+v", r2)
	}
	// The dropped probe must not be durably consumed.
	rec, ok, err := e.store.LoadArmedProbe(second.ProbeID)
	if err != nil || !ok {
		t.Fatalf("dropped probe arm missing: rec=%+v ok=%v err=%v", rec, ok, err)
	}
	if rec.Consumed || len(rec.ACK) != 0 {
		t.Fatalf("dropped probe was persisted as consumed: rec=%+v", rec)
	}
}

func TestHandleUDPProbeQuarantineDropsProbeShapedFrames(t *testing.T) {
	// During a recovery error the manager is in quarantine, symmetric with the
	// TCP ProbeGate which rejects every connection in the same state. Any
	// well-formed WAN1-shaped datagram is consumed without ACK and never
	// forwarded to business; ordinary payloads unaffected.
	e := newProbeTestEnv(t)
	arm := e.mustArm(t)
	raw := signedUDPProviderFrame(t, arm, e.provider)
	source := netip.MustParseAddrPort("127.0.0.1:41000")

	e.mgr.mu.Lock()
	e.mgr.recoveryErr = ErrProbeRecoveryOverflow
	e.mgr.mu.Unlock()

	r1 := e.mgr.HandleUDPProbe(e.forward, source, raw)
	if !r1.Drop || r1.Matched || len(r1.ACK) != 0 || len(r1.Receipt) != 0 {
		t.Fatalf("quarantine must drop probe-shaped frame without ACK/material, got %+v", r1)
	}
	r2 := e.mgr.HandleUDPProbe(e.forward, source, []byte("hello"))
	if r2.Drop || r2.Matched {
		t.Fatalf("quarantine must leave ordinary payload to business, got %+v", r2)
	}
}

func TestHandleUDPProbeFullMatchTTLAndReplay(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*probeTestEnv, *protocol.ProbeArm, *[]byte, *netip.AddrPort)
	}{
		{name: "wrong source", mutate: func(_ *probeTestEnv, _ *protocol.ProbeArm, _ *[]byte, source *netip.AddrPort) {
			*source = netip.MustParseAddrPort("127.0.0.2:41000")
		}},
		{name: "wrong activation", mutate: func(e *probeTestEnv, arm *protocol.ProbeArm, raw *[]byte, _ *netip.AddrPort) {
			frame, _ := protocol.ParseProviderFrame(*raw)
			frame.Activation[0] ^= 0xff
			frame.Signature = ed25519.Sign(e.provider, frame.SigningBytes())
			*raw = append(frame.Canonical(), frame.Signature...)
		}},
		{name: "wrong endpoint", mutate: func(e *probeTestEnv, arm *protocol.ProbeArm, raw *[]byte, _ *netip.AddrPort) {
			frame, _ := protocol.ParseProviderFrame(*raw)
			frame.Endpoint = "198.51.100.7:8081"
			frame.Signature = ed25519.Sign(e.provider, frame.SigningBytes())
			*raw = append(frame.Canonical(), frame.Signature...)
		}},
		{name: "bad signature", mutate: func(_ *probeTestEnv, _ *protocol.ProbeArm, raw *[]byte, _ *netip.AddrPort) {
			(*raw)[len(*raw)-1] ^= 0xff
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newProbeTestEnv(t)
			arm := e.mustArm(t)
			raw := signedUDPProviderFrame(t, arm, e.provider)
			source := netip.MustParseAddrPort("127.0.0.1:41000")
			tt.mutate(e, &arm, &raw, &source)
			if got := e.mgr.HandleUDPProbe(e.forward, source, raw); got.Matched || len(got.ACK) != 0 || len(got.Receipt) != 0 {
				t.Fatalf("rejected input exposed result: %+v", got)
			}
		})
	}

	t.Run("expired", func(t *testing.T) {
		e := newProbeTestEnv(t)
		now := time.Now()
		e.mgr.clock = func() time.Time { return now }
		arm := e.mustArm(t)
		raw := signedUDPProviderFrame(t, arm, e.provider)
		now = now.Add(time.Duration(arm.TTLMS)*time.Millisecond + time.Nanosecond)
		if got := e.mgr.HandleUDPProbe(e.forward, netip.MustParseAddrPort("127.0.0.1:41000"), raw); got.Matched {
			t.Fatal("expired WAN1 matched")
		}
	})

	t.Run("replay", func(t *testing.T) {
		e := newProbeTestEnv(t)
		arm := e.mustArm(t)
		raw := signedUDPProviderFrame(t, arm, e.provider)
		source := netip.MustParseAddrPort("127.0.0.1:41000")
		first := e.mgr.HandleUDPProbe(e.forward, source, raw)
		if !first.Matched || len(first.ACK) == 0 {
			t.Fatal("first ingress failed")
		}
		if err := e.mgr.MarkUDPProbeACKSent(first.ProbeID); err != nil {
			t.Fatal(err)
		}
		replay := e.mgr.HandleUDPProbe(e.forward, source, raw)
		if !replay.Matched || len(replay.ACK) != 0 || len(replay.Receipt) != 0 {
			t.Fatalf("replay result = %+v, want consumed drop", replay)
		}
	})
}
