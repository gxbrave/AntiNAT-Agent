package reconcile

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
	"github.com/gxbrave/AntiNAT-Agent/internal/security"
)

// probeTestEnv assembles the agent probe manager over a real localstate
// store with a test node key.
type probeTestEnv struct {
	t        *testing.T
	store    *localstate.Store
	key      *security.NodeKey
	mgr      *ProbeManager
	sent     chan probeSend
	forward  string
	arm      protocol.ProbeArm
	provider ed25519.PrivateKey
}

type probeSend struct {
	messageType string
	payload     []byte
}

func newProbeTestEnv(t *testing.T) *probeTestEnv {
	return newProbeTestEnvOptionsWithPublicPort(t, nil, 0)
}

// newProbeTestEnvOptions builds a probe environment whose ProbeManagerOptions
// can be mutated (e.g. capacity bounds) before the manager is constructed.
func newProbeTestEnvOptions(t *testing.T, mutate func(*ProbeManagerOptions)) *probeTestEnv {
	return newProbeTestEnvOptionsWithPublicPort(t, mutate, 0)
}

func newProbeTestEnvWithPublicPort(t *testing.T, publicPort uint16) *probeTestEnv {
	return newProbeTestEnvOptionsWithPublicPort(t, nil, publicPort)
}

func newProbeTestEnvOptionsWithPublicPort(t *testing.T, mutate func(*ProbeManagerOptions), publicPort uint16) *probeTestEnv {
	t.Helper()
	st, err := localstate.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	key, err := security.LoadOrCreateNodeKey(t.TempDir(), 1)
	if err != nil {
		t.Fatalf("node key: %v", err)
	}
	sent := make(chan probeSend, 16)
	opts := ProbeManagerOptions{
		Store:   st,
		NodeKey: key,
		Clock:   time.Now,
		SendControl: func(ctx context.Context, messageType string, payload []byte) error {
			sent <- probeSend{messageType: messageType, payload: payload}
			return nil
		},
	}
	if mutate != nil {
		mutate(&opts)
	}
	mgr := NewProbeManager(opts)
	// An applied forward the arm must match.
	applied := protocol.AppliedForwardState{
		ForwardID:       "fwd-1",
		SpecRevision:    1,
		DesiredRevision: 1,
		ActualBindHost:  "198.51.100.7",
		ActualBindPort:  8080,
		PublicPort:      publicPort,
		Strategy:        "direct-v4",
		LayerVersion:    1,
		AppliedAtUnix:   time.Now().Unix(),
	}
	if _, err := st.CommitDesired(protocol.DesiredState{
		NodeID: "node-1",
		Forwards: []protocol.ForwardSpec{{
			ForwardID: "fwd-1", Protocol: protocol.ProtocolTCP,
			Target: "10.0.0.5:9000", Strategy: protocol.StrategyDirectV4,
			DesiredRevision: 1, Presence: protocol.PresencePresent,
		}},
	}, []localstate.ForwardApply{{ForwardID: "fwd-1", Outcome: localstate.ApplyApplied, Applied: &applied}}); err != nil {
		t.Fatalf("commit applied: %v", err)
	}
	return &probeTestEnv{t: t, store: st, key: key, mgr: mgr, sent: sent, forward: "fwd-1"}
}

// mustArm builds a valid arm for the applied forward and arms it.
func (e *probeTestEnv) mustArm(t *testing.T) protocol.ProbeArm {
	t.Helper()
	_, providerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	e.provider = providerPriv
	var probeID, providerID, activation [16]byte
	rand.Read(probeID[:])
	rand.Read(providerID[:])
	activation = activationFor("fwd-1", 1)
	var opaque [16]byte
	rand.Read(opaque[:])
	arm := protocol.ProbeArm{
		ProbeID:           probeID,
		ProviderID:        providerID,
		ProviderPublicKey: [32]byte(providerPriv.Public().(ed25519.PublicKey)),
		ExpectedSourceIP:  [4]byte{127, 0, 0, 1},
		Activation:        activation,
		Endpoint:          "198.51.100.7:8080",
		TTLMS:             30000,
		ExpiryOpaque:      opaque,
	}
	if err := arm.Validate(); err != nil {
		t.Fatalf("arm validate: %v", err)
	}
	rdy, err := e.mgr.HandleProbeArm(context.Background(), arm.Canonical(), "fwd-1")
	if err != nil {
		t.Fatalf("arm: %v", err)
	}
	// RDY1 must verify against the node key and digest.
	digest := arm.Digest()
	if _, err := protocol.ParseProbeArmed(rdy, e.key.PublicKey(), digest); err != nil {
		t.Fatalf("RDY1 does not verify: %v", err)
	}
	// The arm must be durably persisted.
	if _, ok, err := e.store.LoadArmedProbe(arm.ProbeID); err != nil || !ok {
		t.Fatalf("armed probe not durable (ok=%v err=%v)", ok, err)
	}
	return arm
}

// activationFor derives the deterministic activation id (shared helper).
func activationFor(forwardID string, specRevision uint64) [16]byte {
	return protocol.ActivationID(forwardID, specRevision)
}

// TestHandleProbeArmRejectsUnmatchedActivation covers Story 2 RED: an arm
// whose activation does not match any applied forward fails closed, and the
// arm must never be persisted.
func TestTerminalMarkerRejectsNewProbeArm(t *testing.T) {
	e := newProbeTestEnv(t)
	e.mgr.marker = localstate.MarkerDecommissioned
	arm := sampleProbeArm()
	arm.Activation = activationFor("fwd-1", 1)
	if _, err := e.mgr.HandleProbeArm(context.Background(), arm.Canonical(), e.forward); !errors.Is(err, ErrProbeArmRejected) {
		t.Fatalf("terminal-marker arm error = %v, want ErrProbeArmRejected", err)
	}
	if _, ok, _ := e.store.LoadArmedProbe(arm.ProbeID); ok {
		t.Fatal("terminal-marker arm was persisted")
	}
}

func TestHandleProbeArmRejectsUnmatchedActivation(t *testing.T) {
	e := newProbeTestEnv(t)
	arm := sampleProbeArm()
	// Wrong activation: does not match fwd-1 @ revision 1.
	arm.Activation = [16]byte{1, 2, 3}
	if _, err := e.mgr.HandleProbeArm(context.Background(), arm.Canonical(), "fwd-1"); err == nil {
		t.Fatal("arm with wrong activation accepted")
	}
	if _, ok, _ := e.store.LoadArmedProbe(arm.ProbeID); ok {
		t.Fatal("unmatched arm was persisted")
	}
}

// TestHandleProbeArmRejectsEndpointMismatch covers Story 2 RED: an arm whose
// endpoint does not equal the actual bind tuple fails closed.
func TestHandleProbeArmRejectsEndpointMismatch(t *testing.T) {
	e := newProbeTestEnv(t)
	arm := sampleProbeArm()
	arm.Activation = activationFor("fwd-1", 1)
	arm.Endpoint = "198.51.100.7:9999" // does not match bind port 8080
	if _, err := e.mgr.HandleProbeArm(context.Background(), arm.Canonical(), "fwd-1"); err == nil {
		t.Fatal("arm with wrong endpoint accepted")
	}
}

func TestHandleProbeArmAcceptsPublicCandidateForPrivateBind(t *testing.T) {
	e := newProbeTestEnvWithPublicPort(t, 9304)

	arm := sampleProbeArm()
	arm.Activation = activationFor(e.forward, 1)
	arm.Endpoint = "198.51.100.9:9304"
	if _, err := e.mgr.HandleProbeArm(context.Background(), arm.Canonical(), e.forward); err != nil {
		t.Fatalf("public-candidate arm rejected: %v", err)
	}
}

func TestHandleProbeArmRejectsMismatchedPublicCandidatePort(t *testing.T) {
	e := newProbeTestEnvWithPublicPort(t, 9304)

	arm := sampleProbeArm()
	arm.Activation = activationFor(e.forward, 1)
	arm.Endpoint = "198.51.100.9:9305"
	if _, err := e.mgr.HandleProbeArm(context.Background(), arm.Canonical(), e.forward); err == nil {
		t.Fatal("arm with mismatched public candidate port accepted")
	}
}

// TestProbeGateAcceptsAndAcks covers the WAN1 ingress gate: a provider frame
// from the expected source within TTL is accepted on the listener, the ACK1
// is returned on the same connection, and the RCT1 receipt is sent over the
// control channel; the probe connection is never handed to business.
func TestProbeGateAcceptsAndAcks(t *testing.T) {
	e := newProbeTestEnv(t)
	arm := e.mustArm(t)

	// A listener wrapped by the gate.
	inner, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer inner.Close()
	gate := NewProbeGate(inner, e.mgr, ProbeGateOptions{
		ForwardID:   "fwd-1",
		ReadTimeout: 2 * time.Second,
	})

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := gate.Accept()
		if err != nil {
			return
		}
		accepted <- c
	}()

	// Provider dials from the expected source (loopback).
	conn, err := net.Dial("tcp4", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Build and send WAN1.
	challenge := [32]byte{}
	rand.Read(challenge[:])
	frame := protocol.ProviderFrame{
		ArmDigest:    arm.Digest(),
		ProbeID:      arm.ProbeID,
		ProviderID:   arm.ProviderID,
		Activation:   arm.Activation,
		Endpoint:     arm.Endpoint,
		ExpiryOpaque: arm.ExpiryOpaque,
		Challenge:    challenge,
	}
	frame.Signature = ed25519.Sign(e.provider, frame.SigningBytes())
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(wan1Bytes(frame)); err != nil {
		t.Fatalf("write WAN1: %v", err)
	}

	// The ACK1 must come back on the same connection.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4+32+32+64)
	if _, err := readFull(conn, buf); err != nil {
		t.Fatalf("read ACK1: %v", err)
	}
	ack, err := protocol.ParseProbeACK(buf, e.key.PublicKey())
	if err != nil {
		t.Fatalf("parse ACK1: %v", err)
	}
	if ack.ArmDigest != arm.Digest() || ack.ChallengeHash != frame.ChallengeHash() {
		t.Fatal("ACK1 digest/challenge mismatch")
	}

	// The RCT1 receipt must be sent over the control channel.
	select {
	case s := <-e.sent:
		if s.messageType != "probe_ingress_receipt" {
			t.Fatalf("control message type = %q", s.messageType)
		}
		if _, err := protocol.ParseProbeReceipt(s.payload, e.key.PublicKey()); err != nil {
			t.Fatalf("RCT1 receipt invalid: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no probe_ingress_receipt sent")
	}
	consumed, ok, err := e.store.LoadArmedProbe(arm.ProbeID)
	if err != nil || !ok || !consumed.Consumed {
		t.Fatalf("consumed probe not durably retained: ok=%v err=%v record=%+v", ok, err, consumed)
	}

	// The probe connection is consumed, NOT handed to business.
	select {
	case c := <-accepted:
		c.Close()
		t.Fatal("probe connection leaked to business accept")
	case <-time.After(300 * time.Millisecond):
		// expected: the gate consumed the connection and keeps accepting
	}
}

// TestProbeGateWrongSourcePassesToBusiness covers the anti-oracle rule: a
// connection from a NON-provider source is never sniffed — it goes straight
// to the business accept path.
func TestProbeGateWrongSourcePassesToBusiness(t *testing.T) {
	e := newProbeTestEnv(t)
	e.mustArm(t) // expected source is 127.0.0.1

	inner, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer inner.Close()
	gate := NewProbeGate(inner, e.mgr, ProbeGateOptions{ForwardID: "fwd-1", ReadTimeout: 2 * time.Second})

	done := make(chan net.Conn, 1)
	go func() {
		c, err := gate.Accept()
		if err != nil {
			return
		}
		done <- c
	}()

	// Dial from a DIFFERENT loopback address (127.0.0.2 on lo) so the remote
	// source is not the armed provider source.
	dialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2)}}
	conn, err := dialer.Dial("tcp4", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// The connection must arrive at the business accept unchanged.
	select {
	case c := <-done:
		c.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("business connection did not pass through the gate")
	}
	// No receipt must have been sent.
	select {
	case s := <-e.sent:
		t.Fatalf("unexpected control message for business conn: %+v", s)
	default:
	}
}

// TestProbeIngressDemultiplexesSameSourceByFrame verifies that two active
// operations sharing one source IP are selected by authenticated frame fields,
// not by map iteration order.
func TestProbeIngressDemultiplexesSameSourceByFrame(t *testing.T) {
	e := newProbeTestEnv(t)
	first := e.mustArm(t)

	_, secondProvider, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	second := first
	rand.Read(second.ProbeID[:])
	rand.Read(second.ProviderID[:])
	second.ProviderPublicKey = [32]byte(secondProvider.Public().(ed25519.PublicKey))
	rand.Read(second.ExpiryOpaque[:])
	if _, err := e.mgr.HandleProbeArm(context.Background(), second.Canonical(), e.forward); err != nil {
		t.Fatalf("second arm: %v", err)
	}

	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		e.mgr.handleIngress(server, [4]byte{127, 0, 0, 1}, 2*time.Second)
		close(done)
	}()

	challenge := [32]byte{}
	rand.Read(challenge[:])
	frame := protocol.ProviderFrame{
		ArmDigest:    second.Digest(),
		ProbeID:      second.ProbeID,
		ProviderID:   second.ProviderID,
		Activation:   second.Activation,
		Endpoint:     second.Endpoint,
		ExpiryOpaque: second.ExpiryOpaque,
		Challenge:    challenge,
	}
	frame.Signature = ed25519.Sign(secondProvider, frame.SigningBytes())
	go func() { _, _ = client.Write(wan1Bytes(frame)) }()
	ackBytes := make([]byte, 4+32+32+64)
	if _, err := readFull(client, ackBytes); err != nil {
		t.Fatalf("same-source frame was not acknowledged: %v", err)
	}
	if _, err := protocol.ParseProbeACK(ackBytes, e.key.PublicKey()); err != nil {
		t.Fatalf("same-source ACK invalid: %v", err)
	}
	client.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("same-source ingress handler did not finish")
	}
	if rec, ok, err := e.store.LoadArmedProbe(second.ProbeID); err != nil || !ok || !rec.Consumed {
		t.Fatalf("second operation was not consumed: ok=%v err=%v rec=%+v", ok, err, rec)
	}
	if rec, ok, err := e.store.LoadArmedProbe(first.ProbeID); err != nil || !ok || rec.Consumed {
		t.Fatalf("first operation was consumed by second frame: ok=%v err=%v rec=%+v", ok, err, rec)
	}
	if _, err := e.mgr.HandleProbeArm(context.Background(), second.Canonical(), e.forward); !errors.Is(err, ErrProbeArmRejected) {
		t.Fatalf("consumed operation was rearmed: %v", err)
	}
}

// TestConsumedProbeSurvivesArmDeadlineUntilReceiptDeadline verifies that the
// in-memory expiry pass cannot delete a consumed receipt tombstone at the arm
// deadline. The tombstone remains available for reconnect retries/acknowledgement.
func TestConsumedProbeSurvivesArmDeadlineUntilReceiptDeadline(t *testing.T) {
	e := newProbeTestEnv(t)
	arm := e.mustArm(t)
	receipt := []byte("receipt-retention")
	receiptDeadline := time.Now().Add(time.Hour)
	if err := e.store.MarkArmedProbeConsumedWithReceipt(arm.ProbeID, receipt, probeReceiptOperationID(receipt), receiptDeadline); err != nil {
		t.Fatalf("mark consumed: %v", err)
	}
	e.mgr.mu.Lock()
	e.mgr.sweep(time.Now().Add(2 * time.Hour))
	e.mgr.mu.Unlock()
	if _, ok, err := e.store.LoadArmedProbe(arm.ProbeID); err != nil || !ok {
		t.Fatalf("consumed tombstone removed at arm deadline: ok=%v err=%v", ok, err)
	}
}

// TestRetryPendingReceiptsMarksDurableReceiptSent covers restart/disconnect
// recovery: a consumed row with an unsent receipt is retried and only then
// marked sent.
func TestRetryPendingReceiptsMarksDurableReceiptSent(t *testing.T) {
	e := newProbeTestEnv(t)
	arm := e.mustArm(t)
	receipt := []byte("durable-receipt")
	if err := e.store.MarkArmedProbeConsumed(arm.ProbeID, receipt); err != nil {
		t.Fatalf("mark consumed: %v", err)
	}
	calls := 0
	e.mgr.send = func(ctx context.Context, messageType string, payload []byte) error {
		calls++
		if messageType != "probe_ingress_receipt" || string(payload) != string(receipt) {
			t.Fatalf("unexpected retry payload: %q %q", messageType, payload)
		}
		return nil
	}
	if err := e.mgr.RetryPendingReceipts(context.Background()); err != nil {
		t.Fatalf("retry pending receipt: %v", err)
	}
	if calls != 1 {
		t.Fatalf("retry calls = %d, want 1", calls)
	}
	rec, ok, err := e.store.LoadArmedProbe(arm.ProbeID)
	if err != nil || !ok || !rec.Consumed || !rec.ReceiptSent {
		t.Fatalf("receipt state after retry: ok=%v err=%v rec=%+v", ok, err, rec)
	}
}

// TestRetryPendingReceiptsScansAllRetainedRows verifies bounded paging does not
// strand a receipt tombstone after the first active-operation batch.
func TestRetryPendingReceiptsScansAllRetainedRows(t *testing.T) {
	e := newProbeTestEnv(t)
	const count = 257
	for i := 0; i < count; i++ {
		arm := sampleProbeArm()
		arm.ProbeID = [16]byte{}
		arm.ProbeID[0] = byte(i >> 8)
		arm.ProbeID[1] = byte(i)
		if err := e.store.SaveArmedProbe(arm, time.Now().Add(time.Hour)); err != nil {
			t.Fatalf("save probe %d: %v", i, err)
		}
		id := "retry-" + string(rune(i))
		if err := e.store.MarkArmedProbeConsumedWithReceipt(arm.ProbeID, []byte(id), id, time.Now().Add(time.Hour)); err != nil {
			t.Fatalf("consume probe %d: %v", i, err)
		}
	}
	calls := 0
	e.mgr.send = func(ctx context.Context, messageType string, payload []byte) error {
		calls++
		return nil
	}
	if err := e.mgr.RetryPendingReceipts(context.Background()); err != nil {
		t.Fatalf("retry pending receipts: %v", err)
	}
	if calls != count {
		t.Fatalf("retry calls = %d, want %d", calls, count)
	}
}

// A successful socket write is not the Controller's semantic acknowledgement.
// A consumed tombstone must therefore be retried after reconnect even when the
// previous process marked the transport send as completed.
func TestRetryPendingReceiptsResendsAfterTransportWriteUntilSemanticAck(t *testing.T) {
	e := newProbeTestEnv(t)
	arm := e.mustArm(t)
	receipt := []byte("receipt-awaiting-controller-ack")
	operationID := probeReceiptOperationID(receipt)
	deadline := time.Now().Add(time.Hour)
	if err := e.store.MarkArmedProbeConsumedWithReceipt(arm.ProbeID, receipt, operationID, deadline); err != nil {
		t.Fatalf("mark consumed: %v", err)
	}
	if err := e.store.MarkArmedProbeReceiptSent(arm.ProbeID); err != nil {
		t.Fatalf("mark transport send complete: %v", err)
	}
	calls := 0
	e.mgr.send = func(ctx context.Context, messageType string, payload []byte) error {
		calls++
		if messageType != "probe_ingress_receipt" || string(payload) != string(receipt) {
			t.Fatalf("unexpected retry payload: %q %q", messageType, payload)
		}
		return nil
	}
	if err := e.mgr.RetryPendingReceipts(context.Background()); err != nil {
		t.Fatalf("retry pending receipt: %v", err)
	}
	if calls != 1 {
		t.Fatalf("retry calls = %d, want 1", calls)
	}
}

// The Controller's semantic receipt operation id is the digest of the exact
// RCT1 payload. The transport envelope message id is domain-separated from
// that digest; acknowledging the semantic id marks delivery but retains the
// durable replay fence until its explicit fallback deadline.
func TestControllerReceiptAckRetainsProbeFence(t *testing.T) {
	e := newProbeTestEnv(t)
	arm := e.mustArm(t)
	receipt := []byte("durable-rct1-payload")
	operationID := probeReceiptOperationID(receipt)
	operationDigest := sha256.Sum256(receipt)
	envelopeMessage := security.MessageID(operationID, "probe_ingress_receipt")
	envelopeMessageID := hex.EncodeToString(envelopeMessage[:])
	if operationID == envelopeMessageID || operationID != hex.EncodeToString(operationDigest[:]) {
		t.Fatal("test fixture must distinguish semantic operation id from envelope message id")
	}
	if err := e.store.MarkArmedProbeConsumedWithReceipt(arm.ProbeID, receipt, envelopeMessageID, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("mark consumed: %v", err)
	}
	if err := e.mgr.AcknowledgeReceipt(operationID); err != nil {
		t.Fatalf("acknowledge controller receipt: %v", err)
	}
	if rec, ok, err := e.store.LoadArmedProbe(arm.ProbeID); err != nil || !ok || !rec.Consumed {
		t.Fatalf("probe replay fence was deleted after semantic ack: ok=%v err=%v rec=%+v", ok, err, rec)
	}
}

// TestProbeGateRejectsReplay covers Story 2 RED: a consumed probe id within
// the replay window is rejected with a generic drop (no ACK).
func TestProbeGateRejectsReplay(t *testing.T) {
	e := newProbeTestEnv(t)
	arm := e.mustArm(t)

	inner, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer inner.Close()
	gate := NewProbeGate(inner, e.mgr, ProbeGateOptions{ForwardID: "fwd-1", ReadTimeout: 2 * time.Second})

	go gate.Accept() // drain

	// First ingress succeeds.
	conn, err := net.Dial("tcp4", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	challenge := [32]byte{}
	rand.Read(challenge[:])
	frame := protocol.ProviderFrame{
		ArmDigest: arm.Digest(), ProbeID: arm.ProbeID, ProviderID: arm.ProviderID,
		Activation: arm.Activation, Endpoint: arm.Endpoint,
		ExpiryOpaque: arm.ExpiryOpaque, Challenge: challenge,
	}
	frame.Signature = ed25519.Sign(e.provider, frame.SigningBytes())
	conn.Write(wan1Bytes(frame))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4+32+32+64)
	if _, err := readFull(conn, buf); err != nil {
		t.Fatalf("first ingress ACK: %v", err)
	}
	conn.Close()
	select {
	case <-e.sent:
	case <-time.After(3 * time.Second):
		t.Fatal("no receipt for first ingress")
	}

	// Replay the same frame: must be dropped without ACK.
	conn2, err := net.Dial("tcp4", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()
	conn2.Write(frame.Canonical())
	conn2.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := readFull(conn2, buf); err == nil {
		t.Fatal("replay got a response (ACK leak)")
	}
}

// helpers

// wan1Bytes renders the full WAN1 wire frame (canonical + signature).
func wan1Bytes(frame protocol.ProviderFrame) []byte {
	return append(frame.Canonical(), frame.Signature...)
}

func sampleProbeArm() protocol.ProbeArm {
	var arm protocol.ProbeArm
	rand.Read(arm.ProbeID[:])
	rand.Read(arm.ProviderID[:])
	rand.Read(arm.ProviderPublicKey[:])
	copy(arm.Activation[:], "fwd-1")
	arm.Endpoint = "198.51.100.7:8080"
	arm.TTLMS = 30000
	rand.Read(arm.ExpiryOpaque[:])
	return arm
}
