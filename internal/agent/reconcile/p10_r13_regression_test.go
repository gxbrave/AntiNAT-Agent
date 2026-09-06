package reconcile

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
)

type r13StaticConn struct {
	mu                sync.Mutex
	reader            *bytes.Reader
	remote            net.Addr
	readCalled        bool
	writeCalled       bool
	failReadDeadline  bool
	failWriteDeadline bool
	writes            bytes.Buffer
}

func (c *r13StaticConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	c.readCalled = true
	c.mu.Unlock()
	if c.reader == nil {
		return 0, io.EOF
	}
	return c.reader.Read(p)
}
func (c *r13StaticConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeCalled = true
	return c.writes.Write(p)
}
func (c *r13StaticConn) Close() error                { return nil }
func (c *r13StaticConn) LocalAddr() net.Addr         { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (c *r13StaticConn) RemoteAddr() net.Addr        { return c.remote }
func (c *r13StaticConn) SetDeadline(time.Time) error { return nil }
func (c *r13StaticConn) SetReadDeadline(time.Time) error {
	if c.failReadDeadline {
		return errors.New("read deadline install failed")
	}
	return nil
}
func (c *r13StaticConn) SetWriteDeadline(time.Time) error {
	if c.failWriteDeadline {
		return errors.New("write deadline install failed")
	}
	return nil
}

type r13OneConnListener struct {
	conn net.Conn
	once sync.Once
}

func (l *r13OneConnListener) Accept() (net.Conn, error) {
	var conn net.Conn
	l.once.Do(func() { conn = l.conn })
	if conn != nil {
		return conn, nil
	}
	return nil, net.ErrClosed
}
func (l *r13OneConnListener) Close() error   { return nil }
func (l *r13OneConnListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

func r13WAN1(t *testing.T, arm protocol.ProbeArm, provider ed25519.PrivateKey) []byte {
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
	return wan1Bytes(frame)
}

func r13SecondArm(t *testing.T, e *probeTestEnv) (protocol.ProbeArm, ed25519.PrivateKey) {
	t.Helper()
	_, provider, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	arm := e.arm
	if arm.ProbeID == ([16]byte{}) {
		arm = e.mustArm(t)
	}
	if _, err := rand.Read(arm.ProbeID[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(arm.ProviderID[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(arm.ExpiryOpaque[:]); err != nil {
		t.Fatal(err)
	}
	arm.ProviderPublicKey = [32]byte(provider.Public().(ed25519.PublicKey))
	if _, err := e.mgr.HandleProbeArm(context.Background(), arm.Canonical(), e.forward); err != nil {
		t.Fatalf("second arm: %v", err)
	}
	return arm, provider
}

func consumeR13Probe(t *testing.T, e *probeTestEnv, arm protocol.ProbeArm, provider ed25519.PrivateKey) {
	t.Helper()
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		e.mgr.handleIngress(server, arm.ExpectedSourceIP, time.Second, e.forward)
		close(done)
	}()
	go func() { _, _ = client.Write(r13WAN1(t, arm, provider)) }()
	ack := make([]byte, 4+32+32+64)
	if _, err := readFull(client, ack); err != nil {
		t.Fatalf("consume probe ACK: %v", err)
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
}

// R13 RED: if durable active/replay fences exceed bounded in-memory recovery,
// ProbeGate must quarantine the listener. A skipped provider source cannot be
// returned to the business path merely because its exact fence did not fit.
func TestR13RestartOverflowQuarantinesProbeGate(t *testing.T) {
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Unix(70_000, 0)
	for i := byte(1); i <= 2; i++ {
		arm := protocol.ProbeArm{Endpoint: "198.51.100.7:8080", TTLMS: 60_000}
		arm.ProbeID[15] = i
		arm.ExpectedSourceIP = [4]byte{198, 51, 100, i}
		if err := st.SaveArmedProbeForForward(arm, "forward-r13", now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	for i := byte(3); i <= 4; i++ {
		arm := protocol.ProbeArm{Endpoint: "198.51.100.7:8080", TTLMS: 60_000}
		arm.ProbeID[15] = i
		arm.ExpectedSourceIP = [4]byte{203, 0, 113, i}
		if err := st.SaveArmedProbeForForward(arm, "forward-r13", now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if err := st.MarkArmedProbeConsumedWithReceipt(arm.ProbeID, []byte{i}, "receipt-"+hex.EncodeToString([]byte{i}), now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	manager := NewProbeManager(ProbeManagerOptions{
		Store: st, Clock: func() time.Time { return now }, MaxActiveOperations: 1, MaxReplayEntries: 1,
	})
	businessCandidate := &r13StaticConn{remote: &net.TCPAddr{IP: net.IPv4(192, 0, 2, 99), Port: 1234}}
	gate := NewProbeGate(&r13OneConnListener{conn: businessCandidate}, manager, ProbeGateOptions{ForwardID: "forward-r13", ReadTimeout: time.Second})
	got, err := gate.Accept()
	if err == nil || got != nil {
		if got != nil {
			_ = got.Close()
		}
		t.Fatalf("overflow candidate reached business path: conn=%v err=%v", got, err)
	}
}

func TestR13RestartUnknownConsumedDeadlineQuarantinesProbeGate(t *testing.T) {
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Unix(71_000, 0)
	arm := protocol.ProbeArm{Endpoint: "198.51.100.7:8080", TTLMS: 60_000}
	arm.ProbeID[15] = 9
	arm.ExpectedSourceIP = [4]byte{198, 51, 100, 9}
	if err := st.SaveArmedProbeForForward(arm, "forward-r13", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkArmedProbeConsumedWithReceipt(arm.ProbeID, []byte("receipt"), "receipt-r13", time.Time{}); err != nil {
		t.Fatal(err)
	}
	manager := NewProbeManager(ProbeManagerOptions{Store: st, Clock: func() time.Time { return now }, MaxReplayEntries: 1, MaxActiveOperations: 1})
	businessCandidate := &r13StaticConn{remote: &net.TCPAddr{IP: net.IPv4(198, 51, 100, 9), Port: 1234}}
	gate := NewProbeGate(&r13OneConnListener{conn: businessCandidate}, manager, ProbeGateOptions{ForwardID: "forward-r13", ReadTimeout: time.Second})
	got, err := gate.Accept()
	if err == nil || got != nil {
		if got != nil {
			_ = got.Close()
		}
		t.Fatalf("unknown-deadline consumed fence reached business path: conn=%v err=%v", got, err)
	}
}

// R13 RED: a full live replay cache cannot evict an unexpired fence to admit a
// newer proof. The new ingress fails closed before durable consumption/ACK.
func TestR13LiveReplayCapacityNeverEvictsFence(t *testing.T) {
	e := newProbeTestEnv(t)
	e.mgr.maxReplay = 1
	first := e.mustArm(t)
	e.arm = first
	consumeR13Probe(t, e, first, e.provider)
	second, secondProvider := r13SecondArm(t, e)

	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		e.mgr.handleIngress(server, second.ExpectedSourceIP, time.Second, e.forward)
		close(done)
	}()
	go func() { _, _ = client.Write(r13WAN1(t, second, secondProvider)) }()
	_ = client.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	ack := make([]byte, 4+32+32+64)
	if _, err := readFull(client, ack); err == nil {
		t.Fatal("new probe was ACKed after replay capacity was exhausted")
	}
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("capacity-rejected ingress did not finish")
	}
	e.mgr.mu.Lock()
	_, firstFenced := e.mgr.replay[first.ProbeID]
	_, secondActive := e.mgr.ops[second.ProbeID]
	e.mgr.mu.Unlock()
	if !firstFenced || !secondActive {
		t.Fatalf("capacity handling evicted/consumed wrong fence: firstFenced=%v secondActive=%v", firstFenced, secondActive)
	}
	record, found, err := e.store.LoadArmedProbe(second.ProbeID)
	if err != nil || !found || record.Consumed {
		t.Fatalf("capacity-rejected probe durable state = found %v consumed %v err %v", found, record.Consumed, err)
	}
}

// R13 RED: SetReadDeadline failure is itself a hard ingress failure. No byte
// may be read from an unbounded provider connection.
func TestR13ProbeIngressReadDeadlineFailureFailsClosed(t *testing.T) {
	e := newProbeTestEnv(t)
	arm := e.mustArm(t)
	conn := &r13StaticConn{
		reader: bytes.NewReader(r13WAN1(t, arm, e.provider)), remote: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)},
		failReadDeadline: true,
	}
	e.mgr.handleIngress(conn, arm.ExpectedSourceIP, time.Second, e.forward)
	if conn.readCalled || conn.writeCalled {
		t.Fatalf("read-deadline failure continued ingress: read=%v write=%v", conn.readCalled, conn.writeCalled)
	}
}

// R13 RED: SetWriteDeadline failure prevents ACK and receipt publication; an
// unbounded write can never be attempted after the operation is consumed.
func TestR13ProbeIngressWriteDeadlineFailureFailsClosed(t *testing.T) {
	e := newProbeTestEnv(t)
	arm := e.mustArm(t)
	conn := &r13StaticConn{
		reader: bytes.NewReader(r13WAN1(t, arm, e.provider)), remote: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)},
		failWriteDeadline: true,
	}
	e.mgr.handleIngress(conn, arm.ExpectedSourceIP, time.Second, e.forward)
	if conn.writeCalled {
		t.Fatal("write attempted after SetWriteDeadline failure")
	}
	select {
	case msg := <-e.sent:
		t.Fatalf("receipt emitted after ACK deadline failure: %+v", msg)
	default:
	}
}
