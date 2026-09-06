package reconcile

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
)

type gateLifecycleListener struct {
	mu     sync.Mutex
	first  net.Conn
	served bool
	closed chan struct{}
	once   sync.Once
}

func (l *gateLifecycleListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if !l.served {
		l.served = true
		conn := l.first
		l.mu.Unlock()
		return conn, nil
	}
	l.mu.Unlock()
	<-l.closed
	return nil, net.ErrClosed
}

func (l *gateLifecycleListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *gateLifecycleListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 19001}
}

type gateLifecycleConn struct {
	net.Conn
	readStarted chan struct{}
	readDone    chan struct{}
	closeOnce   sync.Once
}

func (c *gateLifecycleConn) Read(p []byte) (int, error) {
	select {
	case <-c.readStarted:
	default:
		close(c.readStarted)
	}
	defer func() {
		select {
		case <-c.readDone:
		default:
			close(c.readDone)
		}
	}()
	return c.Conn.Read(p)
}

func (c *gateLifecycleConn) Close() error {
	var err error
	c.closeOnce.Do(func() { err = c.Conn.Close() })
	return err
}

func (c *gateLifecycleConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 19002}
}

func (c *gateLifecycleConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 19001}
}

func probeGateLifecycleManager() *ProbeManager {
	var probeID [16]byte
	probeID[0] = 1
	return &ProbeManager{
		clock: time.Now,
		ops: map[[16]byte]*armedOp{
			probeID: {
				arm:       protocol.ProbeArm{ExpectedSourceIP: [4]byte{127, 0, 0, 1}},
				forwardID: "fwd-1",
				deadline:  time.Now().Add(time.Hour),
			},
		},
		replay: map[[16]byte]time.Time{},
	}
}

// TestProbeGateCloseJoinsIngressWorkers covers shutdown while a provider
// connection is blocked in the bounded WAN1 reader. Close must close active
// ingress sockets and join their goroutines rather than waiting for the read
// deadline or closing the localstate store underneath them.
func TestProbeGateCloseJoinsIngressWorkers(t *testing.T) {
	server, peer := net.Pipe()
	conn := &gateLifecycleConn{Conn: server, readStarted: make(chan struct{}), readDone: make(chan struct{})}
	listener := &gateLifecycleListener{first: conn, closed: make(chan struct{})}
	gate := NewProbeGate(listener, probeGateLifecycleManager(), ProbeGateOptions{
		ForwardID:   "fwd-1",
		ReadTimeout: time.Hour,
	})
	defer peer.Close()

	acceptDone := make(chan struct{})
	go func() {
		_, _ = gate.Accept()
		close(acceptDone)
	}()
	select {
	case <-conn.readStarted:
	case <-time.After(time.Second):
		t.Fatal("probe ingress worker did not start")
	}

	if err := gate.Close(); err != nil {
		t.Fatalf("gate Close: %v", err)
	}
	select {
	case <-conn.readDone:
	case <-time.After(time.Second):
		t.Fatal("gate Close returned while ingress worker was still blocked")
	}
	select {
	case <-acceptDone:
	case <-time.After(time.Second):
		t.Fatal("gate Accept loop did not stop")
	}
}
