// Story 3 RED: the TCP proxy must sustain long bidirectional connections,
// propagate half-close correctly in both directions (CloseWrite, never a
// full close on one direction's EOF), survive backend failure without
// stopping the accept loop, and back off on transient accept errors instead
// of busy-looping (v0.8 §4.2: TCP forwarding must handle half-close).
package tcp_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/forward"
	"github.com/gxbrave/AntiNAT-Agent/internal/forward/tcp"
)

// startEchoServer runs a TCP echo server that prefixes every received chunk.
func startEchoServer(t *testing.T, prefix string) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listener: %v", err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buffer := make([]byte, 32*1024)
				for {
					n, err := c.Read(buffer)
					if n > 0 {
						if _, writeErr := c.Write(append([]byte(prefix), buffer[:n]...)); writeErr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return listener.Addr().String(), func() {
		listener.Close()
		wg.Wait()
	}
}

// startForward starts a proxy on a fresh loopback port.
func startForward(t *testing.T, backend *forward.Backend, options ...func(*tcp.Options)) (string, *tcp.Forward) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listener: %v", err)
	}
	opts := tcp.Options{Backend: backend}
	for _, apply := range options {
		apply(&opts)
	}
	proxy, err := tcp.New(listener, opts)
	if err != nil {
		listener.Close()
		t.Fatalf("tcp.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = proxy.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		listener.Close()
		<-done
	})
	return listener.Addr().String(), proxy
}

// readExactly reads exactly n bytes with a deadline.
func readExactly(t *testing.T, conn net.Conn, n int) []byte {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 0, n)
	buffer := make([]byte, 32*1024)
	for len(got) < n {
		read, err := conn.Read(buffer)
		if err != nil {
			t.Fatalf("read %d of %d bytes: %v", len(got), n, err)
		}
		got = append(got, buffer[:read]...)
	}
	return got
}

func TestLongConnectionBidirectionalTransfer(t *testing.T) {
	target, stopEcho := startEchoServer(t, "")
	defer stopEcho()
	backend, err := forward.NewBackend(target)
	if err != nil {
		t.Fatal(err)
	}
	proxyAddr, _ := startForward(t, backend)

	conn, err := net.Dial("tcp4", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// Sustained bidirectional exchange: 200 request/response rounds with a
	// small inter-round delay, then a 1 MiB bulk transfer. A naive
	// one-shot-copy proxy would fail this test.
	for round := 0; round < 200; round++ {
		message := fmt.Sprintf("msg-%03d", round)
		if _, err := conn.Write([]byte(message)); err != nil {
			t.Fatalf("round %d write: %v", round, err)
		}
		if got := readExactly(t, conn, len(message)); !bytes.Equal(got, []byte(message)) {
			t.Fatalf("round %d got %q, want %q", round, got, message)
		}
		time.Sleep(5 * time.Millisecond)
	}

	bulk := bytes.Repeat([]byte("bulk-data-"), 128*1024) // 1 MiB
	if _, err := conn.Write(bulk); err != nil {
		t.Fatalf("bulk write: %v", err)
	}
	reply := readExactly(t, conn, len(bulk))
	if !bytes.Equal(reply, bulk) {
		t.Fatalf("bulk reply mismatch: got %d bytes, want %d", len(reply), len(bulk))
	}
}

func TestHalfCloseClientToServerPreservesServerReply(t *testing.T) {
	// Target reads until EOF (only possible when the proxy propagates the
	// client's CloseWrite), then answers with the received length and closes.
	targetListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer targetListener.Close()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := targetListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		data, err := io.ReadAll(conn)
		if err != nil {
			t.Errorf("target read: %v", err)
			return
		}
		conn.Write([]byte(fmt.Sprintf("done-%d", len(data))))
	}()

	backend, err := forward.NewBackend(targetListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	proxyAddr, _ := startForward(t, backend)

	conn, err := net.Dial("tcp4", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload := bytes.Repeat([]byte("x"), 4096)
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	tcpConn := conn.(*net.TCPConn)
	if err := tcpConn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got := readExactly(t, conn, len("done-4096"))
	if string(got) != "done-4096" {
		t.Fatalf("reply = %q, want done-4096", got)
	}
	wg.Wait()
}

func TestHalfCloseServerToClientPreservesClientWrite(t *testing.T) {
	// Target greets, half-closes its write side, then keeps reading. The
	// client must still be able to send after observing read-EOF: a proxy
	// that fully closes on the first direction's EOF would truncate the
	// client's write.
	received := make(chan int64, 1)
	targetListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer targetListener.Close()
	go func() {
		conn, err := targetListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.Write([]byte("hello"))
		conn.(*net.TCPConn).CloseWrite()
		n, _ := io.Copy(io.Discard, conn)
		received <- n
	}()

	backend, err := forward.NewBackend(targetListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	proxyAddr, _ := startForward(t, backend)

	conn, err := net.Dial("tcp4", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tcpConn := conn.(*net.TCPConn)

	if got := readExactly(t, conn, len("hello")); string(got) != "hello" {
		t.Fatalf("greeting = %q, want hello", got)
	}
	// Read side must now report EOF while the write side stays usable.
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var one [1]byte
	if n, err := conn.Read(one[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("read after greeting = %d, %v; want 0, EOF", n, err)
	}
	payload := bytes.Repeat([]byte("y"), 4096)
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write after read-EOF: %v", err)
	}
	if err := tcpConn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	select {
	case n := <-received:
		if n != int64(len(payload)) {
			t.Fatalf("target received %d bytes, want %d", n, len(payload))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("target never received the post-EOF client data")
	}
}

func TestBackendFailureDoesNotStopAcceptLoop(t *testing.T) {
	// Reserve a target port, then leave it closed for the first client.
	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	targetAddr := probe.Addr().String()
	probe.Close()

	backend, err := forward.NewBackend(targetAddr)
	if err != nil {
		t.Fatal(err)
	}
	proxyAddr, _ := startForward(t, backend)

	first, err := net.Dial("tcp4", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	if err := first.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := first.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatalf("failed-backend session read = %d, %v; want immediate EOF", n, err)
	}
	first.Close()

	// The accept loop must survive: bring the target up on the exact port and
	// a second client must work end-to-end.
	echoListener, err := net.Listen("tcp4", targetAddr)
	if err != nil {
		t.Fatalf("rebind target: %v", err)
	}
	defer echoListener.Close()
	go func() {
		for {
			conn, err := echoListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buffer := make([]byte, 1024)
				for {
					n, err := c.Read(buffer)
					if n > 0 {
						c.Write(append([]byte("E:"), buffer[:n]...))
					}
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	second, err := net.Dial("tcp4", proxyAddr)
	if err != nil {
		t.Fatalf("second dial: %v", err)
	}
	defer second.Close()
	if _, err := second.Write([]byte("alive")); err != nil {
		t.Fatalf("second write: %v", err)
	}
	if got := readExactly(t, second, len("E:alive")); string(got) != "E:alive" {
		t.Fatalf("second echo = %q, want E:alive", got)
	}
}

// flakyListener fails Accept with EMFILE a bounded number of times before
// delegating, recording when each failure happened.
type flakyListener struct {
	mu       sync.Mutex
	listener net.Listener
	failures int
	times    []time.Time
}

func (l *flakyListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if l.failures > 0 {
		l.failures--
		l.times = append(l.times, time.Now())
		l.mu.Unlock()
		return nil, &net.OpError{Op: "accept", Net: "tcp4", Err: syscall.EMFILE}
	}
	l.mu.Unlock()
	return l.listener.Accept()
}

func (l *flakyListener) failureTimes() []time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]time.Time(nil), l.times...)
}

func (l *flakyListener) Close() error   { return l.listener.Close() }
func (l *flakyListener) Addr() net.Addr { return l.listener.Addr() }

func TestAcceptBackoffSurvivesTransientErrors(t *testing.T) {
	target, stopEcho := startEchoServer(t, "T:")
	defer stopEcho()
	backend, err := forward.NewBackend(target)
	if err != nil {
		t.Fatal(err)
	}
	realListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	flaky := &flakyListener{listener: realListener, failures: 2}
	proxy, err := tcp.New(flaky, tcp.Options{
		Backend:          backend,
		AcceptBackoffMin: 20 * time.Millisecond,
		AcceptBackoffMax: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = proxy.Run(ctx)
	}()
	defer func() {
		cancel()
		realListener.Close()
		<-done
	}()

	conn, err := net.Dial("tcp4", realListener.Addr().String())
	if err != nil {
		t.Fatalf("dial after transient failures: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	if got := readExactly(t, conn, len("T:ok")); string(got) != "T:ok" {
		t.Fatalf("echo = %q, want T:ok", got)
	}
	times := flaky.failureTimes()
	if len(times) != 2 {
		t.Fatalf("flaky accept count = %d, want 2", len(times))
	}
	// Both failures must have been paced by the backoff, not busy-looped.
	if gap := times[1].Sub(times[0]); gap < 20*time.Millisecond {
		t.Fatalf("accept retry gap = %v, want >= 20ms backoff", gap)
	}
}

func TestRunStopsWhenListenerClosed(t *testing.T) {
	target, stopEcho := startEchoServer(t, "T:")
	defer stopEcho()
	backend, err := forward.NewBackend(target)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := tcp.New(listener, tcp.Options{Backend: backend})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = proxy.Run(ctx)
	}()
	cancel()
	listener.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop after listener close")
	}
}
