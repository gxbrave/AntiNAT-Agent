// Story 5 RED: budget exhaustion at the proxy level must reject the excess
// connection with the explicit reason, and the delete/stop hook must close
// the listener and every tracked session (v0.8 §4.1 rule 4 and M1: online
// DELETE immediately disconnects).
package tcp_test

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/forward"
	"github.com/gxbrave/AntiNAT-Agent/internal/forward/tcp"
)

func TestBudgetExhaustionRejectsConnectionWithExplicitReason(t *testing.T) {
	target, stopEcho := startEchoServer(t, "T:")
	defer stopEcho()
	backend, err := forward.NewBackend(target)
	if err != nil {
		t.Fatal(err)
	}
	budget, err := forward.NewBudget(forward.Limits{MaxConnections: 1})
	if err != nil {
		t.Fatal(err)
	}
	var rejectReason atomic.Value
	proxyAddr, proxy := startForward(t, backend, func(opts *tcp.Options) {
		opts.Budget = budget
		opts.OnReject = func(reason error) { rejectReason.Store(reason) }
	})

	// First connection holds the only budget slot.
	first, err := net.Dial("tcp4", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := first.Write([]byte("one")); err != nil {
		t.Fatal(err)
	}
	if got := readExactly(t, first, len("T:one")); string(got) != "T:one" {
		t.Fatalf("first echo = %q, want T:one", got)
	}

	// Second connection is rejected with the explicit connection-limit reason.
	second, err := net.Dial("tcp4", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := second.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := second.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatalf("rejected connection read = %d, %v; want immediate EOF", n, err)
	}
	reason, ok := rejectReason.Load().(error)
	if !ok {
		t.Fatal("no reject reason recorded")
	}
	if !errors.Is(reason, forward.ErrBudgetExceeded) {
		t.Fatalf("reject reason = %v, want ErrBudgetExceeded", reason)
	}
	var exceeded *forward.BudgetExceededError
	if !errors.As(reason, &exceeded) || exceeded.Kind != forward.LimitConnections {
		t.Fatalf("reject reason = %v, want LimitConnections exceeded", reason)
	}

	// The held session is unaffected.
	if _, err := first.Write([]byte("two")); err != nil {
		t.Fatal(err)
	}
	if got := readExactly(t, first, len("T:two")); string(got) != "T:two" {
		t.Fatalf("first echo after rejection = %q, want T:two", got)
	}

	// When the held session ends, capacity is freed for new connections.
	first.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if proxy.Stats().Active == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("active sessions did not drain, stats = %+v", proxy.Stats())
		}
		time.Sleep(10 * time.Millisecond)
	}
	third, err := net.Dial("tcp4", proxyAddr)
	if err != nil {
		t.Fatalf("third dial after drain: %v", err)
	}
	defer third.Close()
	if _, err := third.Write([]byte("three")); err != nil {
		t.Fatal(err)
	}
	if got := readExactly(t, third, len("T:three")); string(got) != "T:three" {
		t.Fatalf("third echo = %q, want T:three", got)
	}
	stats := proxy.Stats()
	if stats.Accepted != 2 || stats.Rejected != 1 {
		t.Fatalf("stats = %+v, want accepted 2 rejected 1", stats)
	}
}

func TestStopClosesListenerAndTrackedSessions(t *testing.T) {
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
	runErr := make(chan error, 1)
	go func() { runErr <- proxy.Run(context.Background()) }()

	clients := make([]net.Conn, 0, 2)
	for i := 0; i < 2; i++ {
		conn, err := net.Dial("tcp4", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if _, err := conn.Write([]byte("hi")); err != nil {
			t.Fatal(err)
		}
		if got := readExactly(t, conn, len("T:hi")); string(got) != "T:hi" {
			t.Fatalf("client %d echo = %q, want T:hi", i, got)
		}
		clients = append(clients, conn)
	}
	if stats := proxy.Stats(); stats.Active != 2 {
		t.Fatalf("active before stop = %d, want 2", stats.Active)
	}

	if err := proxy.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Run returned %v, want nil on Close", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop after Close")
	}

	// Every tracked session must be disconnected.
	for i, conn := range clients {
		if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if n, err := conn.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("client %d read after Close = %d, %v; want EOF", i, n, err)
		}
	}
	if stats := proxy.Stats(); stats.Active != 0 {
		t.Fatalf("active after stop = %d, want 0", stats.Active)
	}

	// The listener must be closed: new dials fail.
	if conn, err := net.Dial("tcp4", listener.Addr().String()); err == nil {
		conn.Close()
		t.Fatal("dial after Close unexpectedly succeeded")
	}
	// Close is idempotent.
	if err := proxy.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}
