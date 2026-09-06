// Story 2 RED: transaction-safe UDP client over a caller-owned socket.
// Responses are consumed only when transaction ID, exact server tuple, and
// class (success/error) match (v0.8 §4.3); wrong source/class/transaction
// are ignored. Retransmission follows RFC 8489 §6.2.1 (RTO doubling, Rc
// requests, Rm×RTO final wait). Error 300 Try Alternate reattempts against
// the ALTERNATE-SERVER with the same transport, bounded against loops
// (RFC 8489 §10).
package stun

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// replySpec is one datagram the fake server emits: either from its own
// socket (correct source) or from the decoy socket (wrong source).
type replySpec struct {
	wrongSource bool
	msg         *Message
}

// fakeUDPServer is a deterministic STUN server over UDP on loopback. The
// handler decides per request which datagrams to emit, and records receive
// timestamps.
type fakeUDPServer struct {
	conn    *net.UDPConn
	decoy   *net.UDPConn
	addr    netip.AddrPort
	handler func(req *Message, from netip.AddrPort) []replySpec
	mu      sync.Mutex
	seen    []time.Time
}

func newFakeUDPServer(t *testing.T, handler func(req *Message, from netip.AddrPort) []replySpec) *fakeUDPServer {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("fake server listen: %v", err)
	}
	decoy, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		conn.Close()
		t.Fatalf("fake decoy listen: %v", err)
	}
	server := &fakeUDPServer{
		conn:    conn,
		decoy:   decoy,
		addr:    conn.LocalAddr().(*net.UDPAddr).AddrPort(),
		handler: handler,
	}
	go server.serve()
	t.Cleanup(func() {
		conn.Close()
		decoy.Close()
	})
	return server
}

func (s *fakeUDPServer) serve() {
	buf := make([]byte, 2048)
	for {
		n, from, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		s.mu.Lock()
		s.seen = append(s.seen, time.Now())
		s.mu.Unlock()
		msg, err := ParseMessage(buf[:n])
		if err != nil {
			continue
		}
		for _, reply := range s.handler(msg, from.AddrPort()) {
			wire, err := reply.msg.Marshal()
			if err != nil {
				continue
			}
			target := s.conn
			if reply.wrongSource {
				target = s.decoy
			}
			_, _ = target.WriteToUDP(wire, from)
		}
	}
}

func (s *fakeUDPServer) requestCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.seen)
}

// successSpec answers with XOR-MAPPED-ADDRESS reflecting the observed
// source.
func successSpec(req *Message, from netip.AddrPort) []replySpec {
	reply := &Message{Type: MessageTypeBindingSuccess, TransactionID: req.TransactionID}
	_ = reply.AddXORMappedAddress(from)
	return []replySpec{{msg: reply}}
}

func newClientSocket(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func TestUDPExchangeSuccess(t *testing.T) {
	server := newFakeUDPServer(t, successSpec)
	conn := newClientSocket(t)
	client := NewUDPClient(conn, UDPClientOptions{RTO: 10 * time.Millisecond, MaxRequests: 3})

	req := NewBindingRequest([12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	reply, err := client.Exchange(ctx, server.addr, req)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if reply.Type != MessageTypeBindingSuccess {
		t.Fatalf("reply type = %#04x", reply.Type)
	}
	if reply.TransactionID != req.TransactionID {
		t.Fatalf("reply txid = %x, want %x", reply.TransactionID, req.TransactionID)
	}
	mapped, err := reply.XORMappedAddress()
	if err != nil {
		t.Fatalf("XORMappedAddress: %v", err)
	}
	if want := conn.LocalAddr().(*net.UDPAddr).AddrPort(); mapped != want {
		t.Fatalf("mapped = %v, want client tuple %v", mapped, want)
	}
	if got := server.requestCount(); got != 1 {
		t.Fatalf("server saw %d requests, want 1 (no spurious retransmit)", got)
	}
}

func TestUDPExchangeIgnoresWrongSource(t *testing.T) {
	// The server first answers from a decoy socket (wrong source), then from
	// the correct socket. Only the correct-source reply may be consumed.
	var first bool
	server := newFakeUDPServer(t, func(req *Message, from netip.AddrPort) []replySpec {
		correct := &Message{Type: MessageTypeBindingSuccess, TransactionID: req.TransactionID}
		_ = correct.AddXORMappedAddress(from)
		wrong := &Message{Type: MessageTypeBindingSuccess, TransactionID: req.TransactionID}
		_ = wrong.AddXORMappedAddress(netip.MustParseAddrPort("198.51.100.7:1234"))
		if !first {
			first = true
			return []replySpec{{wrongSource: true, msg: wrong}, {msg: correct}}
		}
		return []replySpec{{msg: correct}}
	})
	conn := newClientSocket(t)
	client := NewUDPClient(conn, UDPClientOptions{RTO: 10 * time.Millisecond, MaxRequests: 3})
	req := NewBindingRequest([12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
	reply, err := client.Exchange(context.Background(), server.addr, req)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	mapped, err := reply.XORMappedAddress()
	if err != nil {
		t.Fatalf("XORMappedAddress: %v", err)
	}
	if mapped.Port() == 1234 {
		t.Fatalf("wrong-source reply was consumed: mapped = %v", mapped)
	}
}

func TestUDPExchangeIgnoresWrongClassAndTransaction(t *testing.T) {
	// A request-class echo and a mismatched-transaction response must be
	// ignored; only the matching success response is consumed.
	server := newFakeUDPServer(t, func(req *Message, from netip.AddrPort) []replySpec {
		echo := &Message{Type: MessageTypeBindingRequest, TransactionID: req.TransactionID}
		other := &Message{Type: MessageTypeBindingSuccess, TransactionID: TransactionID{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}
		_ = other.AddXORMappedAddress(netip.MustParseAddrPort("198.51.100.8:4321"))
		correct := &Message{Type: MessageTypeBindingSuccess, TransactionID: req.TransactionID}
		_ = correct.AddXORMappedAddress(from)
		return []replySpec{{msg: echo}, {msg: other}, {msg: correct}}
	})
	conn := newClientSocket(t)
	client := NewUDPClient(conn, UDPClientOptions{RTO: 10 * time.Millisecond, MaxRequests: 3})
	req := NewBindingRequest([12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
	reply, err := client.Exchange(context.Background(), server.addr, req)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	mapped, err := reply.XORMappedAddress()
	if err != nil {
		t.Fatalf("XORMappedAddress: %v", err)
	}
	if want := conn.LocalAddr().(*net.UDPAddr).AddrPort(); mapped != want {
		t.Fatalf("mapped = %v, want %v", mapped, want)
	}
}

func TestUDPExchangeRetransmitsWithDoublingBackoff(t *testing.T) {
	// Drop the first two requests; the client must retransmit with RTO
	// doubling and succeed on the third.
	dropped := 0
	server := newFakeUDPServer(t, func(req *Message, from netip.AddrPort) []replySpec {
		if dropped < 2 {
			dropped++
			return nil // drop
		}
		return successSpec(req, from)
	})
	conn := newClientSocket(t)
	client := NewUDPClient(conn, UDPClientOptions{RTO: 10 * time.Millisecond, MaxRequests: 5})
	req := NewBindingRequest([12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
	start := time.Now()
	reply, err := client.Exchange(context.Background(), server.addr, req)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if reply.TransactionID != req.TransactionID {
		t.Fatalf("txid mismatch")
	}
	if got := server.requestCount(); got != 3 {
		t.Fatalf("server saw %d requests, want 3", got)
	}
	elapsed := time.Since(start)
	// RTO=10ms: sends at 0, 10, 30ms; success arrives after the third send.
	if elapsed < 20*time.Millisecond {
		t.Fatalf("elapsed %v too short for doubling backoff", elapsed)
	}
}

func TestUDPExchangeDeadlineAndRetransmitCap(t *testing.T) {
	// Server never answers. With RTO=10ms and MaxRequests=4 the client must
	// send at most 4 requests and fail with a timeout error.
	server := newFakeUDPServer(t, func(*Message, netip.AddrPort) []replySpec { return nil })
	conn := newClientSocket(t)
	client := NewUDPClient(conn, UDPClientOptions{RTO: 10 * time.Millisecond, MaxRequests: 4})
	req := NewBindingRequest([12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
	_, err := client.Exchange(context.Background(), server.addr, req)
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("Exchange = %v, want ErrTimeout", err)
	}
	if got := server.requestCount(); got != 4 {
		t.Fatalf("server saw %d requests, want exactly 4 (Rc cap)", got)
	}
}

func TestUDPExchangeAlternateServer300(t *testing.T) {
	// Primary server answers 300 Try Alternate with ALTERNATE-SERVER; the
	// client must fail the current transaction and reattempt against the
	// alternate server (RFC 8489 §10). Alternates are disabled by default
	// and restricted to global unicast addresses, so this test opts in via
	// MaxAlternates and the package-internal loopback test seam.
	alternate := newFakeUDPServer(t, successSpec)
	primary := newFakeUDPServer(t, func(req *Message, from netip.AddrPort) []replySpec {
		reply := NewErrorResponse(req.TransactionID, 300, "Try Alternate")
		if err := reply.AddAlternateServer(alternate.addr); err != nil {
			t.Errorf("primary: %v", err)
		}
		return []replySpec{{msg: reply}}
	})
	conn := newClientSocket(t)
	client := NewUDPClient(conn, UDPClientOptions{
		RTO:              10 * time.Millisecond,
		MaxRequests:      3,
		MaxAlternates:    DefaultMaxAlternates,
		alternateAllowed: allowLoopbackAlternates,
	})
	req := NewBindingRequest([12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
	reply, err := client.Exchange(context.Background(), primary.addr, req)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if reply.Type != MessageTypeBindingSuccess {
		t.Fatalf("reply type = %#04x, want success", reply.Type)
	}
	if primary.requestCount() != 1 {
		t.Fatalf("primary saw %d requests, want 1", primary.requestCount())
	}
	if alternate.requestCount() != 1 {
		t.Fatalf("alternate saw %d requests, want 1", alternate.requestCount())
	}
}

func TestUDPExchangeAlternateServerLoopBounded(t *testing.T) {
	// Two servers redirect to each other; the client must stop after a
	// bounded number of alternates instead of ping-ponging forever.
	var (
		mu            sync.Mutex
		primaryAddr   netip.AddrPort
		alternateAddr netip.AddrPort
	)
	alternate := newFakeUDPServer(t, func(req *Message, from netip.AddrPort) []replySpec {
		mu.Lock()
		target := primaryAddr
		mu.Unlock()
		reply := NewErrorResponse(req.TransactionID, 300, "Try Alternate")
		_ = reply.AddAlternateServer(target)
		return []replySpec{{msg: reply}}
	})
	primary := newFakeUDPServer(t, func(req *Message, from netip.AddrPort) []replySpec {
		mu.Lock()
		target := alternateAddr
		mu.Unlock()
		reply := NewErrorResponse(req.TransactionID, 300, "Try Alternate")
		_ = reply.AddAlternateServer(target)
		return []replySpec{{msg: reply}}
	})
	mu.Lock()
	alternateAddr = alternate.addr
	primaryAddr = primary.addr
	mu.Unlock()
	conn := newClientSocket(t)
	client := NewUDPClient(conn, UDPClientOptions{
		RTO:              10 * time.Millisecond,
		MaxRequests:      2,
		MaxAlternates:    2,
		alternateAllowed: allowLoopbackAlternates,
	})
	req := NewBindingRequest([12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
	_, err := client.Exchange(context.Background(), primary.addr, req)
	if !errors.Is(err, ErrAlternateLoop) {
		t.Fatalf("Exchange = %v, want ErrAlternateLoop", err)
	}
	if primary.requestCount()+alternate.requestCount() > 3 {
		t.Fatalf("redirect ping-pong not bounded: primary=%d alternate=%d",
			primary.requestCount(), alternate.requestCount())
	}
}

// allowLoopbackAlternates is the package-internal alternate-policy test
// seam: the production policy (RFC 8489 §10) restricts alternates to
// global unicast addresses, which rejects the loopback servers these
// redirection tests use. Tests opt in explicitly through the unexported
// hook; production callers cannot set it.
func allowLoopbackAlternates(ap netip.AddrPort) bool {
	return ap.Addr().Unmap().IsLoopback()
}

func TestUDPExchangeAlternatesDisabledByDefault(t *testing.T) {
	// ALTERNATE-SERVER handling is disabled by default (frozen design
	// reference §6). A 300 reply is therefore the final transaction result
	// and no datagram may ever be sent to the alternate.
	alternate := newFakeUDPServer(t, successSpec)
	primary := newFakeUDPServer(t, func(req *Message, from netip.AddrPort) []replySpec {
		reply := NewErrorResponse(req.TransactionID, 300, "Try Alternate")
		_ = reply.AddAlternateServer(alternate.addr)
		return []replySpec{{msg: reply}}
	})
	conn := newClientSocket(t)
	client := NewUDPClient(conn, UDPClientOptions{RTO: 10 * time.Millisecond, MaxRequests: 3})
	req := NewBindingRequest([12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
	reply, err := client.Exchange(context.Background(), primary.addr, req)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	code, _, codeErr := reply.ErrorCode()
	if codeErr != nil || code != 300 {
		t.Fatalf("reply error code = %d (%v), want the 300 returned un-followed", code, codeErr)
	}
	if got := alternate.requestCount(); got != 0 {
		t.Fatalf("alternate received %d requests, want 0 (alternates disabled by default)", got)
	}
}

func TestUDPExchangeAlternatesExplicitlyDisabled(t *testing.T) {
	// DisableAlternates is the explicit kill switch: even with
	// MaxAlternates set, the 300 reply is returned un-followed.
	alternate := newFakeUDPServer(t, successSpec)
	primary := newFakeUDPServer(t, func(req *Message, from netip.AddrPort) []replySpec {
		reply := NewErrorResponse(req.TransactionID, 300, "Try Alternate")
		_ = reply.AddAlternateServer(alternate.addr)
		return []replySpec{{msg: reply}}
	})
	conn := newClientSocket(t)
	client := NewUDPClient(conn, UDPClientOptions{
		RTO:               10 * time.Millisecond,
		MaxRequests:       3,
		MaxAlternates:     DefaultMaxAlternates,
		DisableAlternates: true,
	})
	req := NewBindingRequest([12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
	reply, err := client.Exchange(context.Background(), primary.addr, req)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	code, _, codeErr := reply.ErrorCode()
	if codeErr != nil || code != 300 {
		t.Fatalf("reply error code = %d (%v), want the 300 returned un-followed", code, codeErr)
	}
	if got := alternate.requestCount(); got != 0 {
		t.Fatalf("alternate received %d requests, want 0 (DisableAlternates)", got)
	}
}

func TestUDPExchangeAlternateRejectsNonGlobalAddress(t *testing.T) {
	// RFC 8489 §10 restricts alternates to global unicast addresses: a
	// forged 300 must not redirect the client into probing loopback or
	// private space (frozen design reference §6: "validate ... global
	// address ...").
	t.Run("loopback", func(t *testing.T) {
		alternate := newFakeUDPServer(t, successSpec)
		primary := newFakeUDPServer(t, func(req *Message, from netip.AddrPort) []replySpec {
			reply := NewErrorResponse(req.TransactionID, 300, "Try Alternate")
			_ = reply.AddAlternateServer(alternate.addr)
			return []replySpec{{msg: reply}}
		})
		conn := newClientSocket(t)
		client := NewUDPClient(conn, UDPClientOptions{
			RTO:           10 * time.Millisecond,
			MaxRequests:   3,
			MaxAlternates: DefaultMaxAlternates,
		})
		req := NewBindingRequest([12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
		_, err := client.Exchange(context.Background(), primary.addr, req)
		if !errors.Is(err, ErrAlternateLoop) {
			t.Fatalf("Exchange = %v, want ErrAlternateLoop (loopback alternate rejected)", err)
		}
		if got := alternate.requestCount(); got != 0 {
			t.Fatalf("alternate received %d probes, want 0 (non-global alternate must never be contacted)", got)
		}
		if got := primary.requestCount(); got != 1 {
			t.Fatalf("primary saw %d requests, want 1", got)
		}
	})
	t.Run("rfc1918-private", func(t *testing.T) {
		primary := newFakeUDPServer(t, func(req *Message, from netip.AddrPort) []replySpec {
			reply := NewErrorResponse(req.TransactionID, 300, "Try Alternate")
			_ = reply.AddAlternateServer(netip.MustParseAddrPort("192.168.1.1:3478"))
			return []replySpec{{msg: reply}}
		})
		conn := newClientSocket(t)
		client := NewUDPClient(conn, UDPClientOptions{
			RTO:           10 * time.Millisecond,
			MaxRequests:   3,
			MaxAlternates: DefaultMaxAlternates,
		})
		req := NewBindingRequest([12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
		_, err := client.Exchange(context.Background(), primary.addr, req)
		if !errors.Is(err, ErrAlternateLoop) {
			t.Fatalf("Exchange = %v, want ErrAlternateLoop (RFC 1918 alternate rejected)", err)
		}
	})
	t.Run("rfc6598-cgnat", func(t *testing.T) {
		// Optional hardening from the review: the RFC 6598 shared-address
		// space (100.64.0.0/10) is carrier-internal and must not be probed
		// either. Go's IsGlobalUnicast reports it as global, so the CGNAT
		// prefix is excluded explicitly.
		primary := newFakeUDPServer(t, func(req *Message, from netip.AddrPort) []replySpec {
			reply := NewErrorResponse(req.TransactionID, 300, "Try Alternate")
			_ = reply.AddAlternateServer(netip.MustParseAddrPort("100.64.0.1:3478"))
			return []replySpec{{msg: reply}}
		})
		conn := newClientSocket(t)
		client := NewUDPClient(conn, UDPClientOptions{
			RTO:           10 * time.Millisecond,
			MaxRequests:   3,
			MaxAlternates: DefaultMaxAlternates,
		})
		req := NewBindingRequest([12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
		_, err := client.Exchange(context.Background(), primary.addr, req)
		if !errors.Is(err, ErrAlternateLoop) {
			t.Fatalf("Exchange = %v, want ErrAlternateLoop (RFC 6598 CGNAT alternate rejected)", err)
		}
	})
}

func TestUDPExchangeIPv4MappedSourceOnDualStackSocket(t *testing.T) {
	// A dual-stack caller-owned socket reports IPv4 sources as IPv4-mapped
	// (::ffff:a.b.c.d). The demux must unmap the source before comparing it
	// with the plain-IPv4 server tuple, or every response is dropped as a
	// wrong source and the exchange times out (P09 FIX1 bug class).
	server := newFakeUDPServer(t, successSpec)
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6unspecified})
	if err != nil {
		t.Skipf("dual-stack listen unavailable: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	client := NewUDPClient(conn, UDPClientOptions{RTO: 10 * time.Millisecond, MaxRequests: 3})
	req := NewBindingRequest([12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	reply, err := client.Exchange(ctx, server.addr, req)
	if err != nil {
		t.Fatalf("Exchange over dual-stack socket: %v", err)
	}
	if reply.TransactionID != req.TransactionID {
		t.Fatalf("reply txid = %x, want %x", reply.TransactionID, req.TransactionID)
	}
}

func TestUDPExchangeConcurrentTransactions(t *testing.T) {
	// Two concurrent exchanges on the same caller-owned socket must each
	// receive their own matching response (transaction-safe demux).
	server := newFakeUDPServer(t, successSpec)
	conn := newClientSocket(t)
	client := NewUDPClient(conn, UDPClientOptions{RTO: 10 * time.Millisecond, MaxRequests: 3})
	reqA := NewBindingRequest([12]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
	reqB := NewBindingRequest([12]byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2})

	results := make(chan error, 2)
	exchange := func(req *Message, name string) {
		reply, err := client.Exchange(context.Background(), server.addr, req)
		if err == nil && reply.TransactionID != req.TransactionID {
			err = errors.New(name + " received wrong transaction")
		}
		results <- err
	}
	go exchange(reqA, "A")
	go exchange(reqB, "B")
	for i := 0; i < 2; i++ {
		if err := <-results; err != nil {
			t.Fatalf("concurrent exchange: %v", err)
		}
	}
}
