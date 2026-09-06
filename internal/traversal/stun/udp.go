// Transaction-safe STUN UDP client over a caller-owned socket. The client
// never creates or closes the socket; the caller owns it (v0.8 §4.3: STUN is
// consumed only by outstanding transaction ID + exact server tuple + class +
// deadline). A single demux reader routes datagrams to waiters so concurrent
// exchanges on one socket cannot steal each other's responses.
//
// Retransmission follows RFC 8489 §6.2.1: an initial RTO (>= 500 ms,
// doubling after each retransmission), at most Rc requests in total, and a
// final wait of Rm x RTO after the last request. Error 300 Try Alternate
// reattempts the request against the ALTERNATE-SERVER with the same
// transport, using a fresh transaction ID (RFC 8489 §5). Redirection is
// disabled by default (frozen design reference §6); when enabled it is
// bounded by a visited-server set, a total alternate cap, and the RFC 8489
// §10 global-unicast address rule.
package stun

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Default UDP client parameters (RFC 8489 §6.2.1).
const (
	DefaultRTO             = 500 * time.Millisecond
	DefaultMaxRequests     = 7  // Rc
	DefaultFinalWaitFactor = 16 // Rm
	// DefaultMaxAlternates is the standard redirection hop cap used when a
	// caller opts into 300 Try Alternate handling (MaxAlternates > 0).
	DefaultMaxAlternates = 3
)

// UDP client sentinel errors.
var (
	ErrTimeout       = errors.New("stun: UDP transaction timed out")
	ErrAlternateLoop = errors.New("stun: alternate-server redirection rejected or looped")
	ErrClientClosed  = errors.New("stun: UDP client is closed")
	ErrNotARequest   = errors.New("stun: exchange requires a request-class message")
)

// UDPClientOptions tunes the retransmission and redirection policy.
type UDPClientOptions struct {
	RTO             time.Duration // initial retransmission timeout; default 500 ms
	MaxRequests     int           // Rc: total requests; default 7
	FinalWaitFactor int           // Rm: final wait as a multiple of RTO; default 16
	// MaxAlternates caps 300 Try Alternate redirection hops. Redirection is
	// disabled by default (frozen design reference §6: ALTERNATE-SERVER
	// disabled by default); set MaxAlternates > 0 to enable it. When
	// enabled, every alternate must be a global unicast address
	// (RFC 8489 §10) or the redirect is rejected with ErrAlternateLoop.
	MaxAlternates int
	// DisableAlternates is an explicit kill switch: when true, a 300 Try
	// Alternate reply is returned to the caller as the final transaction
	// result even when MaxAlternates is set.
	DisableAlternates bool

	// alternateAllowed overrides the global-unicast alternate policy.
	// Package-internal test seam only: production callers cannot set it,
	// so the RFC 8489 §10 default cannot be weakened outside this package.
	alternateAllowed func(netip.AddrPort) bool
}

func (o UDPClientOptions) withDefaults() UDPClientOptions {
	if o.RTO <= 0 {
		o.RTO = DefaultRTO
	}
	if o.MaxRequests <= 0 {
		o.MaxRequests = DefaultMaxRequests
	}
	if o.FinalWaitFactor <= 0 {
		o.FinalWaitFactor = DefaultFinalWaitFactor
	}
	if o.MaxAlternates < 0 {
		o.MaxAlternates = 0
	}
	return o
}

// waiter is one outstanding transaction registered by an Exchange call.
type waiter struct {
	server netip.AddrPort
	method Method
	ch     chan *Message
	done   chan struct{}
	err    error
}

// fail unblocks the waiter with the given error (socket died).
func (w *waiter) fail(err error) {
	w.err = err
	close(w.done)
}

// UDPClient performs transaction-safe STUN exchanges over a caller-owned
// socket. Close stops new exchanges but never closes the socket.
type UDPClient struct {
	conn *net.UDPConn
	opts UDPClientOptions

	mu        sync.Mutex
	waiters   map[TransactionID]*waiter
	started   bool
	readerErr error
	closed    bool
}

// NewUDPClient binds a client to the caller-owned socket.
func NewUDPClient(conn *net.UDPConn, opts UDPClientOptions) *UDPClient {
	return &UDPClient{
		conn:    conn,
		opts:    opts.withDefaults(),
		waiters: make(map[TransactionID]*waiter),
	}
}

// Close marks the client closed; the caller-owned socket is not touched and
// in-flight transactions continue until their own deadline.
func (c *UDPClient) Close() {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
}

// Exchange sends req to server and waits for the matching response. It
// retransmits with doubling RTO until a response, the Rc cap, or the context
// deadline. 300 Try Alternate reattempts against the ALTERNATE-SERVER with
// the same transport and a fresh transaction ID, but only when redirection
// is enabled (MaxAlternates > 0 and DisableAlternates false; it is disabled
// by default) and the alternate is a global unicast address (RFC 8489 §10).
// The response is accepted only when its source is the exact server tuple,
// its class is success/error, its method matches, and its transaction ID
// matches the request (v0.8 §4.3).
func (c *UDPClient) Exchange(ctx context.Context, server netip.AddrPort, req *Message) (*Message, error) {
	if req.Type.Class() != ClassRequest {
		return nil, ErrNotARequest
	}
	visited := map[netip.AddrPort]bool{server: true}
	for alternates := 0; ; {
		reply, err := c.exchangeOnce(ctx, server, req)
		if err != nil {
			return nil, err
		}
		code, _, codeErr := reply.ErrorCode()
		if codeErr != nil || code != 300 {
			return reply, nil
		}
		if c.opts.DisableAlternates || c.opts.MaxAlternates <= 0 {
			// ALTERNATE-SERVER handling is disabled by default (frozen
			// design reference §6): the 300 error is the final result.
			return reply, nil
		}
		alt, altErr := reply.AlternateServer()
		if altErr != nil || visited[alt] || alternates >= c.opts.MaxAlternates {
			return nil, ErrAlternateLoop
		}
		if !c.alternateAllowed(alt) {
			// RFC 8489 §10 restricts alternates to global unicast
			// addresses; a forged 300 must not redirect the client into
			// probing private/internal/metadata space.
			return nil, ErrAlternateLoop
		}
		// The current transaction is failed; reattempt against the alternate
		// server with the same transport and a fresh transaction ID
		// (RFC 8489 §10, §5).
		txid, txErr := NewTransactionID()
		if txErr != nil {
			return nil, txErr
		}
		req = &Message{
			Type:          req.Type,
			TransactionID: txid,
			Attributes:    append([]Attribute(nil), req.Attributes...),
		}
		visited[alt] = true
		server = alt
		alternates++
	}
}

// alternateAllowed applies the ALTERNATE-SERVER address-class policy,
// defaulting to the RFC 8489 §10 global-unicast rule. The unexported
// override is a package-internal test seam (never settable by production
// callers) that lets tests exercise the redirection path on loopback.
func (c *UDPClient) alternateAllowed(alt netip.AddrPort) bool {
	if c.opts.alternateAllowed != nil {
		return c.opts.alternateAllowed(alt)
	}
	return defaultAlternateAllowed(alt)
}

// defaultAlternateAllowed reports whether an alternate server address may
// be followed. The policy implements the RFC 8489 §10 global-unicast
// restriction (frozen design reference §6: "validate transport, global
// address, loop count, and redirect count"): loopback, link-local,
// multicast, unspecified, RFC 1918 private, and RFC 6598 CGNAT addresses
// are refused, so a forged 300 cannot redirect the client into probing
// internal networks. netip.Addr.IsGlobalUnicast alone is not sufficient —
// it reports true for RFC 1918 private space — so IsPrivate and the CGNAT
// prefix are excluded explicitly.
func defaultAlternateAllowed(alt netip.AddrPort) bool {
	addr := alt.Addr().Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || cgnatPrefix.Contains(addr) {
		return false
	}
	return true
}

// cgnatPrefix is the RFC 6598 shared-address space (100.64.0.0/10).
var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

// exchangeOnce runs one request/response transaction against a single server.
func (c *UDPClient) exchangeOnce(ctx context.Context, server netip.AddrPort, req *Message) (*Message, error) {
	wire, err := req.Marshal()
	if err != nil {
		return nil, err
	}
	address := net.UDPAddrFromAddrPort(server)

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, ErrClientClosed
	}
	if c.readerErr != nil {
		err := c.readerErr
		c.mu.Unlock()
		return nil, err
	}
	if !c.started {
		c.started = true
		go c.readerLoop()
	}
	w := &waiter{
		server: server,
		method: req.Type.Method(),
		ch:     make(chan *Message, 1),
		done:   make(chan struct{}),
	}
	c.waiters[req.TransactionID] = w
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.waiters, req.TransactionID)
		c.mu.Unlock()
	}()

	if _, err := c.conn.WriteToUDP(wire, address); err != nil {
		return nil, err
	}
	rto := c.opts.RTO
	wait := rto
	for sent := 1; ; sent++ {
		if sent >= c.opts.MaxRequests {
			// Final wait of Rm x RTO after the last request (RFC 8489
			// §6.2.1), still bounded by the caller's deadline.
			return waitResponse(ctx, w, time.Duration(c.opts.FinalWaitFactor)*rto)
		}
		select {
		case msg := <-w.ch:
			return msg, nil
		case <-w.done:
			return nil, w.err
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
		if _, err := c.conn.WriteToUDP(wire, address); err != nil {
			return nil, err
		}
		wait *= 2
	}
}

func waitResponse(ctx context.Context, w *waiter, wait time.Duration) (*Message, error) {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case msg := <-w.ch:
		return msg, nil
	case <-w.done:
		return nil, w.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, ErrTimeout
	}
}

// readerLoop demultiplexes datagrams to the matching waiter. Datagrams are
// consumed only when the source equals the waiter's exact server tuple, the
// class is success or error, the method matches, and the transaction ID
// matches (v0.8 §4.3). The loop exits when the caller-owned socket fails,
// failing all pending waiters.
func (c *UDPClient) readerLoop() {
	buf := make([]byte, 65507)
	for {
		n, from, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			c.mu.Lock()
			c.readerErr = err
			waiters := make([]*waiter, 0, len(c.waiters))
			for _, w := range c.waiters {
				waiters = append(waiters, w)
			}
			c.mu.Unlock()
			for _, w := range waiters {
				w.fail(err)
			}
			return
		}
		msg, err := ParseMessage(buf[:n])
		if err != nil {
			continue
		}
		class := msg.Type.Class()
		if class != ClassSuccess && class != ClassError {
			continue // wrong class (e.g. an echoed request) is not a response
		}
		// On a dual-stack caller-owned socket, IPv4 responses arrive with an
		// IPv4-mapped source (::ffff:a.b.c.d); unmap before comparing against
		// the plain-IPv4 server tuple (same bug class as P09 FIX1).
		source := from.AddrPort()
		source = netip.AddrPortFrom(source.Addr().Unmap(), source.Port())
		c.mu.Lock()
		w, ok := c.waiters[msg.TransactionID]
		if ok && w.server == source && w.method == msg.Type.Method() {
			select {
			case w.ch <- msg:
			default: // waiter already has a response; drop the duplicate
			}
		}
		c.mu.Unlock()
	}
}
