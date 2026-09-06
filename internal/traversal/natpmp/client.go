// NAT-PMP client with weak lease ownership (v0.8 §3.4): NAT-PMP has no
// mapping nonce, so ownership is only a short lease plus the exact internal
// tuple. The default posture relies on lease expiry; an active delete is
// sent only for a mapping this client acquired with a non-zero internal
// tuple, and internal port 0 is always refused client-side — v1 never
// provides a delete-all operation. Requested ports are suggestions: the
// response's assigned port is authoritative.
package natpmp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Result-code sentinel errors (all definitive; RFC 6886 has no transient
// codes).
var (
	ErrUnsupportedVersion = errors.New("natpmp: gateway does not support NAT-PMP")
	ErrNotAuthorized      = errors.New("natpmp: gateway denied the mapping (NOT_AUTHORIZED)")
	ErrNetworkFailure     = errors.New("natpmp: gateway reported a network failure")
	ErrOutOfResources     = errors.New("natpmp: gateway is out of mapping resources")
	ErrUnsupportedOpcode  = errors.New("natpmp: gateway does not implement this opcode")
)

// Ownership and transport errors.
var (
	// ErrUnownedMapping refuses deletes/renews without an exact internal
	// tuple: internal port 0 is always rejected and never sent.
	ErrUnownedMapping = errors.New("natpmp: mapping lacks an exact internal tuple; refusing to send")
	// ErrNoResponse exhausts the bounded retry budget without a response.
	ErrNoResponse = errors.New("natpmp: gateway did not respond within the retry budget")
)

// resultErrors maps result codes to their sentinel errors.
var resultErrors = map[uint16]error{
	ResultUnsupportedVersion: ErrUnsupportedVersion,
	ResultNotAuthorized:      ErrNotAuthorized,
	ResultNetworkFailure:     ErrNetworkFailure,
	ResultOutOfResources:     ErrOutOfResources,
	ResultUnsupportedOpcode:  ErrUnsupportedOpcode,
}

// Protocol selects the MAP opcode. The zero value is not a protocol.
type Protocol byte

const (
	ProtocolUDP Protocol = 1 // opcode 1
	ProtocolTCP Protocol = 2 // opcode 2
)

// Valid reports whether the protocol is a known MAP opcode selector.
func (p Protocol) Valid() bool { return p == ProtocolUDP || p == ProtocolTCP }

func (p Protocol) opcode() byte {
	switch p {
	case ProtocolUDP:
		return 1
	case ProtocolTCP:
		return 2
	}
	return 0
}

// MapRequest is one MAP acquire/renew/delete request. Lifetime 0 is a
// delete; use Delete instead of building it by hand.
type MapRequest struct {
	Protocol              Protocol
	InternalPort          uint16
	RequestedExternalPort uint16 // suggestion only; the response decides
	Lifetime              time.Duration
}

// MapResult is the gateway-granted mapping. Ownership is weak: the mapping
// lives exactly as long as the granted lease and the gateway holds no
// client identity, so the journal only records the tuple, lease and epoch.
type MapResult struct {
	Protocol             Protocol
	InternalPort         uint16
	AssignedExternalPort uint16
	Lifetime             time.Duration
	Epoch                uint32
	// ServerRebooted is true when the response epoch rolled back beyond the
	// RFC 6886 tolerance: the gateway may have lost every mapping.
	ServerRebooted bool
}

// ClientOptions tunes the bounded client. Zero fields take defaults.
type ClientOptions struct {
	// Timeout is the per-attempt response budget; default 2s.
	Timeout time.Duration
	// MaxAttempts bounds total sends per transaction; default 3 (RFC 6886
	// §3.3 asks for at least 9 seconds of retransmission; the gateway
	// manager paces renewals instead of long blocking calls).
	MaxAttempts int
	// Backoff is the delay between attempts; default 500ms.
	Backoff time.Duration
	// EpochBaseline / EpochSeen carry the adapter's cross-transaction epoch
	// baseline: reboot detection (RFC 6886 §3.6) compares a response against
	// the PREVIOUS response's epoch, which a per-transaction client cannot
	// know on its own. The adapter snapshots the baseline before every
	// transaction and records the observed epoch after it.
	EpochBaseline uint32
	EpochSeen     bool
}

// Client is a single-transaction NAT-PMP client over UDP. It owns no
// socket: the PacketConn is injected and closed by the caller.
type Client struct {
	conn   net.PacketConn
	server netip.AddrPort
	opts   ClientOptions

	mu        sync.Mutex
	lastEpoch uint32
	sawEpoch  bool
}

// NewClient returns a client bound to the gateway endpoint.
func NewClient(conn net.PacketConn, server netip.AddrPort, opts ClientOptions) *Client {
	if opts.Timeout <= 0 {
		opts.Timeout = 2 * time.Second
	}
	if opts.MaxAttempts <= 0 {
		opts.MaxAttempts = 3
	}
	if opts.Backoff <= 0 {
		opts.Backoff = 500 * time.Millisecond
	}
	return &Client{
		conn:      conn,
		server:    server,
		opts:      opts,
		lastEpoch: opts.EpochBaseline,
		sawEpoch:  opts.EpochSeen,
	}
}

// publicResult carries the public-address response payload.
type publicResult struct {
	address netip.Addr
	epoch   uint32
}

// PublicAddress discovers the gateway's external IPv4 address. This is also
// the NAT-PMP discovery probe: an UNSUPPORTED_OPCODE or no response means
// no NAT-PMP gateway controls the first hop.
func (c *Client) PublicAddress(ctx context.Context) (netip.Addr, uint32, error) {
	request := make([]byte, PublicRequestSize)
	request[0] = Version
	request[1] = OpPublicAddress
	peer := net.UDPAddrFromAddrPort(c.server)
	for attempt := 1; attempt <= c.opts.MaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return netip.Addr{}, 0, err
		}
		if _, err := c.conn.WriteTo(request, peer); err != nil {
			return netip.Addr{}, 0, fmt.Errorf("natpmp: send: %w", err)
		}
		if result, err, done := c.awaitPublic(ctx); done {
			if err != nil {
				return netip.Addr{}, 0, err
			}
			return result.address, result.epoch, nil
		}
		if attempt < c.opts.MaxAttempts {
			select {
			case <-time.After(c.opts.Backoff):
			case <-ctx.Done():
				return netip.Addr{}, 0, ctx.Err()
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return netip.Addr{}, 0, err
	}
	return netip.Addr{}, 0, ErrNoResponse
}

// Map acquires one mapping. The requested external port is a suggestion:
// the response's assigned port is authoritative and is what callers must
// publish and journal.
func (c *Client) Map(ctx context.Context, req MapRequest) (MapResult, error) {
	return c.transaction(ctx, req)
}

// Renew renews an owned mapping. Weak ownership still requires the exact
// tuple this client acquired.
func (c *Client) Renew(ctx context.Context, mapping MapResult, lifetime time.Duration) (MapResult, error) {
	if mapping.InternalPort == 0 {
		return MapResult{}, ErrUnownedMapping
	}
	return c.transaction(ctx, MapRequest{
		Protocol:              mapping.Protocol,
		InternalPort:          mapping.InternalPort,
		RequestedExternalPort: mapping.AssignedExternalPort,
		Lifetime:              lifetime,
	})
}

// Delete removes an owned mapping: lifetime 0 with the exact tuple and the
// suggested external port zeroed (RFC 6886 §3.4). A mapping without an
// exact internal tuple is refused client-side.
func (c *Client) Delete(ctx context.Context, mapping MapResult) (MapResult, error) {
	if mapping.InternalPort == 0 {
		return MapResult{}, ErrUnownedMapping
	}
	return c.transaction(ctx, MapRequest{
		Protocol:     mapping.Protocol,
		InternalPort: mapping.InternalPort,
		// RFC 6886 §3.4: the delete request carries the suggested external
		// port as 0 — the gateway matches on (source, internal port).
		RequestedExternalPort: 0,
		Lifetime:              0, // delete
	})
}

// transaction sends one bounded MAP request/response cycle. Only transport
// timeouts retry; every result code is definitive.
func (c *Client) transaction(ctx context.Context, req MapRequest) (MapResult, error) {
	request, err := buildMapRequest(req)
	if err != nil {
		return MapResult{}, err
	}
	peer := net.UDPAddrFromAddrPort(c.server)
	for attempt := 1; attempt <= c.opts.MaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return MapResult{}, err
		}
		if _, err := c.conn.WriteTo(request, peer); err != nil {
			return MapResult{}, fmt.Errorf("natpmp: send: %w", err)
		}
		result, err, done := c.awaitMap(ctx, req)
		if done {
			if err != nil {
				return MapResult{}, err
			}
			return result, nil
		}
		if attempt < c.opts.MaxAttempts {
			select {
			case <-time.After(c.opts.Backoff):
			case <-ctx.Done():
				return MapResult{}, ctx.Err()
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return MapResult{}, err
	}
	return MapResult{}, ErrNoResponse
}

// awaitMap reads datagrams until the per-attempt deadline, filters to the
// exact server tuple, and classifies the first matching response.
// done=true with err==nil means success; done=true with err!=nil is a
// definitive failure; done=false means the attempt timed out.
func (c *Client) awaitMap(ctx context.Context, req MapRequest) (MapResult, error, bool) {
	deadline := c.deadline(ctx)
	for {
		if err := ctx.Err(); err != nil {
			return MapResult{}, err, true
		}
		if err := c.conn.SetReadDeadline(deadline); err != nil {
			return MapResult{}, err, true
		}
		buf := make([]byte, 1500)
		n, from, err := c.conn.ReadFrom(buf)
		if err != nil {
			return MapResult{}, errTransientRetry, false
		}
		if fromAddr, ok := addrPortOf(from); !ok || fromAddr != c.server {
			continue
		}
		response, err := parseMapResponse(buf[:n], req.Protocol.opcode(), req.InternalPort)
		if err != nil {
			// Malformed gateway response: definitive, never retried.
			return MapResult{}, err, true
		}
		if response.ResultCode != ResultSuccess {
			if sentinel, known := resultErrors[response.ResultCode]; known {
				return MapResult{}, sentinel, true
			}
			return MapResult{}, fmt.Errorf("natpmp: gateway failure, result code %d", response.ResultCode), true
		}
		return MapResult{
			Protocol:             req.Protocol,
			InternalPort:         req.InternalPort,
			AssignedExternalPort: response.AssignedExternalPort,
			Lifetime:             time.Duration(response.LifetimeSeconds) * time.Second,
			Epoch:                response.Epoch,
			ServerRebooted:       c.observeEpoch(response.Epoch),
		}, nil, true
	}
}

// awaitPublic is awaitMap for the public-address exchange.
func (c *Client) awaitPublic(ctx context.Context) (publicResult, error, bool) {
	deadline := c.deadline(ctx)
	var zero publicResult
	for {
		if err := ctx.Err(); err != nil {
			return zero, err, true
		}
		if err := c.conn.SetReadDeadline(deadline); err != nil {
			return zero, err, true
		}
		buf := make([]byte, 1500)
		n, from, err := c.conn.ReadFrom(buf)
		if err != nil {
			return zero, errTransientRetry, false
		}
		if fromAddr, ok := addrPortOf(from); !ok || fromAddr != c.server {
			continue
		}
		response, err := parsePublicResponse(buf[:n])
		if err != nil {
			return zero, err, true
		}
		if response.ResultCode != ResultSuccess {
			if sentinel, known := resultErrors[response.ResultCode]; known {
				return zero, sentinel, true
			}
			return zero, fmt.Errorf("natpmp: gateway failure, result code %d", response.ResultCode), true
		}
		c.observeEpoch(response.Epoch)
		return publicResult{address: response.Address, epoch: response.Epoch}, nil, true
	}
}

// errTransientRetry is the internal signal that the transaction may retry.
var errTransientRetry = errors.New("natpmp: transient failure, retry allowed")

// deadline computes the per-attempt read deadline.
func (c *Client) deadline(ctx context.Context) time.Time {
	deadline := time.Now().Add(c.opts.Timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	return deadline
}

// addrPortOf converts a packet source address to an AddrPort.
func addrPortOf(addr net.Addr) (netip.AddrPort, bool) {
	udp, ok := addr.(*net.UDPAddr)
	if !ok {
		return netip.AddrPort{}, false
	}
	ip, ok := netip.AddrFromSlice(udp.IP)
	if !ok {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(udp.Port)), true
}

// observeEpoch tracks server epoch across responses and reports a reboot on
// a backward jump beyond the 2s tolerance.
func (c *Client) observeEpoch(epoch uint32) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	reboot := false
	if c.sawEpoch && int64(epoch)-int64(c.lastEpoch) < -2 {
		reboot = true
	}
	c.lastEpoch = epoch
	c.sawEpoch = true
	return reboot
}
