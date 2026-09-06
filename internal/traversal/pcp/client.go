// PCP MAP client with strong protocol ownership (v0.8 §3.4): the 12-byte
// nonce is the only delete/renew authority, is generated with crypto/rand by
// default, and every success response is verified to echo it. Result codes
// classify exactly per RFC 6887 §7.4: only transient codes (>= 128) and
// transport timeouts retry; permanent codes and protocol violations fail
// immediately. Epoch tracking detects gateway reboots so callers can
// invalidate publications (state-model §5).
package pcp

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Result-code sentinel errors (permanent failures).
var (
	ErrUnsupportedVersion    = errors.New("pcp: gateway does not support PCP v2")
	ErrNotAuthorized         = errors.New("pcp: gateway denied the mapping (NOT_AUTHORIZED)")
	ErrMalformedRequest      = errors.New("pcp: gateway rejected the request as malformed")
	ErrUnsupportedOpcode     = errors.New("pcp: gateway does not implement the MAP opcode")
	ErrUnsupportedOption     = errors.New("pcp: gateway rejected PREFER_FAILURE")
	ErrNetworkFailure        = errors.New("pcp: gateway reported a network failure")
	ErrNoResources           = errors.New("pcp: gateway is out of mapping resources")
	ErrUnsupportedProtocol   = errors.New("pcp: gateway does not support this protocol")
	ErrUserExQuota           = errors.New("pcp: gateway quota exceeded for this client")
	ErrCannotProvideExternal = errors.New("pcp: gateway cannot provide the exact external port")
	ErrAddressMismatch       = errors.New("pcp: gateway reports an address mismatch")
	ErrExcessiveRemotePeers  = errors.New("pcp: gateway reports excessive remote peers")
)

// Ownership and transport errors.
var (
	// ErrNonceMismatch is a protocol violation: the response did not echo
	// the request nonce. It is never retried and the result is never
	// treated as belonging to this client.
	ErrNonceMismatch = errors.New("pcp: response nonce does not match the request nonce")
	// ErrUnownedMapping refuses deletes/renews that do not carry an exact
	// internal tuple: v1 never provides a delete-all operation.
	ErrUnownedMapping = errors.New("pcp: mapping lacks an exact internal tuple; refusing to send")
	// ErrPreferFailureRequiresPort refuses exact-port requests that do not
	// name the port.
	ErrPreferFailureRequiresPort = errors.New("pcp: PREFER_FAILURE requires a suggested external port")
	// ErrNoResponse exhausts the bounded retry budget without a usable
	// response.
	ErrNoResponse = errors.New("pcp: gateway did not respond within the retry budget")
)

// resultErrors maps permanent base result codes to their sentinel errors.
var resultErrors = map[byte]error{
	ResultUnsupportedVersion:    ErrUnsupportedVersion,
	ResultNotAuthorized:         ErrNotAuthorized,
	ResultMalformedRequest:      ErrMalformedRequest,
	ResultUnsupportedOpcode:     ErrUnsupportedOpcode,
	ResultUnsupportedOption:     ErrUnsupportedOption,
	ResultMalformedOption:       ErrMalformedRequest,
	ResultNetworkFailure:        ErrNetworkFailure,
	ResultNoResources:           ErrNoResources,
	ResultUnsupportedProtocol:   ErrUnsupportedProtocol,
	ResultUserExQuota:           ErrUserExQuota,
	ResultCannotProvideExternal: ErrCannotProvideExternal,
	ResultAddressMismatch:       ErrAddressMismatch,
	ResultExcessiveRemotePeers:  ErrExcessiveRemotePeers,
}

// MapRequest is one MAP acquire/renew/delete request. Lifetime 0 is a
// delete; use Delete instead of building it by hand.
type MapRequest struct {
	Protocol              byte // ProtoTCP or ProtoUDP
	InternalAddress       netip.Addr
	InternalPort          uint16
	SuggestedExternalPort uint16 // 0 = any
	Lifetime              time.Duration
	// PreferFailure demands the exact suggested external port. Requires a
	// non-zero SuggestedExternalPort.
	PreferFailure bool
}

// MapResult is the gateway-granted mapping. The Nonce is the strong
// ownership state: persist it (mapping journal) — only its holder may
// renew or delete the mapping.
type MapResult struct {
	Nonce                   [12]byte
	Protocol                byte
	InternalAddress         netip.Addr
	InternalPort            uint16
	AssignedExternalPort    uint16
	AssignedExternalAddress netip.Addr
	Lifetime                time.Duration
	Epoch                   uint32
	// ServerRebooted is true when the response epoch rolled back beyond the
	// RFC 6887 §8.5 tolerance: the gateway may have lost every mapping and
	// publication state must go stale.
	ServerRebooted bool
}

// ClientOptions tunes the bounded client. Zero fields take defaults.
type ClientOptions struct {
	// Timeout is the per-attempt response budget; default 2s.
	Timeout time.Duration
	// MaxAttempts bounds total sends per transaction; default 3.
	MaxAttempts int
	// Backoff is the delay between attempts; default 500ms.
	Backoff time.Duration
	// Nonce generates MAP nonces; default crypto/rand. Test seam only —
	// production must never inject a deterministic generator.
	Nonce func() ([12]byte, error)
	// EpochBaseline / EpochSeen carry the adapter's cross-transaction epoch
	// baseline: reboot detection compares a response against the PREVIOUS
	// response's epoch (RFC 6887 §8.5), which a per-transaction client
	// cannot know on its own. The adapter snapshots the baseline before
	// every transaction and records the observed epoch after it.
	EpochBaseline uint32
	EpochSeen     bool
}

// Client is a single-transaction PCP client over UDP. It owns no socket:
// the PacketConn is injected and closed by the caller. Transaction state
// (last observed server epoch) is protected for concurrent use.
type Client struct {
	conn   net.PacketConn
	server netip.AddrPort
	opts   ClientOptions

	mu        sync.Mutex
	lastEpoch uint32
	sawEpoch  bool
}

// NewClient validates nothing about reachability (that is the first
// transaction's job) and returns a client bound to the gateway endpoint.
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
	if opts.Nonce == nil {
		opts.Nonce = cryptoRandNonce
	}
	return &Client{
		conn:      conn,
		server:    server,
		opts:      opts,
		lastEpoch: opts.EpochBaseline,
		sawEpoch:  opts.EpochSeen,
	}
}

func cryptoRandNonce() ([12]byte, error) {
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nonce, fmt.Errorf("pcp: nonce generation: %w", err)
	}
	return nonce, nil
}

// Announce probes gateway reachability with no side effects (RFC 6887
// §8.4). This is the PCP discovery probe: success carries the server epoch;
// UNSUPPORTED_VERSION or silence means no PCP gateway controls the first
// hop.
func (c *Client) Announce(ctx context.Context, clientAddr netip.Addr) (uint32, error) {
	packet, err := buildAnnounceRequest(clientAddr)
	if err != nil {
		return 0, err
	}
	peer := net.UDPAddrFromAddrPort(c.server)
	for attempt := 1; attempt <= c.opts.MaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if _, err := c.conn.WriteTo(packet, peer); err != nil {
			return 0, fmt.Errorf("pcp: send: %w", err)
		}
		epoch, err, done := c.awaitAnnounce(ctx, clientAddr)
		if done {
			if err != nil {
				return 0, err
			}
			return epoch, nil
		}
		if attempt < c.opts.MaxAttempts {
			select {
			case <-time.After(c.opts.Backoff):
			case <-ctx.Done():
				return 0, ctx.Err()
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return 0, ErrNoResponse
}

// awaitAnnounce is the ANNOUNCE counterpart of awaitMap.
func (c *Client) awaitAnnounce(ctx context.Context, clientAddr netip.Addr) (uint32, error, bool) {
	deadline := time.Now().Add(c.opts.Timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	for {
		if err := ctx.Err(); err != nil {
			return 0, err, true
		}
		if err := c.conn.SetReadDeadline(deadline); err != nil {
			return 0, err, true
		}
		buf := make([]byte, 1500)
		n, from, err := c.conn.ReadFrom(buf)
		if err != nil {
			return 0, errTransientRetry, false
		}
		if fromAddr, ok := addrPortOf(from); !ok || fromAddr != c.server {
			continue
		}
		response, err := parseAnnounceResponse(buf[:n])
		if err != nil {
			return 0, err, true
		}
		if response.ResultCode != ResultSuccess {
			if TransientResult(response.ResultCode) {
				return 0, errTransientRetry, false
			}
			if sentinel, known := resultErrors[response.ResultCode]; known {
				return 0, sentinel, true
			}
			return 0, fmt.Errorf("pcp: gateway permanent failure, result code %d", response.ResultCode), true
		}
		c.observeEpoch(response.Epoch)
		return response.Epoch, nil, true
	}
}

// Map acquires or renews one mapping with a fresh nonce. The caller persists
// the returned nonce (mapping journal) as the ownership state.
func (c *Client) Map(ctx context.Context, req MapRequest) (MapResult, error) {
	nonce, err := c.opts.Nonce()
	if err != nil {
		return MapResult{}, fmt.Errorf("pcp: %w", err)
	}
	return c.transaction(ctx, req, nonce)
}

// Delete removes an owned mapping: lifetime 0 with the owning nonce and the
// assigned external port. A mapping without an exact internal tuple is
// refused client-side (v1 never provides delete-all).
func (c *Client) Delete(ctx context.Context, mapping MapResult) (MapResult, error) {
	if mapping.InternalPort == 0 {
		return MapResult{}, ErrUnownedMapping
	}
	req := MapRequest{
		Protocol:              mapping.Protocol,
		InternalAddress:       mapping.InternalAddress,
		InternalPort:          mapping.InternalPort,
		SuggestedExternalPort: mapping.AssignedExternalPort,
		Lifetime:              0, // delete
	}
	return c.transaction(ctx, req, mapping.Nonce)
}

// Renew renews an owned mapping with the owning nonce: strong ownership
// requires every lifetime extension to prove possession of the nonce.
func (c *Client) Renew(ctx context.Context, mapping MapResult, lifetime time.Duration) (MapResult, error) {
	if mapping.InternalPort == 0 {
		return MapResult{}, ErrUnownedMapping
	}
	req := MapRequest{
		Protocol:              mapping.Protocol,
		InternalAddress:       mapping.InternalAddress,
		InternalPort:          mapping.InternalPort,
		SuggestedExternalPort: mapping.AssignedExternalPort,
		Lifetime:              lifetime,
	}
	return c.transaction(ctx, req, mapping.Nonce)
}

// transaction sends one bounded request/response cycle. Retry rules:
// transport timeouts and transient result codes (>= 128) retry; permanent
// result codes, protocol violations and malformed datagrams are definitive.
func (c *Client) transaction(ctx context.Context, req MapRequest, nonce [12]byte) (MapResult, error) {
	packet, err := buildMapRequest(req, nonce)
	if err != nil {
		return MapResult{}, err
	}
	peer := net.UDPAddrFromAddrPort(c.server)

	for attempt := 1; attempt <= c.opts.MaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return MapResult{}, err
		}
		if _, err := c.conn.WriteTo(packet, peer); err != nil {
			return MapResult{}, fmt.Errorf("pcp: send: %w", err)
		}
		result, err := c.awaitResponse(ctx, req, nonce)
		switch {
		case err == nil:
			return result, nil
		case errors.Is(err, errTransientRetry):
			// fall through to backoff + retry
		default:
			return result, err
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

// errTransientRetry is the internal signal that the transaction may retry:
// transport timeouts and transient result codes (>= 128).
var errTransientRetry = errors.New("pcp: transient failure, retry allowed")

// awaitResponse reads datagrams until the per-attempt deadline, filters to
// the exact server tuple, and classifies the first matching response:
// (result, nil) success; (zero, errTransientRetry) retry-worthy; (zero, err)
// definitive failure.
func (c *Client) awaitResponse(ctx context.Context, req MapRequest, nonce [12]byte) (MapResult, error) {
	deadline := time.Now().Add(c.opts.Timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	for {
		if err := ctx.Err(); err != nil {
			return MapResult{}, err
		}
		if err := c.conn.SetReadDeadline(deadline); err != nil {
			return MapResult{}, err
		}
		buf := make([]byte, 1500)
		n, from, err := c.conn.ReadFrom(buf)
		if err != nil {
			// Per-attempt timeout or transient socket error: retry.
			return MapResult{}, errTransientRetry
		}
		if fromAddr, ok := addrPortOf(from); !ok || fromAddr != c.server {
			continue // not the gateway's datagram
		}
		response, err := parseMapResponse(buf[:n], req.Protocol, req.InternalPort)
		if err != nil {
			// Malformed gateway response: definitive, never retried.
			return MapResult{}, err
		}
		if response.ResultCode != ResultSuccess {
			if TransientResult(response.ResultCode) {
				return MapResult{}, errTransientRetry
			}
			if sentinel, known := resultErrors[response.ResultCode]; known {
				return MapResult{}, sentinel
			}
			return MapResult{}, fmt.Errorf("pcp: gateway permanent failure, result code %d", response.ResultCode)
		}
		if response.Nonce != nonce {
			return MapResult{}, ErrNonceMismatch
		}
		result := MapResult{
			Nonce:                   response.Nonce,
			Protocol:                req.Protocol,
			InternalAddress:         req.InternalAddress,
			InternalPort:            req.InternalPort,
			AssignedExternalPort:    response.AssignedExternalPort,
			AssignedExternalAddress: response.AssignedExternalAddress,
			Lifetime:                time.Duration(response.LifetimeSeconds) * time.Second,
			Epoch:                   response.Epoch,
			ServerRebooted:          c.observeEpoch(response.Epoch),
		}
		return result, nil
	}
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
// a backward jump beyond the 2s RFC tolerance.
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
