// PCP adapter: bridges the wire client to the normalized
// traversal.GatewayMapper contract. Every transaction opens a short-lived
// UDP socket bound to the internal IP (PCP validates the request source
// address against the mapped client) and closes it after the exchange; the
// nonce in the mapping State is the only renewal/delete authority.
package pcp

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/traversal"
)

// AdapterOptions tune the adapter. Zero fields take client defaults.
type AdapterOptions struct {
	// Gateway is the PCP server endpoint; the default port is 5351. The
	// address is usually the IPv4 default gateway.
	Gateway netip.AddrPort
	// Timeout / MaxAttempts / Backoff pass through to the client.
	Timeout     time.Duration
	MaxAttempts int
	Backoff     time.Duration
}

// Adapter implements traversal.GatewayMapper over PCP.
type Adapter struct {
	gateway netip.AddrPort
	opts    ClientOptions

	// mu guards the cross-transaction epoch baseline: reboot detection
	// (RFC 6887 §8.5) compares each response against the PREVIOUS
	// response's epoch, which per-transaction sockets cannot remember on
	// their own.
	mu        sync.Mutex
	lastEpoch uint32
	epochSeen bool
}

// epochState snapshots the last observed server epoch for the next
// transaction's client.
func (a *Adapter) epochState() (uint32, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastEpoch, a.epochSeen
}

// observeEpoch records the epoch a transaction observed.
func (a *Adapter) observeEpoch(epoch uint32) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lastEpoch = epoch
	a.epochSeen = true
}

// NewAdapter builds the PCP adapter.
func NewAdapter(opts AdapterOptions) *Adapter {
	clientOpts := ClientOptions{
		Timeout:     opts.Timeout,
		MaxAttempts: opts.MaxAttempts,
		Backoff:     opts.Backoff,
	}
	gateway := opts.Gateway
	if !gateway.IsValid() {
		// Gateway address is required for real use; an invalid address
		// fails Discover rather than guessing the default gateway here.
		gateway = netip.AddrPort{}
	} else if gateway.Port() == 0 {
		gateway = netip.AddrPortFrom(gateway.Addr(), DefaultServerPort)
	}
	return &Adapter{gateway: gateway, opts: clientOpts}
}

// Mechanism reports the PCP layer kind.
func (a *Adapter) Mechanism() traversal.MappingLayerKind { return traversal.LayerPCP }

// Ownership reports STRONG_PROTOCOL_OWNERSHIP: the nonce is the authority.
func (a *Adapter) Ownership() traversal.OwnershipStrength { return traversal.OwnershipStrong }

// Capability reports the PCP port-control abilities.
func (a *Adapter) Capability() traversal.PortControlCapability {
	return traversal.PortControlCapabilityFor(traversal.LayerPCP, false)
}

// Discover probes the gateway with ANNOUNCE (no side effects).
func (a *Adapter) Discover(ctx context.Context) (traversal.ControlServer, error) {
	if !a.gateway.IsValid() {
		return traversal.ControlServer{}, fmt.Errorf("pcp: adapter has no gateway endpoint")
	}
	// RFC 6887 §8.2: the gateway validates the header client address
	// against the datagram source. Resolve the route-selected source for
	// the gateway first — a wildcard bind reports 0.0.0.0 in LocalAddr and
	// a compliant server answers ADDRESS_MISMATCH.
	source, err := resolveSourceIP(a.gateway.Addr())
	if err != nil {
		return traversal.ControlServer{}, err
	}
	conn, closeConn, err := a.dialOn(source)
	if err != nil {
		return traversal.ControlServer{}, err
	}
	defer closeConn()

	// The bound socket's source is the source the gateway sees.
	local, ok := localAddrOf(conn)
	if !ok {
		return traversal.ControlServer{}, fmt.Errorf("pcp: control socket has no IPv4 source")
	}
	if local != source {
		return traversal.ControlServer{}, fmt.Errorf("pcp: control socket bound %s, resolved source %s", local, source)
	}
	opts := a.opts
	opts.EpochBaseline, opts.EpochSeen = a.epochState()
	client := NewClient(conn, a.gateway, opts)
	epoch, err := client.Announce(ctx, local)
	if err != nil {
		return traversal.ControlServer{}, err
	}
	a.observeEpoch(epoch)
	return traversal.ControlServer{
		Mechanism: traversal.LayerPCP,
		Address:   a.gateway.String(),
	}, nil
}

// Map acquires one TCP mapping.
func (a *Adapter) Map(ctx context.Context, req traversal.GatewayMapRequest) (traversal.GatewayMapping, error) {
	conn, closeConn, err := a.dialOn(req.InternalIP)
	if err != nil {
		return traversal.GatewayMapping{}, err
	}
	defer closeConn()

	opts := a.opts
	opts.EpochBaseline, opts.EpochSeen = a.epochState()
	client := NewClient(conn, a.gateway, opts)
	result, err := client.Map(ctx, MapRequest{
		Protocol:              ProtoTCP,
		InternalAddress:       req.InternalIP,
		InternalPort:          req.InternalPort,
		SuggestedExternalPort: req.RequestedExternalPort,
		Lifetime:              req.Lease,
		PreferFailure:         req.StrictPort,
	})
	if err != nil {
		return traversal.GatewayMapping{}, err
	}
	a.observeEpoch(result.Epoch)
	return a.normalize(req, result), nil
}

// Renew extends the lease carrying the owning nonce.
func (a *Adapter) Renew(ctx context.Context, mapping traversal.GatewayMapping, lifetime time.Duration) (traversal.GatewayMapping, error) {
	state, ok := mapping.State.(MapResult)
	if !ok {
		return traversal.GatewayMapping{}, fmt.Errorf("pcp: renewal state %T is not a PCP mapping", mapping.State)
	}
	conn, closeConn, err := a.dialOn(mapping.InternalIP)
	if err != nil {
		return traversal.GatewayMapping{}, err
	}
	defer closeConn()

	opts := a.opts
	opts.EpochBaseline, opts.EpochSeen = a.epochState()
	client := NewClient(conn, a.gateway, opts)
	result, err := client.Renew(ctx, state, lifetime)
	if err != nil {
		return traversal.GatewayMapping{}, err
	}
	a.observeEpoch(result.Epoch)
	normalized := a.normalize(traversal.GatewayMapRequest{
		InternalIP:   mapping.InternalIP,
		InternalPort: mapping.InternalPort,
		Lease:        lifetime,
	}, result)
	return normalized, nil
}

// Delete releases the mapping carrying the owning nonce.
func (a *Adapter) Delete(ctx context.Context, mapping traversal.GatewayMapping) error {
	state, ok := mapping.State.(MapResult)
	if !ok {
		return fmt.Errorf("pcp: deletion state %T is not a PCP mapping", mapping.State)
	}
	conn, closeConn, err := a.dialOn(mapping.InternalIP)
	if err != nil {
		return err
	}
	defer closeConn()

	opts := a.opts
	opts.EpochBaseline, opts.EpochSeen = a.epochState()
	client := NewClient(conn, a.gateway, opts)
	result, err := client.Delete(ctx, state)
	if err == nil {
		a.observeEpoch(result.Epoch)
	}
	return err
}

// normalize renders the normalized mapping from one client result.
func (a *Adapter) normalize(req traversal.GatewayMapRequest, result MapResult) traversal.GatewayMapping {
	external := netip.AddrPortFrom(result.AssignedExternalAddress, result.AssignedExternalPort)
	return traversal.GatewayMapping{
		Mechanism:      traversal.LayerPCP,
		Ownership:      traversal.OwnershipStrong,
		InternalIP:     req.InternalIP,
		InternalPort:   req.InternalPort,
		External:       external,
		Lease:          result.Lifetime,
		Epoch:          result.Epoch,
		ServerRebooted: result.ServerRebooted,
		State:          result,
	}
}

// localAddrOf reads the socket's concrete IPv4 source address.
func localAddrOf(conn net.PacketConn) (netip.Addr, bool) {
	udp, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.Addr{}, false
	}
	ip, ok := netip.AddrFromSlice(udp.IP)
	if !ok {
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}

// dialOn opens a UDP socket bound to the internal IP so the gateway sees
// the mapped client address as the request source.
func (a *Adapter) dialOn(internalIP netip.Addr) (net.PacketConn, func(), error) {
	if !internalIP.IsValid() {
		return nil, nil, fmt.Errorf("pcp: mapping requires an internal IP")
	}
	conn, err := net.ListenPacket("udp4", internalIP.String()+":0")
	if err != nil {
		return nil, nil, fmt.Errorf("pcp: control socket on %s: %w", internalIP, err)
	}
	closeConn := func() { _ = conn.Close() }
	return conn, closeConn, nil
}

// resolveSourceIP returns the OS-selected source address for datagrams to
// the gateway: a connected UDP socket's LocalAddr reports the kernel's
// route choice without sending anything, unlike a wildcard bind's 0.0.0.0.
func resolveSourceIP(gateway netip.Addr) (netip.Addr, error) {
	if !gateway.IsValid() {
		return netip.Addr{}, fmt.Errorf("pcp: gateway address required for source resolution")
	}
	conn, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(gateway, DefaultServerPort)))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("pcp: source resolution toward %s: %w", gateway, err)
	}
	defer conn.Close()
	source, ok := localAddrOf(conn)
	if !ok || !source.IsValid() || source.IsUnspecified() {
		return netip.Addr{}, fmt.Errorf("pcp: no usable source address toward %s", gateway)
	}
	return source, nil
}
