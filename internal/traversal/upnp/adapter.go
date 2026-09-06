// UPnP IGD adapter: bridges the SSDP/description/SOAP stack to the
// normalized traversal.GatewayMapper contract with
// BEST_EFFORT_QUERY_THEN_DELETE ownership. Discovery runs the full
// SSDP+description pipeline; the resolve seam is injectable for tests and
// for the netns lab (which drives discovery against a real miniupnpd).
package upnp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/traversal"
)

// AdapterOptions tune the adapter.
type AdapterOptions struct {
	// InterfaceIP pins SSDP multicast and description fetching to one
	// interface's IPv4 address.
	InterfaceIP netip.Addr
	// HTTPClient is the transport for description and SOAP calls; nil uses
	// a bounded default.
	HTTPClient *http.Client
	// Timeout bounds each HTTP round trip; default 5s.
	Timeout time.Duration
	// DiscoverWait is the per-target SSDP MX wait; default 2s.
	DiscoverWait time.Duration
}

// Adapter implements traversal.GatewayMapper over UPnP IGD.
type Adapter struct {
	ifaceIP  netip.Addr
	http     *http.Client
	opts     AdapterOptions
	resolve  func(ctx context.Context, a *Adapter) (Service, string, error)
	delegate *Client
	usn      string
}

// NewAdapter builds the UPnP adapter. Discovery uses the SSDP and
// description pipeline scoped to InterfaceIP. The description fetch runs on
// the same bounded transport as SOAP: an unbounded client must not hang
// discovery.
func NewAdapter(opts AdapterOptions) *Adapter {
	client := opts.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	bounded := *client
	if bounded.Timeout <= 0 {
		bounded.Timeout = opts.Timeout
		if bounded.Timeout <= 0 {
			bounded.Timeout = defaultHTTPTimeout
		}
	}
	adapter := &Adapter{ifaceIP: opts.InterfaceIP, http: &bounded, opts: opts}
	adapter.resolve = defaultResolve
	return adapter
}

// defaultResolve is the production pipeline: SSDP M-SEARCH on the interface,
// deterministic gateway selection, then the description fetch for the best
// control service.
func defaultResolve(ctx context.Context, a *Adapter) (Service, string, error) {
	gateways, err := Discover(ctx, DiscoverOptions{
		InterfaceIP: a.ifaceIP,
		Wait:        a.opts.DiscoverWait,
	})
	if err != nil {
		return Service{}, "", err
	}
	if len(gateways) == 0 {
		return Service{}, "", ErrDescriptionNotFound
	}
	gateway := gateways[0] // deterministic priority order
	service, err := FetchDescription(ctx, a.http, gateway.Location)
	if err != nil {
		return Service{}, "", err
	}
	return service, gateway.USN, nil
}

// Mechanism reports the UPnP IGD layer kind.
func (a *Adapter) Mechanism() traversal.MappingLayerKind { return traversal.LayerUPnP }

// Ownership reports BEST_EFFORT_QUERY_THEN_DELETE (v0.8 §3.4).
func (a *Adapter) Ownership() traversal.OwnershipStrength { return traversal.OwnershipBestEffort }

// Capability reports the IGDv1/v2 port-control abilities.
func (a *Adapter) Capability() traversal.PortControlCapability {
	return traversal.PortControlCapabilityFor(traversal.LayerUPnP, a.currentIGDv2())
}

// currentIGDv2 reports the resolved service version; unresolved adapters
// report the v1 (weaker) capability until discovery proves otherwise.
func (a *Adapter) currentIGDv2() bool {
	if a.delegate != nil {
		return a.delegate.World().IGDv2
	}
	return false
}

// Discover runs the SSDP + description pipeline and remembers the resolved
// service so Map/Delete reuse the same control endpoint.
func (a *Adapter) Discover(ctx context.Context) (traversal.ControlServer, error) {
	service, usn, err := a.resolve(ctx, a)
	if err != nil {
		return traversal.ControlServer{}, err
	}
	a.usn = usn
	a.delegate = NewClient(a.http, service, ClientOptions{Timeout: a.opts.Timeout})
	igdV2 := service.IGDv2
	return traversal.ControlServer{
		Mechanism: traversal.LayerUPnP,
		Address:   service.ControlURL,
		Identity:  usn,
		IGDv2:     igdV2,
	}, nil
}

// Map acquires one port mapping through the resolved service. Discovery is
// required first: an unresolved adapter fails rather than re-probing on
// every forward apply.
func (a *Adapter) Map(ctx context.Context, req traversal.GatewayMapRequest) (traversal.GatewayMapping, error) {
	if a.delegate == nil {
		return traversal.GatewayMapping{}, fmt.Errorf("upnp: adapter has no resolved gateway; run Discover first")
	}
	lease := req.Lease
	if lease <= 0 {
		lease = DefaultLease
	}
	result, err := a.delegate.Map(ctx, MapRequest{
		Protocol:              "TCP",
		InternalAddress:       req.InternalIP.String(),
		InternalPort:          req.InternalPort,
		RequestedExternalPort: req.RequestedExternalPort,
		Lease:                 lease,
		Description:           traversal.GatewayMapping{Identity: a.usn}.Description(),
	})
	if err != nil {
		return traversal.GatewayMapping{}, err
	}
	// Strict port policy is enforced against the device's answer: a
	// reservation that differs from the requested port fails the mapping,
	// and the entry just created (our description) is released instead of
	// leaking.
	if req.StrictPort && req.RequestedExternalPort != 0 && result.AssignedExternalPort != req.RequestedExternalPort {
		violation := fmt.Errorf("upnp: strict port policy violated: gateway assigned %d, requested %d",
			result.AssignedExternalPort, req.RequestedExternalPort)
		if deleteErr := a.delegate.Delete(ctx, result); deleteErr != nil {
			return traversal.GatewayMapping{}, errors.Join(violation, deleteErr)
		}
		return traversal.GatewayMapping{}, violation
	}
	// The SOAP add does not return the external IP; ask the gateway for it
	// so scope classification uses the real WAN address. A device without
	// the action leaves the address unspecified: the STUN layer or the
	// independent probe decides the scope then.
	result = a.fetchExternal(ctx, result)
	return a.normalize(req, result), nil
}

// Renew extends the lease for the mapping record.
func (a *Adapter) Renew(ctx context.Context, mapping traversal.GatewayMapping, lifetime time.Duration) (traversal.GatewayMapping, error) {
	if a.delegate == nil {
		return traversal.GatewayMapping{}, fmt.Errorf("upnp: adapter has no resolved gateway; run Discover first")
	}
	// IGD renewal is a re-add of the exact entry; query-then-delete
	// verification on release keeps the worst case bounded.
	result, err := a.delegate.Map(ctx, MapRequest{
		Protocol:              "TCP",
		InternalAddress:       mapping.InternalIP.String(),
		InternalPort:          mapping.InternalPort,
		RequestedExternalPort: mapping.External.Port(),
		Lease:                 lifetime,
		Description:           mapping.Description(),
	})
	if err != nil {
		return traversal.GatewayMapping{}, err
	}
	result = a.fetchExternal(ctx, result)
	if result.AssignedExternalPort != mapping.External.Port() {
		// The re-add landed on a different port: delete the stray entry
		// (our description) and fail — the live mapping must never silently
		// move.
		stray := fmt.Errorf("upnp: renewal reassigned the external port %d -> %d",
			mapping.External.Port(), result.AssignedExternalPort)
		if deleteErr := a.delegate.Delete(ctx, result); deleteErr != nil {
			return traversal.GatewayMapping{}, errors.Join(stray, deleteErr)
		}
		return traversal.GatewayMapping{}, stray
	}
	return a.normalize(traversal.GatewayMapRequest{
		InternalIP:   mapping.InternalIP,
		InternalPort: mapping.InternalPort,
		Lease:        lifetime,
	}, result), nil
}

// fetchExternal fills the SOAP result's external address from
// GetExternalIPAddress when the device supports it: scope classification and
// the journal must carry the real WAN address, never the unspecified
// fallback. This holds on the renewal path too.
func (a *Adapter) fetchExternal(ctx context.Context, result MapResult) MapResult {
	if externalAddr, err := a.delegate.ExternalAddress(ctx); err == nil && externalAddr.IsValid() {
		result.AssignedExternalAddress = externalAddr
	}
	return result
}

// Delete releases the mapping after query-then-delete verification.
func (a *Adapter) Delete(ctx context.Context, mapping traversal.GatewayMapping) error {
	if a.delegate == nil {
		return fmt.Errorf("upnp: adapter has no resolved gateway; run Discover first")
	}
	return a.delegate.Delete(ctx, MapResult{
		Protocol:             "TCP",
		InternalAddress:      mapping.InternalIP.String(),
		InternalPort:         mapping.InternalPort,
		AssignedExternalPort: mapping.External.Port(),
		Description:          mapping.Description(),
	})
}

// normalize renders the normalized mapping from one SOAP result. The
// external address comes from GetExternalIPAddress when the device supports
// it; otherwise it stays unspecified and scope classification defers to the
// STUN layer or the independent probe.
func (a *Adapter) normalize(req traversal.GatewayMapRequest, result MapResult) traversal.GatewayMapping {
	external := netip.AddrPortFrom(netip.AddrFrom4([4]byte{}), result.AssignedExternalPort)
	if result.AssignedExternalAddress.IsValid() {
		external = netip.AddrPortFrom(result.AssignedExternalAddress, result.AssignedExternalPort)
	}
	return traversal.GatewayMapping{
		Mechanism:    traversal.LayerUPnP,
		Ownership:    traversal.OwnershipBestEffort,
		InternalIP:   req.InternalIP,
		InternalPort: req.InternalPort,
		External:     external,
		Lease:        result.Lease,
		Identity:     a.usn,
		State:        result,
	}
}

// ErrNoGateway is the normalized "no IGD answered" outcome.
var ErrNoGateway = errors.New("upnp: no internet gateway device answered discovery")
