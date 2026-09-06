// Package traversal implements the Linux IPv4 direct-v4 foundations: route
// and source-interface selection with stable capability codes, the
// route/interface fingerprint, and the process-safe socket-owning
// PortRegistry (v0.8 §3.1, §4.1).
//
// direct-v4 succeeds only when the *selected* (default-route) interface
// itself holds a global IPv4; the candidate endpoint is that global source
// IPv4 plus the actual bound port, and WAN reachability is always verified
// later by an independent probe. Capability assessment is a pure function of
// the route table, so identical route state always returns identical codes.
package traversal

import (
	"errors"
	"net/netip"
	"sort"
)

// IPv4Address is one IPv4 address observed on one interface.
type IPv4Address struct {
	Interface string
	Addr      netip.Addr
}

// Selection is the direct-v4 source selection: the concrete global source
// IPv4 on the default-route interface.
type Selection struct {
	Source                netip.Addr
	Interface             string
	DefaultRouteGateway   netip.Addr
	DefaultRouteInterface string
	Global                bool
}

// Capability is a stable direct-v4 capability code (v0.8 §3.1 step 1). The
// code is a pure function of the route table: no-v4, no-default-route,
// private-only source, and ready all map deterministically.
type Capability string

const (
	CapabilityDirectV4Ready             Capability = "DIRECT_V4_READY"
	CapabilityV4SourceUnavailable       Capability = "V4_SOURCE_UNAVAILABLE"
	CapabilityV4DefaultRouteUnavailable Capability = "V4_DEFAULT_ROUTE_UNAVAILABLE"
	CapabilityNoGlobalV4Source          Capability = "NO_GLOBAL_V4_SOURCE"
)

// Sentinel errors for the stable capability codes. CapabilityError preserves
// the stable capability code while retaining the underlying cause for callers
// and logs. It prevents all topology failures from collapsing into
// NO_GLOBAL_V4_SOURCE at the data-plane boundary.
type CapabilityError struct {
	Capability Capability
	Err        error
}

func (e *CapabilityError) Error() string { return string(e.Capability) + ": " + e.Err.Error() }
func (e *CapabilityError) Unwrap() error { return e.Err }

func NewCapabilityError(capability Capability, err error) error {
	if err == nil {
		err = errors.New(string(capability))
	}
	return &CapabilityError{Capability: capability, Err: err}
}

var (
	ErrV4SourceUnavailable       = errors.New("traversal: no IPv4 source address available")
	ErrV4DefaultRouteUnavailable = errors.New("traversal: no IPv4 default route")
	ErrNoGlobalV4Source          = errors.New("traversal: selected interface has no global IPv4 source")
	// ErrInternalSourceUnavailable refuses a default-route interface without
	// any usable IPv4 source address for gateway mapping.
	ErrInternalSourceUnavailable = errors.New("traversal: default-route interface has no usable IPv4 source address")
)

// RouteTable is the host routing state the assessment is a pure function of.
// RouteTableReader failures must be surfaced, never guessed.
type RouteTable interface {
	// DefaultRouteV4 returns the gateway and interface of the IPv4 default
	// route; ok=false means the host has no IPv4 default route.
	DefaultRouteV4() (gateway netip.Addr, iface string, ok bool, err error)
	// IPv4Addresses lists every IPv4 address with its interface.
	IPv4Addresses() ([]IPv4Address, error)
}

// nonGlobalV4Prefixes are the IANA-assigned ranges that are never a valid
// global direct-v4 source even though netip does not classify them as
// private/link-local/loopback: RFC 6598 CGNAT, IETF protocol assignments,
// the three documentation TEST-NET ranges, benchmarking, reserved space,
// the deprecated 6to4 relay anycast, and the special-purpose AS112/AMT
// service prefixes.
var nonGlobalV4Prefixes = []netip.Prefix{
	mustPrefix("0.0.0.0/8"),
	mustPrefix("100.64.0.0/10"),
	mustPrefix("192.0.0.0/24"),
	mustPrefix("192.0.2.0/24"),
	mustPrefix("192.31.196.0/24"), // direct delegation AS112 (RFC 7534)
	mustPrefix("192.52.193.0/24"), // AMT default relay (RFC 7450)
	mustPrefix("192.88.99.0/24"),  // deprecated 6to4 relay anycast (RFC 7526)
	mustPrefix("192.175.48.0/24"), // direct delegation AS112 (RFC 7534)
	mustPrefix("198.18.0.0/15"),
	mustPrefix("198.51.100.0/24"),
	mustPrefix("203.0.113.0/24"),
	mustPrefix("240.0.0.0/4"),
}

func mustPrefix(text string) netip.Prefix {
	prefix, err := netip.ParsePrefix(text)
	if err != nil {
		panic(err)
	}
	return prefix
}

// IsGlobalV4 reports whether addr is a concrete global IPv4 that can serve
// as a direct-v4 source: not unspecified, loopback, multicast, link-local,
// RFC 1918, CGNAT, documentation, benchmarking, or reserved space.
func IsGlobalV4(addr netip.Addr) bool {
	if !addr.Is4() || addr.IsUnspecified() || addr.IsLoopback() || addr.IsMulticast() ||
		addr.IsLinkLocalUnicast() || addr.IsPrivate() {
		return false
	}
	for _, prefix := range nonGlobalV4Prefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

// sortedIPv4Addresses returns the reader's addresses in the deterministic
// interface-then-address order: address order from the reader must not
// matter to either selection function.
func sortedIPv4Addresses(addrs []IPv4Address) []IPv4Address {
	sorted := append([]IPv4Address(nil), addrs...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Interface != sorted[j].Interface {
			return sorted[i].Interface < sorted[j].Interface
		}
		return sorted[i].Addr.Compare(sorted[j].Addr) < 0
	})
	return sorted
}

// Assess returns the direct-v4 source selection and its stable capability
// code for the given route table. A reader failure is returned as err with
// an empty capability; a missing capability maps to one of the three
// sentinel errors.
func Assess(rt RouteTable) (Selection, Capability, error) {
	addrs, err := rt.IPv4Addresses()
	if err != nil {
		return Selection{}, "", err
	}
	if len(addrs) == 0 {
		return Selection{}, CapabilityV4SourceUnavailable, ErrV4SourceUnavailable
	}
	gateway, iface, ok, err := rt.DefaultRouteV4()
	if err != nil {
		return Selection{}, "", err
	}
	if !ok {
		return Selection{}, CapabilityV4DefaultRouteUnavailable, ErrV4DefaultRouteUnavailable
	}

	// Only the selected (default-route) interface counts: its traffic is the
	// only traffic that egresses via the default route, so a global address
	// on another interface is not a valid direct-v4 source.
	for _, candidate := range sortedIPv4Addresses(addrs) {
		if candidate.Interface == iface && IsGlobalV4(candidate.Addr) {
			return Selection{
				Source:                candidate.Addr,
				Interface:             candidate.Interface,
				DefaultRouteGateway:   gateway,
				DefaultRouteInterface: iface,
				Global:                true,
			}, CapabilityDirectV4Ready, nil
		}
	}
	return Selection{}, CapabilityNoGlobalV4Source, ErrNoGlobalV4Source
}

// DefaultRouteSource returns the concrete IPv4 address on the default-route
// interface — private or global — for the gateway strategies (v0.8 §3.2).
// Gateway traversal maps the address the first-hop gateway sees, which
// behind a NAT CPE is private by definition: the global-only Assess rule
// governs direct-v4 only and must not gate the gateway strategies. A
// private source is still reported with Global=false so evidence keeps the
// distinction. Loopback, link-local, multicast and unspecified addresses
// are never valid mapping sources.
func DefaultRouteSource(rt RouteTable) (Selection, error) {
	addrs, err := rt.IPv4Addresses()
	if err != nil {
		return Selection{}, err
	}
	if len(addrs) == 0 {
		return Selection{}, ErrV4SourceUnavailable
	}
	gateway, iface, ok, err := rt.DefaultRouteV4()
	if err != nil {
		return Selection{}, err
	}
	if !ok {
		return Selection{}, ErrV4DefaultRouteUnavailable
	}
	for _, candidate := range sortedIPv4Addresses(addrs) {
		if candidate.Interface == iface && isValidMappingSource(candidate.Addr) {
			return Selection{
				Source:                candidate.Addr,
				Interface:             candidate.Interface,
				DefaultRouteGateway:   gateway,
				DefaultRouteInterface: iface,
				Global:                IsGlobalV4(candidate.Addr),
			}, nil
		}
	}
	return Selection{}, ErrInternalSourceUnavailable
}

// isValidMappingSource reports whether addr can be named to a first-hop
// gateway as the internal side of a mapping. CGNAT and RFC 1918 are valid
// here: they are ordinary interface addresses a NAT gateway sees.
func isValidMappingSource(addr netip.Addr) bool {
	return addr.Is4() && !addr.IsUnspecified() && !addr.IsLoopback() &&
		!addr.IsMulticast() && !addr.IsLinkLocalUnicast()
}
