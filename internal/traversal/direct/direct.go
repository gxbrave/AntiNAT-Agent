// Package direct implements the direct-v4 strategy layer: the candidate
// endpoint is the global source IPv4 on the default-route interface plus the
// actual bound port, and only an independent WAN probe may verify it
// (v0.8 §3.1). A source that is RFC1918/CGNAT/link-local or a missing
// default route yields the stable capability codes — direct-v4 never guesses
// a public endpoint from an address-reflecting service.
package direct

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/gxbrave/AntiNAT-Agent/internal/traversal"
)

// Layer owns the direct-v4 acquisition path for one agent.
type Layer struct {
	routeTable traversal.RouteTable
	registry   *traversal.PortRegistry
	owner      string
}

// New builds the direct layer over the host route table and the agent-global
// port registry.
func New(routeTable traversal.RouteTable, registry *traversal.PortRegistry, owner string) *Layer {
	return &Layer{routeTable: routeTable, registry: registry, owner: owner}
}

// Assess returns the direct-v4 source selection with its stable capability
// code (DIRECT_V4_READY, NO_GLOBAL_V4_SOURCE, V4_SOURCE_UNAVAILABLE,
// V4_DEFAULT_ROUTE_UNAVAILABLE).
func (l *Layer) Assess() (traversal.Selection, traversal.Capability, error) {
	return traversal.Assess(l.routeTable)
}

// Acquire binds the production listener on the global source address inside
// the port registry and returns the lease plus the structured evidence. The
// candidate endpoint is the global source plus the actual bound port: scope
// is GLOBAL_PUBLIC and only the independent WAN probe publishes.
func (l *Layer) Acquire(ctx context.Context, requestedPort uint16) (*traversal.Lease, traversal.LayerEvidence, error) {
	selection, capability, err := traversal.Assess(l.routeTable)
	if err != nil {
		if capability == "" {
			return nil, traversal.LayerEvidence{}, fmt.Errorf("direct: route assessment: %w", err)
		}
		return nil, traversal.LayerEvidence{}, traversal.NewCapabilityError(capability, err)
	}
	if !selection.Global {
		return nil, traversal.LayerEvidence{}, traversal.NewCapabilityError(
			traversal.CapabilityNoGlobalV4Source,
			fmt.Errorf("selected interface %s has no global IPv4 source", selection.Interface),
		)
	}
	lease, err := l.registry.Acquire(ctx, l.owner, traversal.TupleKey{
		Family:   "ipv4",
		Protocol: "tcp",
		Address:  selection.Source.String(),
		Port:     requestedPort,
	})
	if err != nil {
		return nil, traversal.LayerEvidence{}, fmt.Errorf("direct: port registry: %w", err)
	}
	candidate := netip.AddrPortFrom(selection.Source, lease.Actual.Port)
	evidence := traversal.LayerEvidence{
		Kind:             traversal.LayerKindDirect,
		ControlServer:    "",
		InternalEndpoint: candidate.String(),
		AssignedEndpoint: candidate.String(),
		Scope:            traversal.ScopeGlobalPublic,
		Ownership:        traversal.OwnershipNotApplicable,
		ParentLayer:      -1,
	}
	return lease, evidence, nil
}
