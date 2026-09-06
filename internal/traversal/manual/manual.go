// Package manual implements the manual-static-v4 strategy layer: the
// operator supplies the expected public endpoint (cloud 1:1 NAT, DNAT,
// security-group or router static mapping), the Agent binds the local
// listener, and only an independent WAN probe against the operator endpoint
// verifies it. manual-static never participates in automatic detection and
// always starts as USER_CONFIGURED_UNTESTED (v0.8 §3.2).
package manual

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/gxbrave/AntiNAT-Agent/internal/traversal"
)

// Layer owns the manual-static-v4 acquisition path.
type Layer struct {
	registry *traversal.PortRegistry
	owner    string
}

// New builds the manual layer over the agent-global port registry.
func New(registry *traversal.PortRegistry, owner string) *Layer {
	return &Layer{registry: registry, owner: owner}
}

// Acquire binds the production listener and returns the lease plus the
// structured evidence whose candidate is the operator endpoint. The
// operator endpoint is mandatory: an empty endpoint refuses before any side
// effect (OPERATOR_ENDPOINT_REQUIRED).
func (l *Layer) Acquire(ctx context.Context, expectedEndpoint string, requestedPort uint16) (*traversal.Lease, traversal.LayerEvidence, error) {
	if strings.TrimSpace(expectedEndpoint) == "" {
		return nil, traversal.LayerEvidence{}, traversal.ErrOperatorEndpointRequired
	}
	endpoint, err := traversal.ParseManualEndpoint(expectedEndpoint)
	if err != nil {
		return nil, traversal.LayerEvidence{}, fmt.Errorf("manual: operator endpoint: %w", err)
	}

	lease, err := l.registry.Acquire(ctx, l.owner, traversal.TupleKey{
		Family:   "ipv4",
		Protocol: "tcp",
		Address:  "0.0.0.0",
		Port:     requestedPort,
	})
	if err != nil {
		return nil, traversal.LayerEvidence{}, fmt.Errorf("manual: port registry: %w", err)
	}
	evidence := traversal.LayerEvidence{
		Kind:             traversal.LayerKindManual,
		InternalEndpoint: netip.AddrPortFrom(netip.AddrFrom4([4]byte{}), lease.Actual.Port).String(),
		AssignedEndpoint: endpoint.String(),
		Scope:            traversal.ScopeOperatorInput,
		Ownership:        traversal.OwnershipNotApplicable,
		ParentLayer:      -1,
	}
	return lease, evidence, nil
}
