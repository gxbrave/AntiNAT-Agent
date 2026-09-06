// Layered strategy contract (v0.8 plan §3.1–§3.4).
//
// Strategy is a pipeline, not a mode switch: v1 allows at most one explicit
// gateway mapping layer (PCP | NAT-PMP | UPnP IGD) plus one transport-correct
// observed STUN layer on the same source tuple. This file owns the frozen
// classification rules the adapters must obey:
//
//   - a non-global gateway-assigned endpoint is FIRST_HOP only and never a
//     public candidate (mapping_state=FIRST_HOP_MAPPED);
//   - multiple explicit NAT control layers are rejected, never merged;
//   - a fixed strategy fails without silent fallback; `auto` walks its
//     declared ordered list;
//   - gateway_port_policy and final_endpoint_constraint are separate
//     constraints evaluated at their own layer;
//   - every mechanism declares an honest PortControlCapability.
//
// The frozen ForwardSpec (P04) carries the strategy, requested ports and the
// manual endpoint but deliberately does not carry the mapping mechanism: the
// concrete layer is resolved from the node detection profile by the caller
// (Manager), because only the Agent observes which gateway protocol actually
// responds. Planning therefore takes the resolved layer as input.
package traversal

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
)

// MappingLayerKind is one explicit gateway mapping mechanism.
type MappingLayerKind string

const (
	LayerPCP    MappingLayerKind = "pcp"
	LayerNATPMP MappingLayerKind = "nat-pmp"
	LayerUPnP   MappingLayerKind = "upnp-igd"
)

// Valid reports whether the kind is a known explicit gateway mechanism.
func (k MappingLayerKind) Valid() bool {
	switch k {
	case LayerPCP, LayerNATPMP, LayerUPnP:
		return true
	}
	return false
}

// LayerKind classifies one evidence layer of the pipeline.
type LayerKind string

const (
	LayerKindDirect  LayerKind = "direct"  // global source on the selected interface
	LayerKindManual  LayerKind = "manual"  // operator-declared expected endpoint
	LayerKindGateway LayerKind = "gateway" // explicit NAT control layer
	LayerKindSTUN    LayerKind = "stun"    // observed layer on the same tuple
)

// EndpointScope classifies a candidate endpoint's reachability scope. Only a
// GLOBAL_PUBLIC candidate may proceed to an independent WAN probe, and only
// OPEN_FROM_VANTAGE drives a verified publication (state-model §1).
type EndpointScope string

const (
	ScopeGlobalPublic  EndpointScope = "GLOBAL_PUBLIC"
	ScopeFirstHop      EndpointScope = "FIRST_HOP"
	ScopeOperatorInput EndpointScope = "OPERATOR_EXPECTED"
	ScopeNonRoutable   EndpointScope = "NON_ROUTABLE"
)

// PortPolicy is the per-layer port policy (v0.8 §3.3). Gateway port policy
// and final endpoint constraint are saved and evaluated separately.
type PortPolicy string

const (
	PortPolicyStrict         PortPolicy = "strict"          // the requested port must be honored
	PortPolicyAcceptAny      PortPolicy = "accept_any"      // gateway may assign; bounded retry, no scan
	PortPolicyAcceptAssigned PortPolicy = "accept_assigned" // final observed/assigned port accepted
)

// PortControlCapability is the per-layer port ability declaration
// (v0.8 §3.3 PortControlCapability struct).
type PortControlCapability struct {
	Mechanism               MappingLayerKind
	CanRequestExact         bool
	CanAcceptAssigned       bool
	CanRetryCandidate       bool
	FinalEndpointConstraint PortPolicy
}

// OwnershipStrength is the honest mapping ownership classification
// (v0.8 §3.4). The journal records it verbatim; nothing may advertise a
// weaker mechanism as crash-safe strong ownership.
type OwnershipStrength string

const (
	OwnershipStrong        OwnershipStrength = "STRONG_PROTOCOL_OWNERSHIP"     // PCP nonce
	OwnershipWeakLease     OwnershipStrength = "WEAK_LEASE_OWNERSHIP"          // NAT-PMP
	OwnershipBestEffort    OwnershipStrength = "BEST_EFFORT_QUERY_THEN_DELETE" // UPnP IGD
	OwnershipObservedOnly  OwnershipStrength = "OBSERVED_ONLY"                 // STUN layer, no control
	OwnershipNotApplicable OwnershipStrength = "NOT_APPLICABLE"                // direct/manual
)

// Stable strategy-layer failure codes. These are Agent-side pipeline codes,
// not the frozen API error registry.
const (
	CodeUnsupportedMultipleExplicitLayers = "UNSUPPORTED_MULTIPLE_EXPLICIT_NAT_LAYERS"
	CodeFinalPortRewritten                = "FINAL_PORT_REWRITTEN"
	CodeNoViableStrategy                  = "NO_VIABLE_STRATEGY"
	CodeLayerCannotRequestExact           = "LAYER_CANNOT_REQUEST_EXACT"
	CodeOperatorEndpointRequired          = "OPERATOR_ENDPOINT_REQUIRED"
)

// StrategyError carries a stable pipeline code alongside its cause.
type StrategyError struct {
	Code string
	Err  error
}

func (e *StrategyError) Error() string {
	if e.Err == nil {
		return "traversal: " + e.Code
	}
	return "traversal: " + e.Code + ": " + e.Err.Error()
}
func (e *StrategyError) Unwrap() error { return e.Err }

// Stable sentinel errors wrapping the codes above.
var (
	ErrUnsupportedMultipleExplicitLayers = &StrategyError{
		Code: CodeUnsupportedMultipleExplicitLayers,
		Err:  errors.New("at most one explicit mapping layer is supported in v1"),
	}
	ErrFinalPortRewritten = &StrategyError{
		Code: CodeFinalPortRewritten,
		Err:  errors.New("upstream observation rewrote the final port under a strict final constraint"),
	}
	ErrNoViableStrategy = &StrategyError{
		Code: CodeNoViableStrategy,
		Err:  errors.New("no strategy in the ordered list succeeded"),
	}
	ErrLayerCannotRequestExact = &StrategyError{
		Code: CodeLayerCannotRequestExact,
		Err:  errors.New("mechanism cannot honor an exact gateway port request"),
	}
	ErrOperatorEndpointRequired = &StrategyError{
		Code: CodeOperatorEndpointRequired,
		Err:  errors.New("manual-static-v4 requires the operator-declared expected endpoint"),
	}
)

// LayerEvidence is the structured per-layer record (v0.8 §3.1 step 4): every
// layer saves its control server, internal/assigned endpoints, scope, lease,
// epoch, ownership strength and parent layer.
type LayerEvidence struct {
	Kind             LayerKind
	Mechanism        MappingLayerKind // empty for direct/manual/stun layers
	ControlServer    string
	InternalEndpoint string
	AssignedEndpoint string
	Scope            EndpointScope
	LeaseLifetime    time.Duration // 0 = none/unknown
	Epoch            uint32
	Ownership        OwnershipStrength
	ParentLayer      int // index into the layer slice, -1 = root
	Note             string
}

// PipelineVerdict is the classification of a completed layer chain.
type PipelineVerdict struct {
	// Candidate is the best endpoint the chain produced. It is the STUN
	// observed endpoint when present, else the gateway/manual/direct
	// assigned endpoint.
	Candidate netip.AddrPort
	Scope     EndpointScope
	// PublicCandidate reports whether the candidate is a global-class
	// address eligible for an independent WAN probe. FIRST_HOP_MAPPED is
	// never a public candidate (state-model §1).
	PublicCandidate bool
	// MappingStateFirstHop mirrors the frozen mapping_state axis: true iff
	// the chain produced a gateway mapping whose scope is FIRST_HOP.
	MappingStateFirstHop bool
	// FinalPortObserved reports whether an observed STUN layer contributed
	// the candidate endpoint.
	FinalPortObserved bool
}

// IsGlobalV4Endpoint reports whether the endpoint host is a global-class IPv4
// address (network.IsGlobalV4 already excludes loopback, link-local, private,
// CGNAT and documentation ranges).
func IsGlobalV4Endpoint(endpoint netip.AddrPort) bool {
	return endpoint.IsValid() && IsGlobalV4(endpoint.Addr())
}

// EvaluateLayers classifies a completed layer chain. It enforces:
//
//   - at most one explicit gateway layer plus at most one observed STUN
//     layer — two explicit layers are UNSUPPORTED_MULTIPLE_EXPLICIT_NAT_LAYERS
//     and are never merged;
//   - scope classification from the assigned endpoints via IsGlobalV4;
//   - the final endpoint constraint: with a strict constraint an observed
//     STUN port differing from the gateway-assigned port fails with
//     FINAL_PORT_REWRITTEN; with accept_assigned the observed endpoint
//     becomes the candidate.
func EvaluateLayers(layers []LayerEvidence, finalConstraint PortPolicy) (PipelineVerdict, error) {
	gateways := 0
	stuns := 0
	gatewayIdx := -1
	stunIdx := -1
	for i := range layers {
		switch layers[i].Kind {
		case LayerKindGateway:
			gateways++
			gatewayIdx = i
		case LayerKindSTUN:
			stuns++
			stunIdx = i
		case LayerKindDirect, LayerKindManual:
		default:
			return PipelineVerdict{}, fmt.Errorf("traversal: unknown layer kind %q", layers[i].Kind)
		}
	}
	if gateways > 1 {
		return PipelineVerdict{}, ErrUnsupportedMultipleExplicitLayers
	}
	if stuns > 1 {
		return PipelineVerdict{}, fmt.Errorf("traversal: at most one observed STUN layer is supported, got %d", stuns)
	}

	// Pick the best candidate: an observed STUN endpoint wins over the
	// mapping layer's assigned endpoint; a direct/manual chain's endpoint
	// is its own assigned endpoint; otherwise the deepest layer.
	var candidate netip.AddrPort
	var candidateKind LayerKind
	observed := false
	switch {
	case stunIdx >= 0:
		addr, err := parseEndpoint(layers[stunIdx].AssignedEndpoint)
		if err != nil {
			return PipelineVerdict{}, fmt.Errorf("traversal: stun layer endpoint: %w", err)
		}
		candidate = addr
		candidateKind = LayerKindSTUN
		observed = true
	case gatewayIdx >= 0:
		addr, err := parseEndpoint(layers[gatewayIdx].AssignedEndpoint)
		if err != nil {
			return PipelineVerdict{}, fmt.Errorf("traversal: gateway layer endpoint: %w", err)
		}
		candidate = addr
		candidateKind = LayerKindGateway
	default:
		for i := len(layers) - 1; i >= 0; i-- {
			if layers[i].Kind == LayerKindDirect || layers[i].Kind == LayerKindManual {
				addr, err := parseEndpoint(layers[i].AssignedEndpoint)
				if err != nil {
					return PipelineVerdict{}, fmt.Errorf("traversal: %s layer endpoint: %w", layers[i].Kind, err)
				}
				candidate = addr
				candidateKind = layers[i].Kind
				break
			}
		}
		if !candidate.IsValid() {
			return PipelineVerdict{}, errors.New("traversal: layer chain produced no endpoint")
		}
	}

	// Final endpoint constraint: only an observed layer can disagree with
	// the gateway-assigned port; without one, the candidate IS the final
	// endpoint the chain holds.
	if observed && gatewayIdx >= 0 && finalConstraint == PortPolicyStrict {
		gatewayEndpoint, err := parseEndpoint(layers[gatewayIdx].AssignedEndpoint)
		if err != nil {
			return PipelineVerdict{}, fmt.Errorf("traversal: gateway layer endpoint: %w", err)
		}
		if candidate.Port() != gatewayEndpoint.Port() {
			return PipelineVerdict{}, ErrFinalPortRewritten
		}
	}

	verdict := PipelineVerdict{
		Candidate:         candidate,
		FinalPortObserved: observed,
	}
	switch {
	case candidateKind == LayerKindManual:
		if !IsGlobalV4Endpoint(candidate) {
			// A non-global operator endpoint cannot be probed from the WAN:
			// it is carried as NON_ROUTABLE evidence and never a public
			// candidate.
			verdict.Scope = ScopeNonRoutable
		} else {
			// The operator endpoint is the probe target: probe-eligible, but
			// the scope records the operator input explicitly.
			verdict.Scope = ScopeOperatorInput
			verdict.PublicCandidate = true
		}
	case !IsGlobalV4Endpoint(candidate):
		verdict.Scope = ScopeFirstHop
		verdict.MappingStateFirstHop = gatewayIdx >= 0
	case observed && gatewayIdx >= 0:
		// A global observed endpoint downstream of a gateway mapping: the
		// mapping layer itself only proved the first hop, the candidate is
		// probe-eligible.
		verdict.Scope = ScopeGlobalPublic
		verdict.PublicCandidate = true
	default:
		verdict.Scope = ScopeGlobalPublic
		verdict.PublicCandidate = true
	}
	return verdict, nil
}

// PlanRequest is the resolved input for one acquisition plan. The mapping
// layer is resolved by the caller from the node detection profile.
type PlanRequest struct {
	Strategy                protocol.Strategy
	MappingLayer            MappingLayerKind // explicit-gateway only
	IGDv2                   bool             // UPnP IGD version for the capability table
	GatewayPortPolicy       PortPolicy
	FinalEndpointConstraint PortPolicy
	// ManualExpectedEndpoint is the operator-declared public endpoint;
	// manual-static-v4 planning refuses to proceed without it.
	ManualExpectedEndpoint string
}

// StrategyPlan is the resolved per-forward acquisition plan.
type StrategyPlan struct {
	Strategy                protocol.Strategy
	MappingLayer            MappingLayerKind
	IGDv2                   bool
	GatewayPortPolicy       PortPolicy
	FinalEndpointConstraint PortPolicy
	Capability              PortControlCapability
	// ManualExpectedEndpoint carries the operator endpoint through planning
	// so acquisition consumes one validated source.
	ManualExpectedEndpoint string
}

// PlanStrategy resolves and validates one acquisition plan. It refuses an
// exact gateway port requirement a mechanism cannot honor
// (LAYER_CANNOT_REQUEST_EXACT) and requires the manual-static operator
// endpoint to be resolved by the caller before acquisition
// (OPERATOR_ENDPOINT_REQUIRED is enforced at the manual adapter boundary).
func PlanStrategy(req PlanRequest) (StrategyPlan, error) {
	plan := StrategyPlan{
		Strategy:                req.Strategy,
		MappingLayer:            req.MappingLayer,
		IGDv2:                   req.IGDv2,
		GatewayPortPolicy:       req.GatewayPortPolicy,
		FinalEndpointConstraint: req.FinalEndpointConstraint,
		ManualExpectedEndpoint:  req.ManualExpectedEndpoint,
	}
	if plan.GatewayPortPolicy == "" {
		plan.GatewayPortPolicy = PortPolicyAcceptAny
	}
	if plan.FinalEndpointConstraint == "" {
		plan.FinalEndpointConstraint = PortPolicyAcceptAssigned
	}
	switch req.Strategy {
	case protocol.StrategyExplicitGateway:
		if !req.MappingLayer.Valid() {
			return StrategyPlan{}, fmt.Errorf("traversal: explicit-gateway requires a resolved mapping layer, got %q", req.MappingLayer)
		}
		capability := PortControlCapabilityFor(req.MappingLayer, req.IGDv2)
		if plan.GatewayPortPolicy == PortPolicyStrict && !capability.CanRequestExact {
			return StrategyPlan{}, ErrLayerCannotRequestExact
		}
		plan.Capability = capability
	case protocol.StrategyManualStaticV4:
		// manual-static only proceeds after the operator filled the
		// expected public endpoint (v0.8 §3.2); never auto-detected.
		if req.ManualExpectedEndpoint == "" {
			return StrategyPlan{}, ErrOperatorEndpointRequired
		}
	case protocol.StrategyDirectV4, protocol.StrategyStunOnly, protocol.StrategyAuto:
		// direct/manual/stun carry no explicit mapping layer; auto is
		// resolved by ResolveAuto before acquisition planning.
		if req.MappingLayer != "" && req.Strategy != protocol.StrategyAuto {
			plan.MappingLayer = ""
		}
	default:
		return StrategyPlan{}, fmt.Errorf("traversal: unknown strategy %q", req.Strategy)
	}
	return plan, nil
}

// PortControlCapabilityFor is the honest per-mechanism capability table
// (v0.8 §3.3): PCP supports suggested port and PREFER_FAILURE (exact
// requests); NAT-PMP treats the requested port as a suggestion only; UPnP
// IGDv2 AddAnyPortMapping can reserve a port while IGDv1 AddPortMapping
// returns none and may only retry bounded random candidates; direct,
// manual and stun-only layers carry no gateway control.
func PortControlCapabilityFor(kind MappingLayerKind, igdV2 bool) PortControlCapability {
	switch kind {
	case LayerPCP:
		return PortControlCapability{
			Mechanism:               LayerPCP,
			CanRequestExact:         true,
			CanAcceptAssigned:       true,
			CanRetryCandidate:       true,
			FinalEndpointConstraint: PortPolicyStrict,
		}
	case LayerNATPMP:
		return PortControlCapability{
			Mechanism:               LayerNATPMP,
			CanRequestExact:         false,
			CanAcceptAssigned:       true,
			CanRetryCandidate:       false,
			FinalEndpointConstraint: PortPolicyAcceptAssigned,
		}
	case LayerUPnP:
		if igdV2 {
			return PortControlCapability{
				Mechanism:               LayerUPnP,
				CanRequestExact:         true,
				CanAcceptAssigned:       true,
				CanRetryCandidate:       true,
				FinalEndpointConstraint: PortPolicyStrict,
			}
		}
		return PortControlCapability{
			Mechanism:               LayerUPnP,
			CanRequestExact:         false,
			CanAcceptAssigned:       true,
			CanRetryCandidate:       true, // bounded random candidate retry only
			FinalEndpointConstraint: PortPolicyAcceptAssigned,
		}
	default:
		return PortControlCapability{FinalEndpointConstraint: PortPolicyAcceptAssigned}
	}
}

// ResolveAuto walks an ordered auto strategy list and returns the first
// strategy the availability probe accepts. A fixed strategy never falls
// back: callers that hold one resolved strategy acquire it directly and
// surface its failure. Every strategy probed and failed yields
// ErrNoViableStrategy.
func ResolveAuto(order []protocol.Strategy, available func(protocol.Strategy) bool) (protocol.Strategy, error) {
	for _, strategy := range order {
		if available(strategy) {
			return strategy, nil
		}
	}
	return "", ErrNoViableStrategy
}

// parseEndpoint parses "ip:port" into an AddrPort.
func parseEndpoint(endpoint string) (netip.AddrPort, error) {
	addr, err := netip.ParseAddrPort(endpoint)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("invalid endpoint %q: %w", endpoint, err)
	}
	return netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port()), nil
}

// ParseManualEndpoint validates the operator-declared expected endpoint
// (IPv4 literal, concrete port). The manager and the manual layer both
// consume it, so the same operator input cannot succeed in one path and
// fail in the other.
func ParseManualEndpoint(endpoint string) (netip.AddrPort, error) {
	parsed, err := parseEndpoint(endpoint)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if !parsed.Addr().Is4() {
		return netip.AddrPort{}, fmt.Errorf("manual endpoint %q must be an IPv4 literal", endpoint)
	}
	if parsed.Port() == 0 {
		return netip.AddrPort{}, fmt.Errorf("manual endpoint %q must carry a concrete port", endpoint)
	}
	return parsed, nil
}

// ---------------------------------------------------------------------------
// Gateway mapper contract (Story 5 composition).
//
// Adapters wrap their protocol clients and surface the normalized contract
// the Manager and Detector consume. Dependency direction: adapter packages
// import traversal; traversal never imports an adapter, so the composition
// root (the consumer wiring the manager) constructs adapters explicitly.
// ---------------------------------------------------------------------------

// ControlServer is one gateway control endpoint discovered for a mechanism.
type ControlServer struct {
	Mechanism MappingLayerKind
	// Address is the control endpoint: "ip:port" for PCP/NAT-PMP, the
	// absolute control URL for UPnP.
	Address string
	// Identity is the stable gateway identity (UPnP USN; empty otherwise).
	Identity string
	// IGDv2 records the UPnP service version for the capability table.
	IGDv2 bool
}

// GatewayMapRequest is the mechanism-neutral mapping request. v1 maps TCP
// tuples; UDP arrives with P13 through the same contract.
type GatewayMapRequest struct {
	InternalIP            netip.Addr
	InternalPort          uint16
	RequestedExternalPort uint16
	Lease                 time.Duration
	// StrictPort demands the exact external port where the mechanism can
	// express it (PCP PREFER_FAILURE, UPnP IGDv2 request). Mechanisms that
	// cannot request exact ports reject StrictPort at planning.
	StrictPort bool
}

// GatewayMapping is the normalized live mapping state.
type GatewayMapping struct {
	Mechanism    MappingLayerKind
	Ownership    OwnershipStrength
	InternalIP   netip.Addr
	InternalPort uint16
	External     netip.AddrPort
	Lease        time.Duration
	Epoch        uint32
	// Identity is the stable gateway identity for journal records (UPnP
	// USN, empty otherwise).
	Identity string
	// ServerRebooted reports an epoch rollback beyond the protocol
	// tolerance: the gateway may have lost every mapping and publication
	// state must go stale (adapters copy it from the client results).
	ServerRebooted bool
	// State is the mechanism-private renewal state (PCP nonce, NAT-PMP
	// tuple, UPnP mapping record). It is opaque to the Manager and only
	// ever passed back to the same adapter's Renew/Delete.
	State any
}

// Evidence renders the structured layer record (v0.8 §3.1 step 4) for this
// mapping: scope classifies the external endpoint against IsGlobalV4, so a
// non-global assignment carries FIRST_HOP scope and never advertises
// itself as a public candidate.
func (m GatewayMapping) Evidence(control ControlServer) LayerEvidence {
	scope := ScopeFirstHop
	if IsGlobalV4Endpoint(m.External) {
		scope = ScopeGlobalPublic
	}
	return LayerEvidence{
		Kind:             LayerKindGateway,
		Mechanism:        m.Mechanism,
		ControlServer:    control.Address,
		InternalEndpoint: netip.AddrPortFrom(m.InternalIP, m.InternalPort).String(),
		AssignedEndpoint: m.External.String(),
		Scope:            scope,
		LeaseLifetime:    m.Lease,
		Epoch:            m.Epoch,
		Ownership:        m.Ownership,
		ParentLayer:      -1,
	}
}

// maxIGDDescriptionBytes is the description budget the reference IGD
// implementation (miniupnpd) stores verbatim: its 64-byte description field
// is not null-terminated for longer values, so the query echo comes back
// with stack garbage — breaking the SOAP response and making
// query-then-delete verification impossible. Real-device evidence from the
// netns lab. v1 keeps every mapping description within it.
const maxIGDDescriptionBytes = 63

// Description renders the journal mapping description for this record: a
// stable, owner-tagged string the delete verification compares. It is
// deterministically capped at maxIGDDescriptionBytes, so Map and Delete
// derive the identical tag on any device.
func (m GatewayMapping) Description() string {
	description := "AntiNAT"
	if m.Identity != "" {
		description += " " + m.Identity
	}
	if len(description) <= maxIGDDescriptionBytes {
		return description
	}
	return description[:maxIGDDescriptionBytes]
}

// GatewayMapper is one explicit NAT control mechanism (v0.8 §3.4): PCP with
// strong nonce ownership, NAT-PMP with weak leases, UPnP IGD with
// best-effort query-then-delete. Implementations must be safe for
// sequential use; renewals and deletes carry the State they produced.
type GatewayMapper interface {
	// Implementations must be bounded-latency and must honor their context:
	// the manager and detector invoke these methods from goroutines whose
	// hangs cannot be forcibly interrupted (an adapter fault is converted to
	// an ordinary error, but a call that never returns wedges its caller).
	Mechanism() MappingLayerKind
	Ownership() OwnershipStrength
	Capability() PortControlCapability
	// Discover probes whether a gateway of this mechanism controls the
	// first hop. Silence or refusal is evidence of absence, not an error
	// to retry forever.
	Discover(ctx context.Context) (ControlServer, error)
	// Map acquires one external mapping for the internal TCP tuple.
	Map(ctx context.Context, req GatewayMapRequest) (GatewayMapping, error)
	// Renew extends the lease carrying the owning state.
	Renew(ctx context.Context, mapping GatewayMapping, lifetime time.Duration) (GatewayMapping, error)
	// Delete releases the mapping per its ownership strength.
	Delete(ctx context.Context, mapping GatewayMapping) error
}
