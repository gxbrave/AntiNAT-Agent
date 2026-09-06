// Forward strategy translation (P12W Stories 2-5): turns the frozen
// ForwardSpec strategy (+ the node's cached detection profile + the
// configured STUN servers) into the concrete traversal.PlanRequest the
// Manager acquires with. `auto` is resolved to a concrete strategy BEFORE
// acquisition (the Manager refuses auto/stun-only directly). The STUN-only
// composer is the agent-side acquisition for a forward that observes its
// endpoint through same-tuple STUN without any gateway control.
package agent

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
	"github.com/gxbrave/AntiNAT-Agent/internal/traversal"
)

// Strategy translation errors surfaced as apply failures (truthful, not an
// Applied state).
var (
	// errExplicitGatewayNeedsLayer refuses explicit-gateway without a
	// resolved gateway mechanism in the detection profile.
	errNoGatewayLayerInProfile = errors.New("agent: explicit-gateway requires a resolved mapping layer in the detection profile")
	// errNoStunServer refuses stun-only without a configured STUN server.
	errNoStunServer = errors.New("agent: stun-only requires a configured STUN server")
	// errAutoNoPassingDefault refuses auto when the detection profile has no
	// PASSED default strategy (stale or absent capability is never reused).
	errAutoNoPassingDefault = errors.New("agent: auto requires a detection profile default strategy that PASSED")
	// errAutoStaleProfile refuses auto when the cached detection profile no
	// longer describes the node (fingerprint changed or older than the max
	// age). The detection job can repair it; recovery quarantines rather than
	// failing the whole pass (repair R1 finding 3).
	errAutoStaleProfile = errors.New("agent: auto refuses a stale detection profile")
)

// planFor translates one ForwardSpec into the resolved traversal PlanRequest.
// strategy must already be concrete (auto is resolved by resolveAutoStrategy
// before this prefers to plan concrete routes). The profile is the cached
// detection profile used to resolve the explicit-gateway mechanism; direct,
// manual and stun-only carry no mapping layer.
//
// D4 (binding): a pinned public port (RequestedPublicPort != 0) is a strict
// request only for a mechanism that can request exact ports (PCP, UPnP
// IGDv2); NAT-PMP and IGDv1 treat it as a suggestion
// (PortPolicyAcceptAny) — the honest per-mechanism capability.
func planFor(spec protocol.ForwardSpec, profile traversal.Profile, stunServers []string) (traversal.PlanRequest, error) {
	switch spec.Strategy {
	case protocol.StrategyDirectV4:
		return traversal.PlanRequest{Strategy: protocol.StrategyDirectV4}, nil
	case protocol.StrategyManualStaticV4:
		if spec.ManualExpectedEndpoint == "" {
			return traversal.PlanRequest{}, traversal.ErrOperatorEndpointRequired
		}
		return traversal.PlanRequest{
			Strategy:               protocol.StrategyManualStaticV4,
			ManualExpectedEndpoint: spec.ManualExpectedEndpoint,
		}, nil
	case protocol.StrategyExplicitGateway:
		layer, igdV2, ok := explicitGatewayLayer(profile)
		if !ok {
			return traversal.PlanRequest{}, errNoGatewayLayerInProfile
		}
		plan := traversal.PlanRequest{
			Strategy:                protocol.StrategyExplicitGateway,
			MappingLayer:            layer,
			IGDv2:                   igdV2,
			GatewayPortPolicy:       traversal.PortPolicyAcceptAny,
			FinalEndpointConstraint: traversal.PortPolicyAcceptAssigned,
		}
		if spec.RequestedPublicPort != 0 && traversal.PortControlCapabilityFor(layer, igdV2).CanRequestExact {
			plan.GatewayPortPolicy = traversal.PortPolicyStrict
			plan.FinalEndpointConstraint = traversal.PortPolicyStrict
		}
		return plan, nil
	case protocol.StrategyStunOnly:
		if len(stunServers) == 0 {
			return traversal.PlanRequest{}, errNoStunServer
		}
		return traversal.PlanRequest{Strategy: protocol.StrategyStunOnly}, nil
	case protocol.StrategyAuto:
		return traversal.PlanRequest{Strategy: protocol.StrategyAuto}, nil
	default:
		return traversal.PlanRequest{}, fmt.Errorf("agent: unknown strategy %q", spec.Strategy)
	}
}

// explicitGatewayLayer resolves the profile's passing explicit-gateway result
// into the concrete mapping mechanism and UPnP IGD version. A non-PASSED or
// absent result means no mechanism is available on this node.
func explicitGatewayLayer(profile traversal.Profile) (traversal.MappingLayerKind, bool, bool) {
	result, ok := profile.ResultFor(protocol.StrategyExplicitGateway)
	if !ok || result.State != traversal.DetectionPassed {
		return "", false, false
	}
	switch {
	case strings.HasPrefix(result.LayerSignature, "upnp-igd"):
		return traversal.LayerUPnP, result.LayerSignature == "upnp-igd:2", true
	case result.LayerSignature == "pcp":
		return traversal.LayerPCP, false, true
	case result.LayerSignature == "nat-pmp":
		return traversal.LayerNATPMP, false, true
	default:
		return "", false, false
	}
}

// defaultAutoOrder is the production order used when the operator does not
// provide one. It is kept in the Agent composition (and copied into the data
// plane) before any detector or route is built, so every resolver observes the
// same order.
func defaultAutoOrder() []protocol.Strategy {
	return []protocol.Strategy{
		protocol.StrategyExplicitGateway,
		protocol.StrategyDirectV4,
		protocol.StrategyStunOnly,
	}
}

// resolveAutoStrategy resolves one auto Forward to its concrete strategy.
// UDP auto stays direct-v4 (P13 owns the UDP dataplane; detection is
// deferred for UDP). TCP auto walks the CURRENT configured order and accepts
// only a matching PASSED profile result. Profile.DefaultStrategy is a
// diagnostic/cache field, not an authority that can override the configured
// order.
func resolveAutoStrategy(spec protocol.ForwardSpec, profile traversal.Profile, haveProfile bool, order []protocol.Strategy) (protocol.Strategy, error) {
	if spec.Protocol == protocol.ProtocolUDP {
		return protocol.StrategyDirectV4, nil
	}
	if !haveProfile {
		return "", errAutoNoPassingDefault
	}
	if len(order) == 0 {
		order = defaultAutoOrder()
	}
	for _, strategy := range order {
		switch strategy {
		case protocol.StrategyDirectV4, protocol.StrategyExplicitGateway, protocol.StrategyStunOnly:
			result, ok := profile.ResultFor(strategy)
			if ok && result.State == traversal.DetectionPassed {
				return strategy, nil
			}
		default:
			// manual-static-v4 and auto are not probeable order entries. The
			// command parser rejects them; ignoring one here keeps malformed
			// persisted configuration fail-closed rather than selecting it.
			continue
		}
	}
	return "", errAutoNoPassingDefault
}

// forwardRoute is the resolved acquisition direction for one spec: which
// manager (or the agent-side STUN-only composer) acquires the listener.
type forwardRoute struct {
	plan traversal.PlanRequest
	// manager is the traversal.Manager that acquires the listener; nil for
	// stun-only (the composer acquires directly through the shared-port seam).
	manager *traversal.Manager
	// cfg is the synchronized composition snapshot used for the complete
	// external acquisition. A rebuild may publish new pointers while this
	// acquisition is in flight; the generation fields below then reject its
	// install rather than mixing old and new owners.
	cfg dataPlaneConfig
	// isGateway selects the gateway manager path (shared-port listeners).
	isGateway bool
	// stunOnly routes through the agent-side stun-only composer.
	stunOnly              bool
	compositionGeneration uint64
	capabilityGeneration  uint64
	capabilityFingerprint string
	// cfg is a value snapshot; manager/detector pointers in it are published
	// together under dataPlane.mu.
}

// resolveForwardRoute translates one ForwardSpec into its acquisition route.
// Auto is resolved to a concrete strategy first (UDP auto → direct-v4).
func (d *dataPlane) resolveForwardRoute(spec protocol.ForwardSpec) (forwardRoute, error) {
	cfg, compositionGeneration, capabilityGeneration, capabilityFingerprint := d.configSnapshot()
	strategy := spec.Strategy
	// UDP auto is a deliberate P13 direct-v4 exception. Resolve it before
	// loading or validating the TCP detection profile: a stale, malformed, or
	// absent TCP profile must not affect UDP auto.
	if spec.Protocol == protocol.ProtocolUDP {
		if strategy == protocol.StrategyAuto {
			strategy = protocol.StrategyDirectV4
			spec.Strategy = strategy
		} else if strategy != protocol.StrategyDirectV4 {
			return forwardRoute{}, fmt.Errorf("agent: UDP strategy %q is unsupported; only direct-v4 and auto are allowed", strategy)
		}
	}
	if strategy == protocol.StrategyAuto {
		profile, haveProfile, err := d.loadProfileFrom(cfg)
		if err != nil {
			return forwardRoute{}, err
		}
		if err := validateAutoProfile(cfg.RouteTable, cfg.Clock, profile, haveProfile); err != nil {
			return forwardRoute{}, err
		}
		resolved, err := resolveAutoStrategy(spec, profile, haveProfile, cfg.AutoOrder)
		if err != nil {
			return forwardRoute{}, err
		}
		strategy = resolved
		// planFor reads spec.Strategy; route the resolved concrete strategy so
		// the acquisition plan never carries "auto" into the Manager.
		spec.Strategy = resolved
	}
	snapshot := forwardRoute{
		cfg:                   cfg,
		compositionGeneration: compositionGeneration,
		capabilityGeneration:  capabilityGeneration,
		capabilityFingerprint: capabilityFingerprint,
	}
	switch strategy {
	case protocol.StrategyDirectV4:
		snapshot.plan = traversal.PlanRequest{Strategy: protocol.StrategyDirectV4}
		snapshot.manager = cfg.PlainManager
		return snapshot, nil
	case protocol.StrategyManualStaticV4:
		plan, err := planFor(spec, traversal.Profile{}, nil)
		if err != nil {
			return forwardRoute{}, err
		}
		if cfg.PlainManager == nil {
			return forwardRoute{}, errors.New("agent: manual-static route has no plain traversal manager")
		}
		snapshot.plan, snapshot.manager = plan, cfg.PlainManager
		return snapshot, nil
	case protocol.StrategyExplicitGateway:
		profile, haveProfile, err := d.loadProfileFrom(cfg)
		if err != nil {
			return forwardRoute{}, err
		}
		if !haveProfile {
			return forwardRoute{}, errNoGatewayLayerInProfile
		}
		// A present profile without a route fingerprint is malformed evidence;
		// it is never treated as current capability. Explicit gateway is kept
		// fail-closed here just like auto, so recovery can quarantine it.
		if profile.Fingerprint == "" {
			return forwardRoute{}, fmt.Errorf("agent: detection profile has no network fingerprint: %w", errAutoStaleProfile)
		}
		plan, err := planFor(spec, profile, cfg.StunServers)
		if err != nil {
			return forwardRoute{}, err
		}
		if cfg.GatewayManager == nil {
			return forwardRoute{}, errors.New("agent: explicit-gateway route has no gateway traversal manager")
		}
		snapshot.plan, snapshot.manager, snapshot.isGateway = plan, cfg.GatewayManager, true
		return snapshot, nil
	case protocol.StrategyStunOnly:
		plan, err := planFor(spec, traversal.Profile{}, cfg.StunServers)
		if err != nil {
			return forwardRoute{}, err
		}
		snapshot.plan, snapshot.stunOnly = plan, true
		return snapshot, nil
	default:
		return forwardRoute{}, fmt.Errorf("agent: unknown strategy %q", strategy)
	}
}

// loadProfile reads the cached detection profile from a synchronized
// composition snapshot.
func (d *dataPlane) loadProfile() (traversal.Profile, bool, error) {
	cfg, _, _, _ := d.configSnapshot()
	return d.loadProfileFrom(cfg)
}

func (d *dataPlane) loadProfileFrom(cfg dataPlaneConfig) (traversal.Profile, bool, error) {
	if cfg.ProfileStore == nil {
		return traversal.Profile{}, false, nil
	}
	return cfg.ProfileStore.Load()
}

// profileMaxAge is how old a detection profile may be before an auto apply
// refuses to reuse it (a node's capabilities can change; a stale profile is
// never silently treated as current).
const profileMaxAge = 24 * time.Hour

// validateAutoProfile applies the Story 5 staleness gate: an auto forward
// refuses a cached profile that no longer describes the node (missing or
// changed fingerprint, or older than profileMaxAge). UDP auto never looks at
// the profile and is resolved before this function is called.
func validateAutoProfile(routeTable traversal.RouteTable, clock func() time.Time, profile traversal.Profile, haveProfile bool) error {
	if !haveProfile {
		return nil // absent profile is handled by resolveAutoStrategy
	}
	if profile.Fingerprint == "" {
		return fmt.Errorf("agent: detection profile has no network fingerprint: %w", errAutoStaleProfile)
	}
	fingerprint, err := traversal.Fingerprint(routeTable)
	if err != nil {
		return fmt.Errorf("agent: detection fingerprint: %w", err)
	}
	if clock == nil {
		clock = time.Now
	}
	if stale, reason := profile.IsStale(fingerprint, profileMaxAge, clock()); stale {
		return fmt.Errorf("agent: detection profile is stale (%s): %w", reason, errAutoStaleProfile)
	}
	return nil
}

// firstStunServer returns the primary configured STUN endpoint, or "" when
// none are configured.
func firstStunServer(servers []string) string {
	if len(servers) == 0 {
		return ""
	}
	return servers[0]
}
