// Domain model types and validation (docs/protocol.md, docs/state-model.md).
//
// Desired Forward state, activation/operation records, the orthogonal
// activation-state axes, publication truth invariants, the durable control
// FSMs, and the probe/capability result enums. All validators are pure
// functions over the frozen enums; none of them touch storage, sockets, or
// configuration.
package protocol

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
)

// ---------------------------------------------------------------------------
// Forward protocol and strategy enums
// ---------------------------------------------------------------------------

// Protocol is the Forward data-plane protocol (v1 is IPv4-only).
type Protocol string

const (
	ProtocolTCP Protocol = "tcp"
	ProtocolUDP Protocol = "udp"
)

// Valid reports whether p is a known protocol.
func (p Protocol) Valid() bool {
	return p == ProtocolTCP || p == ProtocolUDP
}

// Strategy is the frozen Forward traversal strategy
// (docs/state-model.md §2, v0.8 §3.1).
type Strategy string

const (
	StrategyDirectV4        Strategy = "direct-v4"
	StrategyManualStaticV4  Strategy = "manual-static-v4"
	StrategyExplicitGateway Strategy = "explicit-gateway"
	StrategyStunOnly        Strategy = "stun-only"
	StrategyAuto            Strategy = "auto"
)

// ValidStrategies lists every frozen strategy.
var ValidStrategies = []Strategy{
	StrategyDirectV4, StrategyManualStaticV4, StrategyExplicitGateway,
	StrategyStunOnly, StrategyAuto,
}

// Valid reports whether s is a frozen strategy.
func (s Strategy) Valid() bool {
	for _, v := range ValidStrategies {
		if s == v {
			return true
		}
	}
	return false
}

// ParseStrategy parses a strategy string, rejecting unknown values.
func ParseStrategy(s string) (Strategy, error) {
	strategy := Strategy(s)
	if !strategy.Valid() {
		return "", fmt.Errorf("protocol: unknown strategy %q", s)
	}
	return strategy, nil
}

// DesiredPresence is the explicit presence axis of a desired Forward
// (docs/state-model.md §4): deletion is only an explicit ABSENT plus a
// deletion_operation_id.
type DesiredPresence string

const (
	PresencePresent DesiredPresence = "PRESENT"
	PresenceAbsent  DesiredPresence = "ABSENT"
)

// Valid reports whether p is a known presence value.
func (p DesiredPresence) Valid() bool {
	return p == PresencePresent || p == PresenceAbsent
}

// ValidatePort enforces the concrete-port rule (1..65535; 0 means unset).
func ValidatePort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("protocol: port %d out of range 1..65535", port)
	}
	return nil
}

// ---------------------------------------------------------------------------
// ForwardSpec / DesiredState
// ---------------------------------------------------------------------------

// ForwardSpec is one desired Forward record carried by the C2A `desired`
// message. The target is always an IPv4 literal:port (v1 Forward
// ingress/target are IPv4-only).
type ForwardSpec struct {
	ForwardID              string
	Name                   string
	Protocol               Protocol
	Target                 string
	Strategy               Strategy
	SourceInterface        string
	RequestedLocalPort     uint16
	RequestedPublicPort    uint16
	ManualExpectedEndpoint string
	RateLimitBPS           uint64
	DetailedStats          bool
	PublishScheme          string
	PublishedHost          string
	CustomURITemplate      string
	DesiredRevision        uint64
	Presence               DesiredPresence
	DeletionOperationID    string
}

// Validate enforces the frozen ForwardSpec invariants.
func (s ForwardSpec) Validate() error {
	if s.ForwardID == "" {
		return errors.New("protocol: forward_id must be non-empty")
	}
	if !s.Protocol.Valid() {
		return fmt.Errorf("protocol: unknown protocol %q", s.Protocol)
	}
	if err := validateIPv4Target(s.Target); err != nil {
		return err
	}
	if !s.Strategy.Valid() {
		return fmt.Errorf("protocol: unknown strategy %q", s.Strategy)
	}
	if s.PublishScheme != "" && s.PublishScheme != "http" && s.PublishScheme != "https" {
		return fmt.Errorf("protocol: unknown publish_scheme %q", s.PublishScheme)
	}
	if !s.Presence.Valid() {
		return fmt.Errorf("protocol: unknown desired presence %q", s.Presence)
	}
	switch s.Presence {
	case PresenceAbsent:
		if s.DeletionOperationID == "" {
			return errors.New("protocol: ABSENT forward requires a deletion_operation_id")
		}
	case PresencePresent:
		if s.DeletionOperationID != "" {
			return errors.New("protocol: PRESENT forward must not carry a deletion_operation_id")
		}
	}
	return nil
}

// validateIPv4Target requires a concrete IPv4 literal:port.
func validateIPv4Target(target string) error {
	host, portText, err := net.SplitHostPort(target)
	if err != nil || host == "" {
		return fmt.Errorf("protocol: target %q is not a valid IPv4:port", target)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.Is4() {
		return fmt.Errorf("protocol: target host %q is not an IPv4 literal (v6/hostname Forwards are not supported in v1)", host)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return fmt.Errorf("protocol: target port %q is not an integer", portText)
	}
	if err := ValidatePort(port); err != nil {
		return fmt.Errorf("protocol: target: %v", err)
	}
	return nil
}

// DesiredState is the full C2A desired snapshot for one node.
type DesiredState struct {
	NodeID   string
	Forwards []ForwardSpec
}

// Validate enforces the DesiredState invariants.
func (d DesiredState) Validate() error {
	if d.NodeID == "" {
		return errors.New("protocol: desired state requires a node_id")
	}
	seen := map[string]bool{}
	for i := range d.Forwards {
		f := d.Forwards[i]
		if err := f.Validate(); err != nil {
			return fmt.Errorf("protocol: forward %q: %v", f.ForwardID, err)
		}
		if seen[f.ForwardID] {
			return fmt.Errorf("protocol: duplicate forward_id %q in desired state", f.ForwardID)
		}
		seen[f.ForwardID] = true
	}
	return nil
}

// ForwardActivation identifies one activation instance of a Forward
// (v0.8 §2: each activation has its own activation_id, generation, and spec
// revision).
type ForwardActivation struct {
	ActivationID string
	Generation   uint64
	SpecRevision uint64
	ForwardID    string
}

// Validate enforces activation invariants.
func (a ForwardActivation) Validate() error {
	if a.ActivationID == "" {
		return errors.New("protocol: activation requires an activation_id")
	}
	if a.ForwardID == "" {
		return errors.New("protocol: activation requires a forward_id")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Orthogonal activation-state axes
// ---------------------------------------------------------------------------

// stateAxis is one independent activation-state axis with its frozen enum.
type stateAxis struct {
	name   string
	states map[string]bool
}

func axis(name string, states ...string) stateAxis {
	m := make(map[string]bool, len(states))
	for _, s := range states {
		m[s] = true
	}
	return stateAxis{name: name, states: m}
}

// activationAxes are the frozen orthogonal axes (docs/state-model.md §1).
var activationAxes = []stateAxis{
	axis("control_state", "ONLINE", "OFFLINE"),
	axis("listener_state", "STOPPED", "STARTING", "READY", "ERROR"),
	axis("mapping_state", "NOT_REQUIRED", "ACQUIRING", "FIRST_HOP_MAPPED", "PUBLIC_CANDIDATE", "LOST", "ERROR"),
	axis("keepalive_state", "NOT_REQUIRED", "HEALTHY", "DEGRADED", "LOST"),
	axis("wan_reachability_state", "NOT_TESTED", "PROBING", "OPEN_FROM_VANTAGE", "REJECTED", "TIMEOUT", "NO_INDEPENDENT_VANTAGE", "PROBE_INFRA_UNAVAILABLE", "UNKNOWN"),
	axis("return_path_state", "NOT_TESTED", "VERIFIED", "FAILED", "UNKNOWN"),
	axis("target_health_state", "PASS", "FAIL", "SKIPPED", "UNSUPPORTED", "UNKNOWN"),
	axis("publication_state", "NONE", "PUBLISHED_VERIFIED", "PUBLISHED_UNVERIFIED", "STALE", "UNPUBLISHED"),
	axis("data_plane_state", "STOPPED", "READY", "DEGRADED", "ERROR"),
}

// ValidAxisValue reports whether value is a legal value of the named axis.
func ValidAxisValue(axisName, value string) bool {
	for _, a := range activationAxes {
		if a.name == axisName {
			return a.states[value]
		}
	}
	return false
}

// ValidActivationSnapshot validates a complete orthogonal snapshot: exactly
// one legal value per axis and no extra fields.
func ValidActivationSnapshot(s map[string]string) error {
	if len(s) != len(activationAxes) {
		return fmt.Errorf("protocol: activation snapshot has %d axes, want %d", len(s), len(activationAxes))
	}
	for _, a := range activationAxes {
		v, ok := s[a.name]
		if !ok {
			return fmt.Errorf("protocol: activation snapshot missing axis %q", a.name)
		}
		if !a.states[v] {
			return fmt.Errorf("protocol: axis %q has illegal value %q", a.name, v)
		}
	}
	return nil
}

// ActivationStates is the typed struct mirror of the orthogonal axes.
type ActivationStates struct {
	ControlState         string `json:"control_state"`
	ListenerState        string `json:"listener_state"`
	MappingState         string `json:"mapping_state"`
	KeepaliveState       string `json:"keepalive_state"`
	WanReachabilityState string `json:"wan_reachability_state"`
	ReturnPathState      string `json:"return_path_state"`
	TargetHealthState    string `json:"target_health_state"`
	PublicationState     string `json:"publication_state"`
	DataPlaneState       string `json:"data_plane_state"`
}

// Validate requires every axis to be present with a legal value and enforces
// the cross-axis truth relations.
func (s ActivationStates) Validate() error {
	snapshot := map[string]string{
		"control_state":          s.ControlState,
		"listener_state":         s.ListenerState,
		"mapping_state":          s.MappingState,
		"keepalive_state":        s.KeepaliveState,
		"wan_reachability_state": s.WanReachabilityState,
		"return_path_state":      s.ReturnPathState,
		"target_health_state":    s.TargetHealthState,
		"publication_state":      s.PublicationState,
		"data_plane_state":       s.DataPlaneState,
	}
	if err := ValidActivationSnapshot(snapshot); err != nil {
		return err
	}
	return ValidateAxisRelations(s.MappingState, s.WanReachabilityState, s.ReturnPathState, s.PublicationState)
}

// ValidatePublication enforces the frozen publication truth rules:
// PUBLISHED_VERIFIED requires OPEN_FROM_VANTAGE + VERIFIED return path;
// PUBLISHED_UNVERIFIED must never claim OPEN_FROM_VANTAGE.
func ValidatePublication(pubState, wanReach, returnPath string) error {
	switch pubState {
	case "PUBLISHED_VERIFIED":
		if wanReach != "OPEN_FROM_VANTAGE" {
			return errors.New("protocol: PUBLISHED_VERIFIED requires wan_reachability_state=OPEN_FROM_VANTAGE")
		}
		if returnPath != "VERIFIED" {
			return errors.New("protocol: PUBLISHED_VERIFIED requires return_path_state=VERIFIED")
		}
	case "PUBLISHED_UNVERIFIED":
		if wanReach == "OPEN_FROM_VANTAGE" {
			return errors.New("protocol: PUBLISHED_UNVERIFIED must not claim OPEN_FROM_VANTAGE")
		}
	}
	return nil
}

// ValidatePublicationCandidate rejects a published candidate that is not a
// concrete global IPv4 literal (a private/RFC1918 endpoint can never be a
// published candidate).
func ValidatePublicationCandidate(pubState, candidate string) error {
	if pubState != "PUBLISHED_VERIFIED" && pubState != "PUBLISHED_UNVERIFIED" {
		return nil
	}
	if candidate == "" {
		return errors.New("protocol: published state requires a published endpoint")
	}
	host, _, err := net.SplitHostPort(candidate)
	if err != nil {
		return fmt.Errorf("protocol: published candidate %q is not a valid endpoint", candidate)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.Is4() {
		return errors.New("protocol: published candidate must be an IPv4 literal")
	}
	if !IsGlobalEndpoint(ip) {
		return fmt.Errorf("protocol: published candidate %q is not a global IPv4 literal", candidate)
	}
	return nil
}

// ValidateAxisRelations enforces the impossible layer relations frozen by the
// state model: FIRST_HOP_MAPPED is never a verified public endpoint, and
// PUBLISHED_VERIFIED cannot ride on a first-hop mapping.
func ValidateAxisRelations(mappingState, wanReach, returnPath, pubState string) error {
	if mappingState == "FIRST_HOP_MAPPED" && returnPath == "VERIFIED" {
		return errors.New("protocol: FIRST_HOP_MAPPED is never a verified public endpoint")
	}
	if err := ValidatePublication(pubState, wanReach, returnPath); err != nil {
		return err
	}
	if pubState == "PUBLISHED_VERIFIED" && mappingState == "FIRST_HOP_MAPPED" {
		return errors.New("protocol: PUBLISHED_VERIFIED cannot ride on a FIRST_HOP_MAPPED mapping")
	}
	return nil
}

// ---------------------------------------------------------------------------
// AppliedForwardState
// ---------------------------------------------------------------------------

// AppliedForwardState is the durable Agent LKG record for a Forward
// (docs/state-model.md §2). It never persists a directly-restorable verified
// health.
type AppliedForwardState struct {
	ForwardID             string `json:"forward_id"`
	SpecRevision          uint64 `json:"spec_revision"`
	DesiredRevision       uint64 `json:"desired_revision"`
	ActualBindHost        string `json:"actual_bind_host"`
	ActualBindPort        uint16 `json:"actual_bind_port"`
	AssignedGatewayPort   uint16 `json:"assigned_gateway_port,omitempty"`
	PublicPort            uint16 `json:"public_port,omitempty"`
	Strategy              string `json:"strategy"`
	LayerVersion          uint64 `json:"layer_version"`
	ActivationRecovery    string `json:"activation_recovery_descriptor"`
	MappingJournalRef     string `json:"mapping_journal_ref,omitempty"`
	HookDefinitionVersion uint64 `json:"hook_definition_version,omitempty"`
	HookSecretVersion     uint64 `json:"hook_secret_version,omitempty"`
	AppliedAtUnix         int64  `json:"applied_at_unix"`
}

// validStrategies is the frozen AppliedForwardState strategy set.
var validStrategies = map[string]bool{
	"direct-v4":        true,
	"manual-static-v4": true,
	"explicit-gateway": true,
	"stun-only":        true,
	"auto":             true,
}

// Validate enforces the frozen AppliedForwardState invariants.
func (a AppliedForwardState) Validate() error {
	if a.ForwardID == "" {
		return errors.New("protocol: forward_id must be non-empty")
	}
	if a.DesiredRevision < a.SpecRevision {
		return errors.New("protocol: desired_revision must be >= spec_revision")
	}
	if a.ActualBindHost == "" || a.ActualBindPort == 0 {
		return errors.New("protocol: actual bind tuple must be concrete")
	}
	if !validStrategies[a.Strategy] {
		return fmt.Errorf("protocol: unknown strategy %q", a.Strategy)
	}
	if a.AppliedAtUnix <= 0 {
		return errors.New("protocol: applied_at_unix must be set")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Durable control FSMs
// ---------------------------------------------------------------------------

// transitionTable maps the exact-predecessor (from, to) legal transitions.
type transitionTable map[[2]string]bool

func transitionPair(from, to string) [2]string { return [2]string{from, to} }

// frozenFSMs are the single-step transition tables frozen by
// docs/state-model.md §3. A transition is legal only if the source is the
// exact predecessor.
var frozenFSMs = map[string]transitionTable{
	"outbox": {
		transitionPair("PENDING", "CLAIMED"):          true,
		transitionPair("CLAIMED", "SENT"):             true,
		transitionPair("SENT", "SEMANTIC_ACKED"):      true,
		transitionPair("SEMANTIC_ACKED", "RECEIPTED"): true,
		transitionPair("RECEIPTED", "GC"):             true,
	},
	"inbox": {
		transitionPair("RECEIVED", "INTENT_PERSISTED"): true,
		transitionPair("INTENT_PERSISTED", "APPLYING"): true,
		transitionPair("APPLYING", "APPLIED"):          true,
		transitionPair("APPLYING", "NACKED"):           true,
	},
	"key_rotation": {
		transitionPair("PREPARED", "ANNOUNCED"): true,
		transitionPair("ANNOUNCED", "ACKED"):    true,
		transitionPair("ACKED", "ACTIVE"):       true,
		transitionPair("ACTIVE", "RETIRED"):     true,
	},
	"decommission": {
		transitionPair("ACTIVE", "DECOMMISSIONING"):         true,
		transitionPair("DECOMMISSIONING", "DECOMMISSIONED"): true,
		transitionPair("DECOMMISSIONED", "CLEANUP_ONLY"):    true,
	},
	"restore": {
		transitionPair("RESTORED", "RECOVERY_QUARANTINE"):    true,
		transitionPair("RECOVERY_QUARANTINE", "RECONCILING"): true,
		transitionPair("RECONCILING", "AUTHORIZED"):          true,
	},
}

var frozenFSMStates = map[string]map[string]bool{
	"outbox":       fsmStateSet("PENDING", "CLAIMED", "SENT", "SEMANTIC_ACKED", "RECEIPTED", "GC"),
	"inbox":        fsmStateSet("RECEIVED", "INTENT_PERSISTED", "APPLYING", "APPLIED", "NACKED"),
	"key_rotation": fsmStateSet("PREPARED", "ANNOUNCED", "ACKED", "ACTIVE", "RETIRED"),
	"decommission": fsmStateSet("ACTIVE", "DECOMMISSIONING", "DECOMMISSIONED", "CLEANUP_ONLY"),
	"restore":      fsmStateSet("RESTORED", "RECOVERY_QUARANTINE", "RECONCILING", "AUTHORIZED"),
}

func fsmStateSet(states ...string) map[string]bool {
	m := make(map[string]bool, len(states))
	for _, s := range states {
		m[s] = true
	}
	return m
}

// FSMNames lists every durable control FSM.
var FSMNames = []string{"outbox", "inbox", "key_rotation", "decommission", "restore"}

// ValidFSMState reports whether state is a legal state of the named FSM.
func ValidFSMState(fsm, state string) bool {
	return frozenFSMStates[fsm][state]
}

// ValidateFSMTransition returns nil iff the transition is single-step legal
// in the named FSM.
func ValidateFSMTransition(fsm, from, to string) error {
	table, ok := frozenFSMs[fsm]
	if !ok {
		return fmt.Errorf("protocol: unknown FSM %q", fsm)
	}
	if !frozenFSMStates[fsm][from] {
		return fmt.Errorf("protocol: FSM %q has no state %q", fsm, from)
	}
	if !frozenFSMStates[fsm][to] {
		return fmt.Errorf("protocol: FSM %q has no state %q", fsm, to)
	}
	if !table[transitionPair(from, to)] {
		return fmt.Errorf("protocol: illegal transition %s -> %s in FSM %q", from, to, fsm)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Operation kinds, probe outcomes, capability results
// ---------------------------------------------------------------------------

// OperationKind is a durable operation category (docs/error-codes.md §3).
type OperationKind string

const (
	OperationForwardDeletion  OperationKind = "forward_deletion"
	OperationNodeDeletion     OperationKind = "node_deletion"
	OperationNodeDecommission OperationKind = "node_decommission"
	OperationForceCutover     OperationKind = "force_cutover"
	OperationRetry            OperationKind = "retry"
	OperationDetection        OperationKind = "detection"
)

// Valid reports whether k is a known operation kind.
func (k OperationKind) Valid() bool {
	switch k {
	case OperationForwardDeletion, OperationNodeDeletion, OperationNodeDecommission,
		OperationForceCutover, OperationRetry, OperationDetection:
		return true
	}
	return false
}

// ProbeOutcome is the frozen probe operation outcome registry
// (docs/protocol.md §8). The Controller persists exactly one per operation.
type ProbeOutcome string

const (
	OutcomeArmed                 ProbeOutcome = "ARMED"
	OutcomeAccepted              ProbeOutcome = "ACCEPTED"
	OutcomeRejected              ProbeOutcome = "REJECTED"
	OutcomeDropped               ProbeOutcome = "DROPPED"
	OutcomeOpenFromVantage       ProbeOutcome = "OPEN_FROM_VANTAGE"
	OutcomeTimeout               ProbeOutcome = "TIMEOUT"
	OutcomeNoIndependentVantage  ProbeOutcome = "NO_INDEPENDENT_VANTAGE"
	OutcomeProbeInfraUnavailable ProbeOutcome = "PROBE_INFRA_UNAVAILABLE"
	OutcomeUnknown               ProbeOutcome = "UNKNOWN"
)

var probeOutcomes = map[ProbeOutcome]bool{
	OutcomeArmed: true, OutcomeAccepted: true, OutcomeRejected: true,
	OutcomeDropped: true, OutcomeOpenFromVantage: true, OutcomeTimeout: true,
	OutcomeNoIndependentVantage: true, OutcomeProbeInfraUnavailable: true,
	OutcomeUnknown: true,
}

// ParseProbeOutcome parses a frozen outcome, rejecting unknown values.
func ParseProbeOutcome(s string) (ProbeOutcome, error) {
	o := ProbeOutcome(s)
	if !probeOutcomes[o] {
		return "", fmt.Errorf("protocol: unknown probe outcome %q", s)
	}
	return o, nil
}

// MayDriveVerifiedPublication reports whether the outcome is the only one
// that may drive a verified publication (OPEN_FROM_VANTAGE).
func (o ProbeOutcome) MayDriveVerifiedPublication() bool {
	return o == OutcomeOpenFromVantage
}

// CapabilityResult is the evidence-backed capability verdict used by
// handoffs and capability reporting (master plan §1, §10).
type CapabilityResult string

const (
	CapabilityPass                CapabilityResult = "PASS"
	CapabilitySupportedWithLimits CapabilityResult = "SUPPORTED_WITH_LIMITS"
	CapabilityNoGo                CapabilityResult = "NO_GO"
	CapabilityUnknown             CapabilityResult = "UNKNOWN"
)

var capabilityResults = map[CapabilityResult]bool{
	CapabilityPass: true, CapabilitySupportedWithLimits: true,
	CapabilityNoGo: true, CapabilityUnknown: true,
}

// ParseCapabilityResult parses a capability verdict, rejecting unknown
// values.
func ParseCapabilityResult(s string) (CapabilityResult, error) {
	c := CapabilityResult(s)
	if !capabilityResults[c] {
		return "", fmt.Errorf("protocol: unknown capability result %q", s)
	}
	return c, nil
}
