package protocol

import (
	"testing"
)

// Story 3 RED: invalid state enums, out-of-range ports, IPv6 Forwards,
// private published candidates, and impossible layer relations must all fail
// validation; valid domain records must pass.

func TestActivationStateEnums(t *testing.T) {
	// Every frozen axis accepts its exact enum values.
	for _, a := range activationAxesForTest {
		for _, v := range a.values {
			if !ValidAxisValue(a.name, v) {
				t.Errorf("axis %q should accept %q", a.name, v)
			}
		}
		// Invalid values must fail.
		for _, bad := range []string{"BOGUS", "", "verified", "online"} {
			if ValidAxisValue(a.name, bad) {
				t.Errorf("axis %q should reject %q", a.name, bad)
			}
		}
	}
	// Unknown axis names always fail.
	if ValidAxisValue("not_an_axis", "ONLINE") {
		t.Fatal("unknown axis accepted")
	}
}

func TestActivationSnapshotValidation(t *testing.T) {
	valid := map[string]string{
		"control_state":          "ONLINE",
		"listener_state":         "READY",
		"mapping_state":          "PUBLIC_CANDIDATE",
		"keepalive_state":        "HEALTHY",
		"wan_reachability_state": "NOT_TESTED",
		"return_path_state":      "NOT_TESTED",
		"target_health_state":    "PASS",
		"publication_state":      "NONE",
		"data_plane_state":       "READY",
	}
	if err := ValidActivationSnapshot(valid); err != nil {
		t.Fatalf("valid snapshot rejected: %v", err)
	}
	// Missing axis fails.
	missing := map[string]string{}
	for k, v := range valid {
		missing[k] = v
	}
	delete(missing, "mapping_state")
	if err := ValidActivationSnapshot(missing); err == nil {
		t.Fatal("snapshot with a missing axis accepted")
	}
	// Illegal value fails.
	bad := map[string]string{}
	for k, v := range valid {
		bad[k] = v
	}
	bad["mapping_state"] = "PUBLISHED"
	if err := ValidActivationSnapshot(bad); err == nil {
		t.Fatal("snapshot with an illegal axis value accepted")
	}
	// Extra unknown axis fails.
	extra := map[string]string{}
	for k, v := range valid {
		extra[k] = v
	}
	extra["fake_axis"] = "x"
	if err := ValidActivationSnapshot(extra); err == nil {
		t.Fatal("snapshot with an extra axis accepted")
	}
}

// TestActivationStatesStruct pins the typed struct mirror of the axes.
func TestActivationStatesStruct(t *testing.T) {
	s := ActivationStates{
		ControlState:         "ONLINE",
		ListenerState:        "READY",
		MappingState:         "PUBLIC_CANDIDATE",
		KeepaliveState:       "HEALTHY",
		WanReachabilityState: "NOT_TESTED",
		ReturnPathState:      "NOT_TESTED",
		TargetHealthState:    "PASS",
		PublicationState:     "NONE",
		DataPlaneState:       "READY",
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("valid states rejected: %v", err)
	}
	bad := s
	bad.MappingState = "BOGUS"
	if err := bad.Validate(); err == nil {
		t.Fatal("invalid enum accepted in ActivationStates")
	}
	empty := ActivationStates{}
	if err := empty.Validate(); err == nil {
		t.Fatal("empty ActivationStates accepted (missing axes)")
	}
}

// TestPublicationInvariants pins the frozen publication truth rules.
func TestPublicationInvariants(t *testing.T) {
	if err := ValidatePublication("PUBLISHED_VERIFIED", "OPEN_FROM_VANTAGE", "VERIFIED"); err != nil {
		t.Fatalf("valid verified publication rejected: %v", err)
	}
	// PUBLISHED_VERIFIED requires both WAN vantage and return path.
	if err := ValidatePublication("PUBLISHED_VERIFIED", "NOT_TESTED", "VERIFIED"); err == nil {
		t.Fatal("PUBLISHED_VERIFIED without OPEN_FROM_VANTAGE accepted")
	}
	if err := ValidatePublication("PUBLISHED_VERIFIED", "OPEN_FROM_VANTAGE", "NOT_TESTED"); err == nil {
		t.Fatal("PUBLISHED_VERIFIED without VERIFIED return path accepted")
	}
	// PUBLISHED_UNVERIFIED must never claim OPEN_FROM_VANTAGE.
	if err := ValidatePublication("PUBLISHED_UNVERIFIED", "OPEN_FROM_VANTAGE", "NOT_TESTED"); err == nil {
		t.Fatal("PUBLISHED_UNVERIFIED claiming OPEN_FROM_VANTAGE accepted")
	}
	if err := ValidatePublication("PUBLISHED_UNVERIFIED", "PROBING", "NOT_TESTED"); err != nil {
		t.Fatalf("valid unverified publication rejected: %v", err)
	}
}

// TestPrivatePublishedCandidateFails pins that a private endpoint can never
// be a published candidate.
func TestPrivatePublishedCandidateFails(t *testing.T) {
	for _, pub := range []string{"PUBLISHED_VERIFIED", "PUBLISHED_UNVERIFIED"} {
		if err := ValidatePublicationCandidate(pub, "10.0.0.5:4444"); err == nil {
			t.Fatalf("private candidate accepted for %s", pub)
		}
		if err := ValidatePublicationCandidate(pub, "192.168.1.1:80"); err == nil {
			t.Fatalf("private candidate accepted for %s", pub)
		}
	}
	if err := ValidatePublicationCandidate("PUBLISHED_VERIFIED", "198.51.100.7:4444"); err != nil {
		t.Fatalf("global documentation candidate rejected: %v", err)
	}
	if err := ValidatePublicationCandidate("NONE", "10.0.0.5:4444"); err != nil {
		t.Fatalf("private candidate with NONE publication accepted: %v", err)
	}
}

// TestImpossibleLayerRelationFails pins cross-axis impossibilities.
func TestImpossibleLayerRelationFails(t *testing.T) {
	// FIRST_HOP_MAPPED is never a verified public endpoint.
	if err := ValidateAxisRelations("FIRST_HOP_MAPPED", "NOT_TESTED", "VERIFIED", "PUBLISHED_VERIFIED"); err == nil {
		t.Fatal("FIRST_HOP_MAPPED with verified return path accepted")
	}
	// PUBLISHED_VERIFIED cannot ride on a first-hop mapping.
	if err := ValidateAxisRelations("FIRST_HOP_MAPPED", "OPEN_FROM_VANTAGE", "VERIFIED", "PUBLISHED_VERIFIED"); err == nil {
		t.Fatal("PUBLISHED_VERIFIED over FIRST_HOP_MAPPED accepted")
	}
	// Valid verified publication relation passes.
	if err := ValidateAxisRelations("PUBLIC_CANDIDATE", "OPEN_FROM_VANTAGE", "VERIFIED", "PUBLISHED_VERIFIED"); err != nil {
		t.Fatalf("valid verified relation rejected: %v", err)
	}
}

func TestForwardSpecValidation(t *testing.T) {
	base := ForwardSpec{
		ForwardID:          "fwd-1",
		Name:               "web",
		Protocol:           ProtocolTCP,
		Target:             "198.51.100.7:8080",
		Strategy:           StrategyDirectV4,
		RequestedLocalPort: 0,
		DesiredRevision:    1,
		Presence:           PresencePresent,
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid spec rejected: %v", err)
	}
	cases := []struct {
		name string
		mut  func(*ForwardSpec)
	}{
		{"empty-forward-id", func(s *ForwardSpec) { s.ForwardID = "" }},
		{"unknown-protocol", func(s *ForwardSpec) { s.Protocol = "sctp" }},
		{"v6-target", func(s *ForwardSpec) { s.Target = "[2001:db8::1]:80" }},
		{"hostname-target", func(s *ForwardSpec) { s.Target = "example.com:80" }},
		{"target-port-zero", func(s *ForwardSpec) { s.Target = "198.51.100.7:0" }},
		{"target-port-overflow", func(s *ForwardSpec) { s.Target = "198.51.100.7:65536" }},
		{"empty-target", func(s *ForwardSpec) { s.Target = "" }},
		{"unknown-strategy", func(s *ForwardSpec) { s.Strategy = "magic" }},
		{"absent-without-deletion-id", func(s *ForwardSpec) { s.Presence = PresenceAbsent; s.DeletionOperationID = "" }},
		{"present-with-deletion-id", func(s *ForwardSpec) { s.DeletionOperationID = "op-1" }},
		{"bad-publish-scheme", func(s *ForwardSpec) { s.PublishScheme = "ftp" }},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			spec := base
			tc.mut(&spec)
			if err := spec.Validate(); err == nil {
				t.Fatalf("invalid spec accepted (%s)", tc.name)
			}
		})
	}
	// A valid deletion carries ABSENT + a deletion operation id.
	del := base
	del.Presence = PresenceAbsent
	del.DeletionOperationID = "op-del-1"
	if err := del.Validate(); err != nil {
		t.Fatalf("valid deletion spec rejected: %v", err)
	}
}

// TestPortBounds pins the port range helper used by domain and config.
func TestPortBounds(t *testing.T) {
	for _, p := range []int{1, 80, 65535} {
		if err := ValidatePort(p); err != nil {
			t.Errorf("port %d rejected: %v", p, err)
		}
	}
	for _, p := range []int{0, -1, 65536, 1 << 20} {
		if err := ValidatePort(p); err == nil {
			t.Errorf("port %d accepted", p)
		}
	}
}

func TestDesiredStateValidation(t *testing.T) {
	spec := ForwardSpec{
		ForwardID: "fwd-1", Name: "web", Protocol: ProtocolTCP,
		Target: "198.51.100.7:8080", Strategy: StrategyDirectV4,
		DesiredRevision: 1, Presence: PresencePresent,
	}
	d := DesiredState{NodeID: "node-1", Forwards: []ForwardSpec{spec}}
	if err := d.Validate(); err != nil {
		t.Fatalf("valid desired state rejected: %v", err)
	}
	empty := DesiredState{}
	if err := empty.Validate(); err == nil {
		t.Fatal("desired state without node id accepted")
	}
	bad := d
	bad.Forwards[0].Target = "[2001:db8::1]:80"
	if err := bad.Validate(); err == nil {
		t.Fatal("desired state with invalid forward accepted")
	}
}

func TestAppliedForwardStateValidation(t *testing.T) {
	valid := AppliedForwardState{
		ForwardID: "fwd-1", SpecRevision: 1, DesiredRevision: 1,
		ActualBindHost: "0.0.0.0", ActualBindPort: 8080,
		Strategy: "direct-v4", LayerVersion: 1,
		ActivationRecovery: "rec-1", AppliedAtUnix: 1_700_000_000,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid applied state rejected: %v", err)
	}
	cases := []struct {
		name string
		mut  func(*AppliedForwardState)
	}{
		{"empty-forward-id", func(a *AppliedForwardState) { a.ForwardID = "" }},
		{"revision-regression", func(a *AppliedForwardState) { a.DesiredRevision = 0 }},
		{"empty-bind-host", func(a *AppliedForwardState) { a.ActualBindHost = "" }},
		{"zero-bind-port", func(a *AppliedForwardState) { a.ActualBindPort = 0 }},
		{"unknown-strategy", func(a *AppliedForwardState) { a.Strategy = "nope" }},
		{"zero-applied-at", func(a *AppliedForwardState) { a.AppliedAtUnix = 0 }},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			a := valid
			tc.mut(&a)
			if err := a.Validate(); err == nil {
				t.Fatalf("invalid applied state accepted (%s)", tc.name)
			}
		})
	}
}

func TestFSMTransitionValidation(t *testing.T) {
	// Legal single-step transitions.
	legal := []struct{ fsm, from, to string }{
		{"outbox", "PENDING", "CLAIMED"},
		{"outbox", "RECEIPTED", "GC"},
		{"inbox", "APPLYING", "APPLIED"},
		{"inbox", "APPLYING", "NACKED"},
		{"key_rotation", "ACKED", "ACTIVE"},
		{"decommission", "DECOMMISSIONING", "DECOMMISSIONED"},
		{"restore", "RECONCILING", "AUTHORIZED"},
	}
	for _, tr := range legal {
		if err := ValidateFSMTransition(tr.fsm, tr.from, tr.to); err != nil {
			t.Errorf("legal %s %s->%s rejected: %v", tr.fsm, tr.from, tr.to, err)
		}
	}
	// Illegal transitions (skips and backward moves) pinned by fixtures.
	illegal := []struct{ fsm, from, to string }{
		{"outbox", "SENT", "GC"},
		{"outbox", "PENDING", "SENT"},
		{"outbox", "SEMANTIC_ACKED", "GC"},
		{"outbox", "CLAIMED", "PENDING"},
		{"outbox", "GC", "PENDING"},
		{"inbox", "RECEIVED", "APPLIED"},
		{"inbox", "APPLIED", "NACKED"},
		{"inbox", "RECEIVED", "APPLYING"},
		{"key_rotation", "PREPARED", "ACTIVE"},
		{"key_rotation", "ACTIVE", "PREPARED"},
		{"decommission", "ACTIVE", "DECOMMISSIONED"},
		{"decommission", "DECOMMISSIONED", "ACTIVE"},
		{"restore", "RESTORED", "AUTHORIZED"},
	}
	for _, tr := range illegal {
		if err := ValidateFSMTransition(tr.fsm, tr.from, tr.to); err == nil {
			t.Errorf("illegal %s %s->%s accepted", tr.fsm, tr.from, tr.to)
		}
	}
	if err := ValidateFSMTransition("bogus_fsm", "PENDING", "CLAIMED"); err == nil {
		t.Fatal("unknown FSM accepted")
	}
	if err := ValidateFSMTransition("outbox", "NOPE", "CLAIMED"); err == nil {
		t.Fatal("unknown state accepted")
	}
}

func TestProbeOutcomeEnum(t *testing.T) {
	want := []string{
		"ARMED", "ACCEPTED", "REJECTED", "DROPPED", "OPEN_FROM_VANTAGE",
		"TIMEOUT", "NO_INDEPENDENT_VANTAGE", "PROBE_INFRA_UNAVAILABLE", "UNKNOWN",
	}
	for _, w := range want {
		o, err := ParseProbeOutcome(w)
		if err != nil {
			t.Errorf("ParseProbeOutcome(%q): %v", w, err)
		}
		if string(o) != w {
			t.Errorf("outcome mismatch")
		}
	}
	if _, err := ParseProbeOutcome("MAGIC_SUCCESS"); err == nil {
		t.Fatal("unknown probe outcome accepted")
	}
	// Only OPEN_FROM_VANTAGE may drive a verified publication.
	if !ProbeOutcome("OPEN_FROM_VANTAGE").MayDriveVerifiedPublication() {
		t.Fatal("OPEN_FROM_VANTAGE must drive verified publication")
	}
	for _, o := range []ProbeOutcome{"ACCEPTED", "REJECTED", "TIMEOUT", "UNKNOWN"} {
		if o.MayDriveVerifiedPublication() {
			t.Fatalf("%s must not drive verified publication", o)
		}
	}
}

func TestCapabilityResultEnum(t *testing.T) {
	for _, w := range []string{"PASS", "SUPPORTED_WITH_LIMITS", "NO_GO", "UNKNOWN"} {
		if _, err := ParseCapabilityResult(w); err != nil {
			t.Errorf("ParseCapabilityResult(%q): %v", w, err)
		}
	}
	if _, err := ParseCapabilityResult("PASSED"); err == nil {
		t.Fatal("unknown capability result accepted")
	}
}

func TestOperationKindEnum(t *testing.T) {
	for _, w := range []string{"forward_deletion", "node_deletion", "node_decommission", "force_cutover", "retry", "detection"} {
		if !OperationKind(w).Valid() {
			t.Errorf("operation kind %q should be valid", w)
		}
	}
	if OperationKind("nonsense").Valid() {
		t.Fatal("unknown operation kind accepted")
	}
}

func TestForwardActivationValidation(t *testing.T) {
	a := ForwardActivation{ActivationID: "act-1", Generation: 1, SpecRevision: 1, ForwardID: "fwd-1"}
	if err := a.Validate(); err != nil {
		t.Fatalf("valid activation rejected: %v", err)
	}
	bad := a
	bad.ActivationID = ""
	if err := bad.Validate(); err == nil {
		t.Fatal("activation without id accepted")
	}
	bad2 := a
	bad2.ForwardID = ""
	if err := bad2.Validate(); err == nil {
		t.Fatal("activation without forward id accepted")
	}
}

// activationAxisForTest mirrors the frozen axes for enum coverage.
type axisForTest struct {
	name   string
	values []string
}

var activationAxesForTest = []axisForTest{
	{"control_state", []string{"ONLINE", "OFFLINE"}},
	{"listener_state", []string{"STOPPED", "STARTING", "READY", "ERROR"}},
	{"mapping_state", []string{"NOT_REQUIRED", "ACQUIRING", "FIRST_HOP_MAPPED", "PUBLIC_CANDIDATE", "LOST", "ERROR"}},
	{"keepalive_state", []string{"NOT_REQUIRED", "HEALTHY", "DEGRADED", "LOST"}},
	{"wan_reachability_state", []string{"NOT_TESTED", "PROBING", "OPEN_FROM_VANTAGE", "REJECTED", "TIMEOUT", "NO_INDEPENDENT_VANTAGE", "PROBE_INFRA_UNAVAILABLE", "UNKNOWN"}},
	{"return_path_state", []string{"NOT_TESTED", "VERIFIED", "FAILED", "UNKNOWN"}},
	{"target_health_state", []string{"PASS", "FAIL", "SKIPPED", "UNSUPPORTED", "UNKNOWN"}},
	{"publication_state", []string{"NONE", "PUBLISHED_VERIFIED", "PUBLISHED_UNVERIFIED", "STALE", "UNPUBLISHED"}},
	{"data_plane_state", []string{"STOPPED", "READY", "DEGRADED", "ERROR"}},
}
