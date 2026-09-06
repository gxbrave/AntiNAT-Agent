package reconcile

import (
	"errors"
	"testing"

	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
)

// TestActivationAxesVaryIndependently covers Story 3 RED: mapping/listener/
// target/WAN/publication states vary independently — updating one axis never
// touches the others.
func TestActivationAxesVaryIndependently(t *testing.T) {
	act := NewActivation("fwd-1", "act-1", 1)

	if err := act.Set(protocol.ActivationStates{
		ControlState: "ONLINE", ListenerState: "READY", MappingState: "NOT_REQUIRED",
		KeepaliveState: "NOT_REQUIRED", WanReachabilityState: "NOT_TESTED",
		ReturnPathState: "NOT_TESTED", TargetHealthState: "UNKNOWN",
		PublicationState: "NONE", DataPlaneState: "READY",
	}); err != nil {
		t.Fatalf("initial snapshot: %v", err)
	}

	// Update ONLY the WAN axis; every other axis must stay untouched.
	if err := act.StartProbe(1); err != nil {
		t.Fatalf("start probe: %v", err)
	}
	snap := act.Snapshot()
	if snap.ListenerState != "READY" || snap.MappingState != "NOT_REQUIRED" ||
		snap.TargetHealthState != "UNKNOWN" || snap.DataPlaneState != "READY" {
		t.Fatalf("independent axis mutated by probe start: %+v", snap)
	}
	if snap.WanReachabilityState != "PROBING" {
		t.Fatalf("wan axis = %q, want PROBING", snap.WanReachabilityState)
	}

	// Update ONLY the target-health axis.
	if err := act.Update("target_health_state", "PASS", 1); err != nil {
		t.Fatalf("target health update: %v", err)
	}
	snap = act.Snapshot()
	if snap.WanReachabilityState != "PROBING" {
		t.Fatalf("wan axis mutated by target update: %+v", snap)
	}
	if snap.TargetHealthState != "PASS" {
		t.Fatalf("target axis = %q, want PASS", snap.TargetHealthState)
	}
}

// TestActivationStaleEventCannotOverwriteCurrentCAS covers Story 3 RED: an
// old event (lower generation) can never overwrite the current CAS — a
// stale probe result must not flip an OPEN_FROM_VANTAGE activation back to
// REJECTED.
func TestActivationStaleEventCannotOverwriteCurrentCAS(t *testing.T) {
	act := NewActivation("fwd-1", "act-1", 1)
	if err := act.Set(protocol.ActivationStates{
		ControlState: "ONLINE", ListenerState: "READY", MappingState: "NOT_REQUIRED",
		KeepaliveState: "NOT_REQUIRED", WanReachabilityState: "OPEN_FROM_VANTAGE",
		ReturnPathState: "VERIFIED", TargetHealthState: "PASS",
		PublicationState: "PUBLISHED_VERIFIED", DataPlaneState: "READY",
	}); err != nil {
		t.Fatalf("initial snapshot: %v", err)
	}

	// Activation advances to generation 2 (spec revision bump).
	act.AdvanceGeneration(2)

	// A stale event from generation 1 must be rejected.
	err := act.Update("wan_reachability_state", "REJECTED", 1)
	if !errors.Is(err, ErrStaleEvent) {
		t.Fatalf("stale event error = %v, want ErrStaleEvent", err)
	}
	snap := act.Snapshot()
	if snap.WanReachabilityState != "OPEN_FROM_VANTAGE" {
		t.Fatalf("stale event overwrote CAS: %+v", snap)
	}
	if snap.PublicationState != "PUBLISHED_VERIFIED" {
		t.Fatalf("stale event overwrote publication: %+v", snap)
	}

	// The current generation update succeeds.
	if err := act.RecordProbeOutcome(protocol.OutcomeRejected, 2); err != nil {
		t.Fatalf("current generation outcome: %v", err)
	}
	// Publication invariant: a rejected probe unpublishes; it can never
	// stay PUBLISHED_VERIFIED.
	snap = act.Snapshot()
	if snap.WanReachabilityState != "REJECTED" {
		t.Fatalf("wan = %q, want REJECTED", snap.WanReachabilityState)
	}
	if snap.PublicationState == "PUBLISHED_VERIFIED" {
		t.Fatalf("publication still PUBLISHED_VERIFIED after WAN rejection")
	}
	if snap.PublicationState != "UNPUBLISHED" {
		t.Fatalf("publication = %q, want UNPUBLISHED", snap.PublicationState)
	}
}

// TestActivationFutureGenerationCannotBypassCAS covers the other side of the
// generation fence: a future event must not mutate the current activation
// while leaving its generation unchanged.
func TestActivationFutureGenerationCannotBypassCAS(t *testing.T) {
	act := NewActivation("fwd-future", "act-future", 1)
	if err := act.Update("wan_reachability_state", "PROBING", 1); err != nil {
		t.Fatalf("start probe state: %v", err)
	}
	if err := act.RecordProbeOutcome(protocol.OutcomeOpenFromVantage, 2); !errors.Is(err, ErrStaleEvent) {
		t.Fatalf("future outcome error = %v, want ErrStaleEvent", err)
	}
	snap := act.Snapshot()
	if snap.WanReachabilityState != "PROBING" || snap.PublicationState != "NONE" {
		t.Fatalf("future event mutated snapshot: %+v", snap)
	}
	if got := act.Generation(); got != 1 {
		t.Fatalf("future event advanced generation to %d", got)
	}
}

// TestActivationEvidenceLossImmediateUnpublish covers Story 3 RED: on local
// evidence loss the old publication is immediately marked stale/unpublished
// (docs/state-model.md §5) before any remap/reprobe is attempted.
func TestActivationEvidenceLossImmediateUnpublish(t *testing.T) {
	act := NewActivation("fwd-1", "act-1", 1)
	if err := act.Set(protocol.ActivationStates{
		ControlState: "ONLINE", ListenerState: "READY", MappingState: "NOT_REQUIRED",
		KeepaliveState: "NOT_REQUIRED", WanReachabilityState: "OPEN_FROM_VANTAGE",
		ReturnPathState: "VERIFIED", TargetHealthState: "PASS",
		PublicationState: "PUBLISHED_VERIFIED", DataPlaneState: "READY",
	}); err != nil {
		t.Fatalf("initial snapshot: %v", err)
	}

	// Route/interface change or lease loss: publication must flip to STALE
	// immediately, and the WAN state must not claim verified reachability.
	if err := act.EvidenceLost(); err != nil {
		t.Fatalf("evidence lost: %v", err)
	}
	snap := act.Snapshot()
	if snap.PublicationState != "STALE" && snap.PublicationState != "UNPUBLISHED" {
		t.Fatalf("publication after evidence loss = %q, want STALE/UNPUBLISHED", snap.PublicationState)
	}
	if snap.WanReachabilityState == "OPEN_FROM_VANTAGE" {
		t.Fatalf("wan still OPEN_FROM_VANTAGE after evidence loss")
	}
	if snap.ReturnPathState == "VERIFIED" {
		t.Fatalf("return path still VERIFIED after evidence loss")
	}

	// A reprobe starts from PROBING, never from a verified state; the stale
	// publication is fully unpublished when the probe cycle begins.
	if err := act.StartProbe(1); err != nil {
		t.Fatalf("reprobe: %v", err)
	}
	snap = act.Snapshot()
	if snap.PublicationState != "UNPUBLISHED" {
		t.Fatalf("publication during reprobe = %q, want UNPUBLISHED", snap.PublicationState)
	}
	if snap.WanReachabilityState != "PROBING" {
		t.Fatalf("wan during reprobe = %q, want PROBING", snap.WanReachabilityState)
	}
}

// RED R7-2: a process restart must invalidate the old proof before the
// recovered listener can be considered for publication. The old verified
// snapshot is retained only as an explicitly unverified publication.
func TestActivationRecoveryCannotRestoreVerifiedPublication(t *testing.T) {
	act := NewActivation("fwd-restart", "act-restart", 1)
	if err := act.Set(protocol.ActivationStates{
		ControlState: "ONLINE", ListenerState: "READY", MappingState: "PUBLIC_CANDIDATE",
		KeepaliveState: "HEALTHY", WanReachabilityState: "OPEN_FROM_VANTAGE",
		ReturnPathState: "VERIFIED", TargetHealthState: "PASS",
		PublicationState: "PUBLISHED_VERIFIED", DataPlaneState: "READY",
	}); err != nil {
		t.Fatalf("verified snapshot: %v", err)
	}
	if err := act.RecoverAfterRestart(); err != nil {
		t.Fatalf("RecoverAfterRestart: %v", err)
	}
	snap := act.Snapshot()
	if snap.WanReachabilityState != "NOT_TESTED" || snap.ReturnPathState != "NOT_TESTED" {
		t.Fatalf("recovered evidence = %+v, want NOT_TESTED axes", snap)
	}
	if snap.PublicationState != "PUBLISHED_UNVERIFIED" {
		t.Fatalf("recovered publication = %q, want PUBLISHED_UNVERIFIED", snap.PublicationState)
	}
}

// TestActivationPublicationTruthInvariants covers the frozen cross-axis
// rules: PUBLISHED_VERIFIED requires OPEN_FROM_VANTAGE + VERIFIED return
// path, and PUBLISHED_UNVERIFIED never claims OPEN_FROM_VANTAGE.
func TestActivationPublicationTruthInvariants(t *testing.T) {
	act := NewActivation("fwd-1", "act-1", 1)

	// Illegal: PUBLISHED_VERIFIED without OPEN_FROM_VANTAGE.
	err := act.Update("publication_state", "PUBLISHED_VERIFIED", 1)
	if err == nil {
		t.Fatal("PUBLISHED_VERIFIED without OPEN_FROM_VANTAGE accepted")
	}

	// Legal: PUBLISHED_UNVERIFIED while NOT_TESTED.
	if err := act.Update("publication_state", "PUBLISHED_UNVERIFIED", 1); err != nil {
		t.Fatalf("PUBLISHED_UNVERIFIED with NOT_TESTED: %v", err)
	}

	// Illegal: PUBLISHED_UNVERIFIED must never claim OPEN_FROM_VANTAGE.
	act2 := NewActivation("fwd-2", "act-2", 1)
	if err := act2.Update("wan_reachability_state", "OPEN_FROM_VANTAGE", 1); err != nil {
		t.Fatalf("wan open: %v", err)
	}
	if err := act2.Update("return_path_state", "VERIFIED", 1); err != nil {
		t.Fatalf("return verified: %v", err)
	}
	if err := act2.Update("publication_state", "PUBLISHED_UNVERIFIED", 1); err == nil {
		t.Fatal("PUBLISHED_UNVERIFIED with OPEN_FROM_VANTAGE accepted")
	}

	// Full verified chain is legal.
	if err := act2.Update("publication_state", "PUBLISHED_VERIFIED", 1); err != nil {
		t.Fatalf("PUBLISHED_VERIFIED with full chain: %v", err)
	}
}
