// P14 repair-1 M5: the decommission terminal latch must gate dataPlane.recover
// and finishReopen so a recover in the Begin->Complete window (a liveness
// fingerprint-change rebuild, or a cleanup-retry) never reopens applied LKG rows
// that stop-all is tearing down. The in-memory marker also flips to
// DECOMMISSIONING at Begin so runDetectionOnce/monitorLiveness stop immediately.
package agent

import (
	"context"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
	"github.com/gxbrave/AntiNAT-Agent/internal/traversal"
)

func seedGatewayApplied(t *testing.T, d *dataPlane) {
	t.Helper()
	st := d.cfg.Store
	oldRef := "fwd-m5-STALE"
	if err := st.MappingJournal().Put(traversal.JournalRecord{
		ID: oldRef, ForwardID: "fwd-m5", Mechanism: traversal.LayerPCP,
		Ownership: traversal.OwnershipStrong, Protocol: "tcp",
	}); err != nil {
		t.Fatal(err)
	}
	gwSpec := protocol.ForwardSpec{
		ForwardID: "fwd-m5", Protocol: protocol.ProtocolTCP, Target: "127.0.0.1:9",
		Strategy: protocol.StrategyExplicitGateway, DesiredRevision: 1, Presence: protocol.PresencePresent,
	}
	seeded := protocol.AppliedForwardState{
		ForwardID: "fwd-m5", SpecRevision: 1, DesiredRevision: 1,
		ActualBindHost: "10.0.0.2", ActualBindPort: 23456,
		Strategy: "explicit-gateway", LayerVersion: 1,
		MappingJournalRef: oldRef, AppliedAtUnix: time.Now().Unix(),
	}
	if _, err := st.CommitDesired(protocol.DesiredState{NodeID: "node-m5", Forwards: []protocol.ForwardSpec{gwSpec}},
		[]localstate.ForwardApply{{ForwardID: "fwd-m5", Outcome: localstate.ApplyApplied, Applied: &seeded}}); err != nil {
		t.Fatal(err)
	}
}

// TestDataPlaneRecoverOpenBeforeDecommissionBaseline proves the harness reopens
// the applied gateway forward when the terminal latch is NOT engaged (the
// behavior a decommission must suppress).
func TestDataPlaneRecoverOpenBeforeDecommissionBaseline(t *testing.T) {
	_, d, _, _ := p12wRecoveryApp(t)
	latch := localstate.NewLatch()
	d.cfg.TerminalEngaged = latch.Engaged
	seedGatewayApplied(t, d)

	if _, err := d.recover(context.Background()); err != nil {
		t.Fatalf("recover: %v", err)
	}
	d.mu.Lock()
	actor := d.forwards["fwd-m5"]
	d.mu.Unlock()
	if actor == nil || actor.acq == nil {
		t.Fatal("baseline: recover did not reopen the applied gateway forward")
	}
}

// TestDataPlaneRecoverSkipsReopenOnceTerminalEngaged is the Begin->Complete
// window probe: a forward that was live and is being torn down must NOT come
// back if a recover runs after the decommission latch engages.
func TestDataPlaneRecoverSkipsReopenOnceTerminalEngaged(t *testing.T) {
	_, d, _, _ := p12wRecoveryApp(t)
	latch := localstate.NewLatch()
	d.cfg.TerminalEngaged = latch.Engaged
	seedGatewayApplied(t, d)

	// The forward is live before the decommission begins.
	if _, err := d.recover(context.Background()); err != nil {
		t.Fatalf("recover before decommission: %v", err)
	}
	d.mu.Lock()
	live := d.forwards["fwd-m5"] != nil
	d.mu.Unlock()
	if !live {
		t.Fatal("precondition: forward should be live before Begin")
	}

	// Begin engages the terminal latch (the DECOMMISSIONING marker is durable).
	if !latch.TryEngage() {
		t.Fatal("terminal latch could not engage")
	}
	// stop-all tears the forward down.
	if err := d.stop(context.Background(), "fwd-m5"); err != nil {
		t.Fatalf("stop: %v", err)
	}
	d.mu.Lock()
	afterStop := d.forwards["fwd-m5"] != nil
	d.mu.Unlock()
	if afterStop {
		t.Fatal("forward still live after stop-all")
	}

	// A concurrent cleanup-retry / liveness recover in the window must NOT
	// reopen the applied LKG row.
	if _, err := d.recover(context.Background()); err != nil {
		t.Fatalf("recover in decommission window: %v", err)
	}
	d.mu.Lock()
	resurrected := d.forwards["fwd-m5"] != nil
	d.mu.Unlock()
	if resurrected {
		t.Fatal("decommission window recover resurrected an applied LKG row (terminal latch ignored)")
	}
}
