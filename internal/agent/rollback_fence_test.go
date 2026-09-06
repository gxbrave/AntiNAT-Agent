package agent

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/reconcile"
	"github.com/gxbrave/AntiNAT-Agent/internal/forward"
	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
	"github.com/gxbrave/AntiNAT-Agent/internal/traversal"
)

func TestDataPlaneRollbackRejectsSupersededHotUpdate(t *testing.T) {
	d := newDataPlane(dataPlaneConfig{Clock: time.Now})
	d.capabilityReady = true
	lease, err := d.registry.Acquire(context.Background(), "fence-forward", traversal.TupleKey{
		Address: "127.0.0.1", Family: "ipv4", Protocol: "tcp",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lease.Release() })
	backend, err := forward.NewBackend("10.0.0.1:80")
	if err != nil {
		t.Fatal(err)
	}
	actor := &forwardActor{
		lease:       registryLease{lease: lease},
		backend:     backend,
		updateFence: reconcile.NewSideEffectFence(),
	}
	d.forwards["fence-forward"] = actor

	spec2 := rollbackFenceSpec("fence-forward", "10.0.0.2:81", 2)
	fence2 := reconcile.NewSideEffectFence()
	effect2, err := d.apply(reconcile.WithSideEffectFence(context.Background(), fence2), spec2)
	if err != nil {
		t.Fatalf("revision 2 apply: %v", err)
	}
	spec3 := rollbackFenceSpec("fence-forward", "10.0.0.3:82", 3)
	fence3 := reconcile.NewSideEffectFence()
	if _, err := d.apply(reconcile.WithSideEffectFence(context.Background(), fence3), spec3); err != nil {
		t.Fatalf("revision 3 apply: %v", err)
	}

	previous := rollbackFenceSpec("fence-forward", "10.0.0.1:80", 1)
	err = d.rollback(reconcile.WithSideEffectFence(context.Background(), fence2), previous, effect2)
	if !errors.Is(err, reconcile.ErrStaleSideEffect) {
		t.Fatalf("stale rollback error = %v, want ErrStaleSideEffect", err)
	}
	if got := backend.Target(); got != netip.MustParseAddrPort("10.0.0.3:82") {
		t.Fatalf("backend target after stale rollback = %s, want revision 3 target", got)
	}
	if actor.updateSeq != 2 {
		t.Fatalf("actor fence after stale rollback sequence = %d, want 2", actor.updateSeq)
	}
}

func rollbackFenceSpec(id, target string, revision uint64) protocol.ForwardSpec {
	return protocol.ForwardSpec{
		ForwardID: id, Protocol: protocol.ProtocolTCP, Target: target,
		Strategy: protocol.StrategyDirectV4, DesiredRevision: revision,
		Presence: protocol.PresencePresent,
	}
}

func rollbackFenceApplied(id string, revision uint64, lease *traversal.Lease) protocol.AppliedForwardState {
	return protocol.AppliedForwardState{
		ForwardID: id, SpecRevision: revision, DesiredRevision: revision,
		ActualBindHost: lease.Actual.Address, ActualBindPort: lease.Actual.Port,
		Strategy: "direct-v4", LayerVersion: 1, AppliedAtUnix: time.Now().Unix(),
	}
}
