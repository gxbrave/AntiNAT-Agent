// P12W Story 3: strategy-aware TCP acquisition through the Manager, preserving
// actor topology. A same-ID hot update with unchanged transport+strategy keeps
// the SAME acquisition (journal ref unchanged, no new journal record), the
// applied state carries the acquisition evidence, and a strategy change fails
// closed like the frozen transport-change rule.
package agent

import (
	"context"
	"testing"

	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
)

// Story 3 (a): the applied state carries the acquisition evidence — the
// journal ref matches the acquisition's JournalID and AssignedGatewayPort is
// the mapping's external port.
func TestDataPlaneGatewayApplySurfacesAcquisitionEvidence(t *testing.T) {
	d, _, _, _ := p12wGatewayComposition(t)
	spec := protocol.ForwardSpec{
		ForwardID:       "fwd-gateway-evidence",
		Protocol:        protocol.ProtocolTCP,
		Target:          "127.0.0.1:9",
		Strategy:        protocol.StrategyExplicitGateway,
		DesiredRevision: 1,
		Presence:        protocol.PresencePresent,
	}
	applied, err := d.apply(context.Background(), spec)
	if err != nil {
		t.Fatalf("apply explicit-gateway: %v", err)
	}
	d.mu.Lock()
	actor := d.forwards[spec.ForwardID]
	d.mu.Unlock()
	if actor == nil || actor.acq == nil {
		t.Fatal("gateway actor missing")
	}
	if applied.MappingJournalRef != actor.acq.JournalID {
		t.Fatalf("mapping_journal_ref = %q, want the acquisition journal id %q", applied.MappingJournalRef, actor.acq.JournalID)
	}
	if mapping := actor.acq.CurrentMapping(); mapping == nil || applied.AssignedGatewayPort != mapping.External.Port() {
		t.Fatalf("assigned_gateway_port = %d, want the mapping external port", applied.AssignedGatewayPort)
	}
	if applied.PublicPort != actor.acq.Verdict.Candidate.Port() {
		t.Fatalf("public_port = %d, want the verdict candidate port %d", applied.PublicPort, actor.acq.Verdict.Candidate.Port())
	}
}

// Story 3 (b): a same-ID hot update with the same transport+strategy keeps
// the SAME acquisition running — the journal ref is unchanged and no new
// journal record is created.
func TestDataPlaneGatewayHotUpdateKeepsSameAcquisition(t *testing.T) {
	d, mapper, _, journal := p12wGatewayComposition(t)

	mk := func(revision uint64, target string) protocol.ForwardSpec {
		return protocol.ForwardSpec{
			ForwardID:       "fwd-gateway-hot",
			Protocol:        protocol.ProtocolTCP,
			Target:          target,
			Strategy:        protocol.StrategyExplicitGateway,
			DesiredRevision: revision,
			Presence:        protocol.PresencePresent,
		}
	}
	first, err := d.apply(context.Background(), mk(1, "127.0.0.1:10"))
	if err != nil {
		t.Fatalf("initial apply: %v", err)
	}
	d.mu.Lock()
	actor := d.forwards["fwd-gateway-hot"]
	d.mu.Unlock()
	if actor == nil || actor.acq == nil {
		t.Fatal("gateway actor missing after initial apply")
	}
	journalBefore, err := journal.ListByForward("fwd-gateway-hot")
	if err != nil || len(journalBefore) != 1 {
		t.Fatalf("journal before hot update = %d records (%v)", len(journalBefore), err)
	}
	firstRef := first.MappingJournalRef

	second, err := d.apply(context.Background(), mk(2, "127.0.0.1:11"))
	if err != nil {
		t.Fatalf("hot update apply: %v", err)
	}
	d.mu.Lock()
	actorAfter := d.forwards["fwd-gateway-hot"]
	d.mu.Unlock()
	if actorAfter != actor {
		t.Fatal("hot update replaced the actor instead of preserving it")
	}
	if second.MappingJournalRef != firstRef {
		t.Fatalf("hot update journal ref = %q, want the preserved ref %q", second.MappingJournalRef, firstRef)
	}
	journalAfter, err := journal.ListByForward("fwd-gateway-hot")
	if err != nil || len(journalAfter) != 1 {
		t.Fatalf("journal after hot update = %d records (%v), want 1", len(journalAfter), err)
	}
	if journalAfter[0].ID != firstRef {
		t.Fatal("hot update wrote a new journal record")
	}
	if mapper.deleteCount() != 0 {
		t.Fatalf("hot update released the mapping: deletes = %d", mapper.deleteCount())
	}
}

// Story 3 (c): a strategy change in a same-ID hot update fails closed (mirror
// of the transport-change rule); the existing actor keeps serving.
func TestDataPlaneGatewayHotUpdateRejectsStrategyChange(t *testing.T) {
	d, _, _, _ := p12wGatewayComposition(t)

	gatewaySpec := protocol.ForwardSpec{
		ForwardID:       "fwd-gateway-strategy",
		Protocol:        protocol.ProtocolTCP,
		Target:          "127.0.0.1:20",
		Strategy:        protocol.StrategyExplicitGateway,
		DesiredRevision: 1,
		Presence:        protocol.PresencePresent,
	}
	if _, err := d.apply(context.Background(), gatewaySpec); err != nil {
		t.Fatalf("initial explicit-gateway apply: %v", err)
	}
	changed := gatewaySpec
	changed.Strategy = protocol.StrategyDirectV4
	changed.DesiredRevision = 2
	if _, err := d.apply(context.Background(), changed); err == nil {
		t.Fatal("strategy change hot update must fail closed")
	}
	d.mu.Lock()
	actor := d.forwards["fwd-gateway-strategy"]
	d.mu.Unlock()
	if actor == nil || actor.strategy != protocol.StrategyExplicitGateway {
		t.Fatal("strategy change torn down the existing gateway actor")
	}
}
