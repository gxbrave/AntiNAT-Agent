// P14 Story 1: crash-safe Forward deletion and orphaned-journal evacuation.
//
// The Forward delete FSM itself (durable ABSENT intent, tombstone-before-stop,
// best-effort mapping release through the P12W forwardLease.Release, durable
// receipt/GC) is integrated prior to P14. This file owns the pieces P12W
// explicitly deferred: decoding the adapter-private JournalRecord.State back
// to the typed renewal/delete state (no such decoder existed), authoritatively
// evacuating orphaned/superseded journal records with the decode, and the
// same-revision applied-record MappingJournalRef refresh that restart recovery
// performs so a re-acquired mapping is reflected in the durable LKG without
// moving SpecRevision.
package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
	"github.com/gxbrave/AntiNAT-Agent/internal/traversal"
	"github.com/gxbrave/AntiNAT-Agent/internal/traversal/natpmp"
	"github.com/gxbrave/AntiNAT-Agent/internal/traversal/pcp"
	"github.com/gxbrave/AntiNAT-Agent/internal/traversal/upnp"
)

// ErrUndecodableJournalState reports a journal record whose adapter State
// cannot be decoded for a known mechanism. The record is surfaced to the
// operator (never silently dropped) and kept for manual reconciliation.
var ErrUndecodableJournalState = errors.New("reconcile: cannot decode journal state")

// MapperRegistry maps a traversal mechanism to the adapter that owns it. The
// composed Agent surfaces one authoritative adapter set here exactly as it
// registers the adapters into the Manager/Detector (P12W Story 2), so an
// evacuation dispatches the decoded mapping to the same adapter the
// acquisition used.
type MapperRegistry map[traversal.MappingLayerKind]traversal.GatewayMapper

// DecodeJournalState restores the typed adapter renewal/delete state recorded
// in one journal record (P12W deferred: the State []byte is adapter JSON that
// only the mechanism knows how to re-interpret). The resulting GatewayMapping
// carries the typed State so the owning adapter's Renew/Delete can be invoked
// after a restart with the real gateway authority (PCP nonce, NAT-PMP tuple,
// UPnP record).
func DecodeJournalState(record traversal.JournalRecord) (traversal.GatewayMapping, error) {
	mapping := traversal.GatewayMapping{
		Mechanism:    record.Mechanism,
		InternalIP:   parseV4Addr(record.InternalIP),
		InternalPort: record.InternalPort,
		Identity:     record.Identity,
	}
	var external netip.AddrPort
	if record.ExternalIP != "" {
		external = netip.AddrPortFrom(parseV4Addr(record.ExternalIP), record.ExternalPort)
	}
	switch record.Mechanism {
	case traversal.LayerPCP:
		var st pcp.MapResult
		if err := json.Unmarshal(record.State, &st); err != nil {
			return mapping, fmt.Errorf("%w: pcp: %v", ErrUndecodableJournalState, err)
		}
		mapping.State = st
		if !external.IsValid() && st.AssignedExternalAddress.IsValid() {
			external = netip.AddrPortFrom(st.AssignedExternalAddress, st.AssignedExternalPort)
		}
		if mapping.InternalIP == (netip.Addr{}) && st.InternalAddress.IsValid() {
			mapping.InternalIP = st.InternalAddress
		}
		if mapping.InternalPort == 0 && st.InternalPort != 0 {
			mapping.InternalPort = st.InternalPort
		}
	case traversal.LayerNATPMP:
		var st natpmp.MapResult
		if err := json.Unmarshal(record.State, &st); err != nil {
			return mapping, fmt.Errorf("%w: nat-pmp: %v", ErrUndecodableJournalState, err)
		}
		mapping.State = st
		if mapping.InternalPort == 0 && st.InternalPort != 0 {
			mapping.InternalPort = st.InternalPort
		}
		if !external.IsValid() && st.AssignedExternalPort != 0 {
			// NAT-PMP carries only the assigned port; the external address is
			// the gateway WAN IP which only the adapter knows. The adapter's
			// Delete key is the exact tuple, not the external address.
			external = netip.AddrPortFrom(netip.IPv4Unspecified(), st.AssignedExternalPort)
		}
	case traversal.LayerUPnP:
		var st upnp.MapResult
		if err := json.Unmarshal(record.State, &st); err != nil {
			return mapping, fmt.Errorf("%w: upnp: %v", ErrUndecodableJournalState, err)
		}
		mapping.State = st
		if mapping.InternalIP == (netip.Addr{}) && st.InternalAddress != "" {
			mapping.InternalIP = parseV4Addr(st.InternalAddress)
		}
		if mapping.InternalPort == 0 && st.InternalPort != 0 {
			mapping.InternalPort = st.InternalPort
		}
		if !external.IsValid() && st.AssignedExternalPort != 0 {
			external = netip.AddrPortFrom(st.AssignedExternalAddress, st.AssignedExternalPort)
		}
	default:
		return mapping, fmt.Errorf("%w: mechanism %q has no decoder", ErrUndecodableJournalState, record.Mechanism)
	}
	if !external.IsValid() {
		return mapping, fmt.Errorf("%w: record %q has no decodable external tuple", ErrUndecodableJournalState, record.ID)
	}
	if mapping.InternalIP == (netip.Addr{}) || mapping.InternalPort == 0 {
		return mapping, fmt.Errorf("%w: record %q has no decodable internal tuple", ErrUndecodableJournalState, record.ID)
	}
	mapping.External = external
	return mapping, nil
}

func parseV4Addr(s string) netip.Addr {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap()
}

// EvacuationReport summarizes one orphaned-journal evacuation pass.
type EvacuationReport struct {
	// Evacuated lists the journal records deleted this pass.
	Evacuated []string
	// Kept lists orphaned/superseded records deliberately retained because
	// their State could not be decoded (authoritative gateway release is
	// impossible, so the record stays for operator reconciliation).
	Kept []traversal.JournalRecord
	// Refreshed lists applied forwards whose MappingJournalRef was updated at
	// the same SpecRevision by this pass.
	Refreshed []string
	// ReleaseErrors lists the per-record authoritative release failures
	// (best-effort gateway delete). The journal record is retained on error so
	// a later pass can retry the exact record.
	ReleaseErrors []string
}

// EvacuateOrphanedJournals reconciles the durable mapping journal against the
// durable applied/tombstone records and EVACUATES the boundary:
//
//   - A journal record whose Forward owns neither a live applied row nor a
//     durable delete fence is orphaned: no durable fact requires it, so its
//     gateway mapping is released via the mechanism adapter (State decoded to
//     the typed renewal/delete authority) and the record is deleted.
//   - A journal record that is the applied ref of a live applied forward is
//     the durable LKG reference: it is never deleted.
//   - A journal record whose ID is in liveRefs is the LIVE acquisition's
//     current record: it is retained EVEN IF the durable applied ref is empty
//     or stale (repair-1 M4 keeps the authoritative live mapping set as a
//     first-class retention input so a live gateway forward with an
//     un-refreshed applied row is never released as orphaned).
//   - An applied forward whose MappingJournalRef points at a journal record
//     that no longer exists has a dangling reference: the applied record is
//     refreshed at the same revision to an empty ref so restart recovery
//     cannot try to renew a mapping that is already gone.
//
// Every delete/refresh is one bbolt transaction (applied/tombstone rows are
// transactionally adjacent to the journal bucket). A record whose State fails
// decode is retained (Kept) and never dropped silently: releasing a live
// gateway mapping is an external side effect that must only run when the
// decode is authoritative.
func EvacuateOrphanedJournals(ctx context.Context, store *localstate.Store, mappers MapperRegistry, liveRefs map[string]string) (EvacuationReport, error) {
	var report EvacuationReport
	if store == nil {
		return report, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	journal := store.MappingJournal()
	records, err := journal.List()
	if err != nil {
		return report, fmt.Errorf("reconcile: evacuation journal list: %w", err)
	}
	applied, err := store.ListAppliedRecords()
	if err != nil {
		return report, fmt.Errorf("reconcile: evacuation applied list: %w", err)
	}
	// Even with an empty journal (the common case), a dangling applied ref must
	// be refreshed: there is nothing to iterate below, so the early-exit is
	// only allowed after the dangling-ref check has run.
	if len(records) == 0 && len(applied) == 0 {
		return report, nil
	}
	// liveIDs is the set of journal record ids backing LIVE acquisitions
	// (repair-1 M4). A live mapping is never released on a stale/empty applied
	// ref, so its record joins the retention set below.
	liveIDs := make(map[string]bool, len(liveRefs))
	for _, id := range liveRefs {
		if id != "" {
			liveIDs[id] = true
		}
	}
	appliedRefs := make(map[string]string, len(applied))
	appliedRevs := make(map[string]uint64, len(applied))
	for _, rec := range applied {
		if rec.State.MappingJournalRef != "" {
			appliedRefs[rec.State.ForwardID] = rec.State.MappingJournalRef
		}
		appliedRevs[rec.State.ForwardID] = rec.State.SpecRevision
	}
	tombstones, err := store.ListTombstones()
	if err != nil {
		return report, fmt.Errorf("reconcile: evacuation tombstone list: %w", err)
	}
	tombstoned := make(map[string]bool, len(tombstones))
	for _, ts := range tombstones {
		tombstoned[ts.ForwardID] = true
	}
	intents, err := store.ListForwardDeleteIntents()
	if err != nil {
		return report, fmt.Errorf("reconcile: evacuation delete intent list: %w", err)
	}
	fenced := make(map[string]bool, len(intents))
	for _, intent := range intents {
		fenced[intent.ForwardID] = true
	}

	existing := make(map[string]bool, len(records))
	for _, r := range records {
		existing[r.ID] = true
	}

	// Dangling applied refs (vice-versa boundary): the applied record points at
	// a journal record that no longer exists. Refresh to empty at the same
	// revision so recovery never renews a vanished mapping.
	for forwardID, ref := range appliedRefs {
		if !existing[ref] {
			updated, err := store.RefreshAppliedJournalRef(forwardID, "")
			if err != nil {
				return report, err
			}
			if updated {
				report.Refreshed = append(report.Refreshed, forwardID)
			}
		}
	}

	var evacuateIDs []string
	for _, record := range records {
		if record.ForwardID == "" {
			// A detection-temp mapping with no owning forward is orphaned but its
			// State is not required to carry a live forward; keep it unless it
			// decodes AND is a gateway mechanism. Anyone without a forward could
			// be an in-flight detection record owned by a controller operation.
			continue
		}
		_, appliedRef := appliedRefs[record.ForwardID]
		_, isTombstoned := tombstoned[record.ForwardID]
		_, isFenced := fenced[record.ForwardID]
		if liveIDs[record.ID] || appliedRef || isTombstoned || isFenced {
			// A LIVE backing record (repair-1 M4), a durable fact (LKG applied
			// ref, tombstone, or pending delete intent) retains the record.
			// Recovery/apply paths own those.
			continue
		}
		// Orphaned: no durable fact describes this forward. Decode and release
		// the mapping authority, then delete the record.
		decoded, decodeErr := DecodeJournalState(record)
		if decodeErr != nil {
			report.Kept = append(report.Kept, record)
			continue
		}
		mapper := mappers[decoded.Mechanism]
		if mapper == nil {
			report.Kept = append(report.Kept, record)
			continue
		}
		if err := mapper.Delete(ctx, decoded); err != nil {
			report.ReleaseErrors = append(report.ReleaseErrors, record.ID)
			continue
		}
		evacuateIDs = append(evacuateIDs, record.ID)
	}
	if len(evacuateIDs) != 0 {
		if err := store.EvacuateJournalRecords(evacuateIDs); err != nil {
			return report, err
		}
		report.Evacuated = evacuateIDs
	}
	return report, nil
}

// DeleteForwardOnce drives one explicit ABSENT Forward through the P14 delete
// FSM: durable intent (already installed by the caller's desired snapshot),
// stop side effect (releases the forwardLease: listener + mapping + journal
// together), and durable result recording. It is the reconcile-level
// completion helper the data plane and command handlers share.
func DeleteForwardOnce(ctx context.Context, store *localstate.Store, spec protocol.ForwardSpec, stop StopHook) error {
	if spec.Presence != protocol.PresenceAbsent || spec.DeletionOperationID == "" {
		return errors.New("reconcile: DeleteForwardOnce requires an ABSENT spec with a deletion_operation_id")
	}
	if _, err := store.PutForwardDeleteIntent(localstate.ForwardDeleteIntent{
		ForwardID: spec.ForwardID, DeletionOperationID: spec.DeletionOperationID,
		DesiredRevision: spec.DesiredRevision,
	}); err != nil {
		return err
	}
	if stop != nil {
		if err := stop(ctx, spec.ForwardID); err != nil {
			return err
		}
	}
	return store.CompleteForwardDeleteIntent(spec.ForwardID, spec.DeletionOperationID)
}
