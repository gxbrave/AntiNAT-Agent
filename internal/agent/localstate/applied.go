// Received desired state and per-Forward applied state (docs/state-model.md
// §2, v0.8 §6.4 / §7.1).
//
// CommitDesired applies a desired snapshot with one atomic bbolt transaction
// and per-resource PARTIAL semantics: an apply failure retains the Forward's
// old applied record while its siblings advance. A desired snapshot that
// merely omits a Forward never implies deletion; only an explicit ABSENT with
// a deletion_operation_id does (and that path writes a durable tombstone,
// tombstone.go).
package localstate

import (
	"encoding/json"
	"errors"
	"fmt"

	bolt "go.etcd.io/bbolt"

	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
)

// ApplyOutcome is the per-resource result of reconciling one desired Forward.
type ApplyOutcome int

const (
	// ApplyApplied records a newly applied Forward state.
	ApplyApplied ApplyOutcome = iota
	// ApplyFailed retains the old applied state (hook/apply error).
	ApplyFailed
	// ApplyDeleted writes the durable tombstone and removes applied state.
	ApplyDeleted
	// ApplySkipped writes nothing and counts as neither a success nor a
	// failure (e.g. an old-revision duplicate or a policy rejection already
	// decided by the reconcile layer).
	ApplySkipped
)

// ForwardApply is one per-Forward decision handed to CommitDesired. Exactly
// one outcome per Forward in the desired snapshot is required.
type ForwardApply struct {
	ForwardID string
	Outcome   ApplyOutcome
	// Applied is set for ApplyApplied and must itself pass
	// protocol.AppliedForwardState.Validate.
	Applied *protocol.AppliedForwardState
	// Err carries the apply error for ApplyFailed.
	Err error
}

// appliedRecord keeps the serving target beside the durable applied LKG while
// preserving the frozen AppliedForwardState fields at the top level. The
// decoder accepts legacy rows that contain only AppliedForwardState; new
// successful applies always write the complete ForwardSpec needed for restart
// recovery.
type appliedRecord struct {
	protocol.AppliedForwardState
	ServingSpec *protocol.ForwardSpec `json:"serving_spec,omitempty"`
}

func encodeAppliedRecord(state protocol.AppliedForwardState, spec protocol.ForwardSpec) ([]byte, error) {
	return json.Marshal(appliedRecord{AppliedForwardState: state, ServingSpec: &spec})
}

func decodeAppliedRecord(raw []byte) (protocol.AppliedForwardState, protocol.ForwardSpec, bool, error) {
	var record appliedRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return protocol.AppliedForwardState{}, protocol.ForwardSpec{}, false, err
	}
	if record.ForwardID != "" {
		if record.ServingSpec == nil {
			return record.AppliedForwardState, protocol.ForwardSpec{}, false, nil
		}
		return record.AppliedForwardState, *record.ServingSpec, true, nil
	}
	// Keep malformed legacy rows visible to the common validator instead of
	// treating an empty embedded record as a successful new-format decode.
	return record.AppliedForwardState, protocol.ForwardSpec{}, false, nil
}

// AppliedStateRecord is the validated durable applied state plus its complete
// serving target. HasServingSpec is false only for legacy rows written before
// serving-target persistence was introduced.
type AppliedStateRecord struct {
	State          protocol.AppliedForwardState
	ServingSpec    protocol.ForwardSpec
	HasServingSpec bool
}

func validateAppliedRecord(key string, state protocol.AppliedForwardState, spec protocol.ForwardSpec, hasSpec bool) error {
	if err := state.Validate(); err != nil {
		return err
	}
	if key != "" && state.ForwardID != key {
		return fmt.Errorf("localstate: applied record forward_id %q does not match key %q", state.ForwardID, key)
	}
	if !hasSpec {
		return nil
	}
	if err := spec.Validate(); err != nil {
		return fmt.Errorf("localstate: serving spec for %q: %w", state.ForwardID, err)
	}
	if spec.ForwardID != state.ForwardID {
		return fmt.Errorf("localstate: serving spec forward_id %q does not match applied record %q", spec.ForwardID, state.ForwardID)
	}
	if spec.Presence != protocol.PresencePresent || spec.DesiredRevision != state.SpecRevision {
		return fmt.Errorf("localstate: serving spec for %q does not match applied revision %d", state.ForwardID, state.SpecRevision)
	}
	if string(spec.Strategy) != state.Strategy {
		return fmt.Errorf("localstate: serving spec strategy %q does not match applied strategy %q", spec.Strategy, state.Strategy)
	}
	return nil
}

func loadAppliedRecordTx(bucket *bolt.Bucket, key string) (AppliedStateRecord, bool, error) {
	raw := bucket.Get([]byte(key))
	if raw == nil {
		return AppliedStateRecord{}, false, nil
	}
	state, spec, hasSpec, err := decodeAppliedRecord(raw)
	if err != nil {
		return AppliedStateRecord{}, false, fmt.Errorf("localstate: decode applied state for %q: %w", key, err)
	}
	if err := validateAppliedRecord(key, state, spec, hasSpec); err != nil {
		return AppliedStateRecord{}, false, fmt.Errorf("localstate: applied state for %q: %w", key, err)
	}
	return AppliedStateRecord{State: state, ServingSpec: spec, HasServingSpec: hasSpec}, true, nil
}

func validateAppliedBucketTx(bucket *bolt.Bucket) error {
	return bucket.ForEach(func(key, raw []byte) error {
		state, spec, hasSpec, err := decodeAppliedRecord(raw)
		if err != nil {
			return fmt.Errorf("localstate: decode applied state for %q: %w", string(key), err)
		}
		if err := validateAppliedRecord(string(key), state, spec, hasSpec); err != nil {
			return fmt.Errorf("localstate: applied state for %q: %w", string(key), err)
		}
		return nil
	})
}

func equivalentAppliedState(a, b protocol.AppliedForwardState) bool {
	// AppliedAtUnix records when the successful apply was observed, not the
	// serving identity. A duplicate result at the same revisions may therefore
	// carry a newer observation timestamp without changing the LKG semantics.
	a.AppliedAtUnix = 0
	b.AppliedAtUnix = 0
	return a == b
}

// ApplyStatus summarizes a CommitDesired batch.
type ApplyStatus int

const (
	// ApplyStatusFull means no Forward failed to apply.
	ApplyStatusFull ApplyStatus = iota
	// ApplyStatusPartial means some Forwards applied while others failed.
	ApplyStatusPartial
	// ApplyStatusFailed means no Forward made progress.
	ApplyStatusFailed
)

func (s ApplyStatus) String() string {
	switch s {
	case ApplyStatusFull:
		return "FULL"
	case ApplyStatusPartial:
		return "PARTIAL"
	case ApplyStatusFailed:
		return "FAILED"
	}
	return "UNKNOWN"
}

// ApplyReport summarizes a CommitDesired batch.
type ApplyReport struct {
	Status         ApplyStatus
	AppliedCount   int
	DeletedCount   int
	FailedCount    int
	FailedForwards []string
}

// ErrDesiredRevisionConflict reports two different specifications carrying the
// same per-Forward desired revision. Treating that as a last-writer-wins update
// would make recovery depend on message arrival order rather than durable
// intent, so the merge fails closed.
var ErrDesiredRevisionConflict = errors.New("localstate: desired revision conflict")

// ErrAppliedRevisionConflict reports an apply result that would move a durable
// last-known-good record backwards. The received desired view may still be
// retained by a later retry, but the applied record must never regress.
var ErrAppliedRevisionConflict = errors.New("localstate: applied revision conflict")

// mergeDesiredSnapshots merges desired entries independently by ForwardID.
// Omission is not deletion: entries present only in current are retained.
// Higher revisions replace lower ones; equal revisions must carry byte-for-byte
// equivalent Go values or the merge is rejected as conflicting intent.
func mergeDesiredSnapshots(current, incoming protocol.DesiredState) (protocol.DesiredState, error) {
	if current.NodeID == "" {
		return incoming, nil
	}
	if current.NodeID != incoming.NodeID {
		return protocol.DesiredState{}, fmt.Errorf("localstate: desired node mismatch: current %q, incoming %q", current.NodeID, incoming.NodeID)
	}
	if err := current.Validate(); err != nil {
		return protocol.DesiredState{}, fmt.Errorf("localstate: stored desired: %w", err)
	}
	merged := current
	index := make(map[string]int, len(merged.Forwards)+len(incoming.Forwards))
	for i, spec := range merged.Forwards {
		index[spec.ForwardID] = i
	}
	for _, incomingSpec := range incoming.Forwards {
		at, exists := index[incomingSpec.ForwardID]
		if !exists {
			index[incomingSpec.ForwardID] = len(merged.Forwards)
			merged.Forwards = append(merged.Forwards, incomingSpec)
			continue
		}
		currentSpec := merged.Forwards[at]
		switch {
		case incomingSpec.DesiredRevision > currentSpec.DesiredRevision:
			merged.Forwards[at] = incomingSpec
		case incomingSpec.DesiredRevision < currentSpec.DesiredRevision:
			// A delayed snapshot cannot roll a Forward back.
		case incomingSpec == currentSpec:
			// Idempotent duplicate.
		default:
			return protocol.DesiredState{}, fmt.Errorf("%w: forward %q revision %d", ErrDesiredRevisionConflict, incomingSpec.ForwardID, incomingSpec.DesiredRevision)
		}
	}
	return merged, nil
}

// loadReceivedDesiredTx reads the one received desired snapshot inside an
// existing bbolt transaction. Keeping the read in the caller's write
// transaction makes the monotonic merge atomic with the subsequent write.
func loadReceivedDesiredTx(tx *bolt.Tx) (protocol.DesiredState, bool, error) {
	var desired protocol.DesiredState
	found := false
	err := tx.Bucket([]byte(bucketDesired)).ForEach(func(key, raw []byte) error {
		if found {
			return errors.New("localstate: multiple received desired snapshots in one Agent store")
		}
		if err := json.Unmarshal(raw, &desired); err != nil {
			return fmt.Errorf("localstate: decode received desired: %w", err)
		}
		if err := desired.Validate(); err != nil {
			return fmt.Errorf("localstate: stored desired: %w", err)
		}
		if string(key) != desired.NodeID {
			return fmt.Errorf("localstate: desired node_id %q does not match storage key %q", desired.NodeID, string(key))
		}
		found = true
		return nil
	})
	return desired, found, err
}

// deleteFenceIdentity returns the semantic deletion identity currently
// authoritative for one Forward. A pending intent and a final tombstone may
// coexist while cleanup is in progress; if they disagree, fail closed rather
// than let arrival order decide which delete owns the Forward.
func deleteFenceIdentity(intent ForwardDeleteIntent, pending bool, tombstone ForwardTombstone, tombstoned bool) (string, uint64, bool, error) {
	var operationID string
	var revision uint64
	if pending {
		operationID = intent.DeletionOperationID
		revision = intent.DesiredRevision
	}
	if tombstoned {
		if operationID != "" && tombstone.DeletionOperationID != operationID {
			return "", 0, false, fmt.Errorf("%w: forward %q has pending operation %q and tombstone operation %q", ErrForwardDeleteConflict, tombstone.ForwardID, operationID, tombstone.DeletionOperationID)
		}
		operationID = tombstone.DeletionOperationID
		if tombstone.DesiredRevision != 0 {
			if revision != 0 && tombstone.DesiredRevision != revision {
				return "", 0, false, fmt.Errorf("%w: forward %q has pending revision %d and tombstone revision %d", ErrForwardDeleteConflict, tombstone.ForwardID, revision, tombstone.DesiredRevision)
			}
			revision = tombstone.DesiredRevision
		}
	}
	return operationID, revision, operationID != "", nil
}

func fencedAbsentSpec(spec protocol.ForwardSpec, operationID string, revision uint64) protocol.ForwardSpec {
	spec.Presence = protocol.PresenceAbsent
	spec.DeletionOperationID = operationID
	if revision != 0 {
		spec.DesiredRevision = revision
	}
	return spec
}

// mergeReceivedDesiredWithDeleteFences performs the normal per-Forward
// monotonic merge, except that durable pending/final deletion facts are the
// authority. A higher-revision PRESENT cannot overwrite an ABSENT fence, and
// a matching ABSENT retry can reassert itself over a stale PRESENT retry row.
func mergeReceivedDesiredWithDeleteFences(tx *bolt.Tx, current, incoming protocol.DesiredState) (protocol.DesiredState, error) {
	if current.NodeID != incoming.NodeID {
		return protocol.DesiredState{}, fmt.Errorf("localstate: desired node mismatch: current %q, incoming %q", current.NodeID, incoming.NodeID)
	}
	if err := current.Validate(); err != nil {
		return protocol.DesiredState{}, fmt.Errorf("localstate: stored desired: %w", err)
	}
	merged := current
	index := make(map[string]int, len(merged.Forwards)+len(incoming.Forwards))
	for i, spec := range merged.Forwards {
		index[spec.ForwardID] = i
	}
	fences := tx.Bucket([]byte(bucketForwardDeleteIntents))
	tombstones := tx.Bucket([]byte(bucketTombstones))
	for _, incomingSpec := range incoming.Forwards {
		at, exists := index[incomingSpec.ForwardID]
		intent, pending, err := loadForwardDeleteIntentTx(fences, incomingSpec.ForwardID)
		if err != nil {
			return protocol.DesiredState{}, err
		}
		tombstone, tombstoned, err := loadForwardTombstoneTx(tombstones, incomingSpec.ForwardID)
		if err != nil {
			return protocol.DesiredState{}, err
		}
		operationID, revision, fenced, err := deleteFenceIdentity(intent, pending, tombstone, tombstoned)
		if err != nil {
			return protocol.DesiredState{}, err
		}
		if fenced {
			if incomingSpec.Presence == protocol.PresenceAbsent {
				if incomingSpec.DeletionOperationID != operationID || (revision != 0 && incomingSpec.DesiredRevision != revision) {
					return protocol.DesiredState{}, fmt.Errorf("%w: forward %q", ErrForwardDeleteConflict, incomingSpec.ForwardID)
				}
				// A matching ABSENT is the only retry allowed to overwrite a
				// stale PRESENT received row. Keep its concrete target fields.
				if exists {
					merged.Forwards[at] = incomingSpec
				} else {
					index[incomingSpec.ForwardID] = len(merged.Forwards)
					merged.Forwards = append(merged.Forwards, incomingSpec)
				}
				continue
			}
			// PRESENT is fenced. Preserve a durable ABSENT row when one is
			// already retained; otherwise turn this retry material into a
			// valid ABSENT entry using the authoritative semantic identity.
			if exists && merged.Forwards[at].Presence == protocol.PresenceAbsent {
				currentSpec := merged.Forwards[at]
				if currentSpec.DeletionOperationID != operationID || (revision != 0 && currentSpec.DesiredRevision != revision) {
					return protocol.DesiredState{}, fmt.Errorf("%w: forward %q", ErrForwardDeleteConflict, incomingSpec.ForwardID)
				}
				continue
			}
			fencedSpec := fencedAbsentSpec(incomingSpec, operationID, revision)
			if exists {
				merged.Forwards[at] = fencedSpec
			} else {
				index[incomingSpec.ForwardID] = len(merged.Forwards)
				merged.Forwards = append(merged.Forwards, fencedSpec)
			}
			continue
		}
		if !exists {
			index[incomingSpec.ForwardID] = len(merged.Forwards)
			merged.Forwards = append(merged.Forwards, incomingSpec)
			continue
		}
		currentSpec := merged.Forwards[at]
		switch {
		case incomingSpec.DesiredRevision > currentSpec.DesiredRevision:
			merged.Forwards[at] = incomingSpec
		case incomingSpec.DesiredRevision < currentSpec.DesiredRevision:
			// A delayed snapshot cannot roll a Forward back.
		case incomingSpec == currentSpec:
			// Idempotent duplicate.
		default:
			return protocol.DesiredState{}, fmt.Errorf("%w: forward %q revision %d", ErrDesiredRevisionConflict, incomingSpec.ForwardID, incomingSpec.DesiredRevision)
		}
	}
	return merged, nil
}

// mergeReceivedDesiredTx applies the per-Forward monotonic merge and stores the
// resulting snapshot. Durable deletion fences are authoritative over revision
// ordering so a retry cannot turn an ABSENT back into PRESENT.
func mergeReceivedDesiredTx(tx *bolt.Tx, incoming protocol.DesiredState) (protocol.DesiredState, error) {
	current, found, err := loadReceivedDesiredTx(tx)
	if err != nil {
		return protocol.DesiredState{}, err
	}
	if !found {
		merged := incoming
		// A fence may predate the received desired row (for example after a
		// crash before transport persistence), so apply the same authority rule
		// against an empty current snapshot.
		return mergeReceivedDesiredWithDeleteFences(tx, protocol.DesiredState{NodeID: incoming.NodeID}, merged)
	}
	return mergeReceivedDesiredWithDeleteFences(tx, current, incoming)
}

// CommitDesired atomically persists a received desired snapshot together with
// the per-Forward decisions: applied records for successes, tombstones plus
// applied-state removal for explicit deletions, and untouched old applied
// records for failures. The whole batch is one transaction: any invalid
// outcome fails the commit closed with no partial writes.
func (s *Store) CommitDesired(d protocol.DesiredState, outcomes []ForwardApply) (ApplyReport, error) {
	if err := d.Validate(); err != nil {
		return ApplyReport{}, fmt.Errorf("localstate: desired: %w", err)
	}
	specs := make(map[string]protocol.ForwardSpec, len(d.Forwards))
	for _, f := range d.Forwards {
		specs[f.ForwardID] = f
	}
	if len(outcomes) != len(d.Forwards) {
		return ApplyReport{}, fmt.Errorf("localstate: commit needs %d outcomes for %d desired Forwards", len(outcomes), len(d.Forwards))
	}
	seen := make(map[string]bool, len(outcomes))
	for _, o := range outcomes {
		spec, ok := specs[o.ForwardID]
		if !ok {
			return ApplyReport{}, fmt.Errorf("localstate: outcome for unknown forward %q", o.ForwardID)
		}
		if seen[o.ForwardID] {
			return ApplyReport{}, fmt.Errorf("localstate: duplicate outcome for forward %q", o.ForwardID)
		}
		seen[o.ForwardID] = true
		switch o.Outcome {
		case ApplyApplied:
			if o.Applied == nil {
				return ApplyReport{}, fmt.Errorf("localstate: forward %q Applied outcome carries no applied state", o.ForwardID)
			}
			if err := o.Applied.Validate(); err != nil {
				return ApplyReport{}, fmt.Errorf("localstate: forward %q: %w", o.ForwardID, err)
			}
			if o.Applied.ForwardID != o.ForwardID {
				return ApplyReport{}, fmt.Errorf("localstate: applied record forward_id %q does not match outcome %q", o.Applied.ForwardID, o.ForwardID)
			}
			if o.Applied.SpecRevision != spec.DesiredRevision || o.Applied.DesiredRevision < o.Applied.SpecRevision {
				return ApplyReport{}, fmt.Errorf("localstate: forward %q applied revision %d does not match desired revision %d", o.ForwardID, o.Applied.SpecRevision, spec.DesiredRevision)
			}
			if spec.Presence != protocol.PresencePresent {
				return ApplyReport{}, fmt.Errorf("localstate: Applied outcome for forward %q whose desired presence is %q", o.ForwardID, spec.Presence)
			}
			if err := validateAppliedRecord(o.ForwardID, *o.Applied, spec, true); err != nil {
				return ApplyReport{}, fmt.Errorf("localstate: forward %q: %w", o.ForwardID, err)
			}
		case ApplyDeleted:
			if spec.Presence != protocol.PresenceAbsent || spec.DeletionOperationID == "" {
				return ApplyReport{}, fmt.Errorf("localstate: Deleted outcome for forward %q requires desired ABSENT with deletion_operation_id", o.ForwardID)
			}
		case ApplyFailed:
			// Old applied state is retained; nothing to validate.
		case ApplySkipped:
			// No write; nothing to validate.
		default:
			return ApplyReport{}, fmt.Errorf("localstate: forward %q has unknown outcome %d", o.ForwardID, o.Outcome)
		}
	}

	var report ApplyReport
	err := s.db.Update(func(tx *bolt.Tx) error {
		desiredBucket := tx.Bucket([]byte(bucketDesired))
		appliedBucket := tx.Bucket([]byte(bucketApplied))
		tombstoneBucket := tx.Bucket([]byte(bucketTombstones))
		if err := validateAppliedBucketTx(appliedBucket); err != nil {
			return err
		}

		mergedDesired, err := mergeReceivedDesiredTx(tx, d)
		if err != nil {
			return err
		}
		raw, err := json.Marshal(mergedDesired)
		if err != nil {
			return err
		}
		if err := desiredBucket.Put([]byte(mergedDesired.NodeID), raw); err != nil {
			return err
		}

		mergedSpecs := make(map[string]protocol.ForwardSpec, len(mergedDesired.Forwards))
		for _, mergedSpec := range mergedDesired.Forwards {
			mergedSpecs[mergedSpec.ForwardID] = mergedSpec
		}

		for _, o := range outcomes {
			spec := specs[o.ForwardID]
			key := []byte(o.ForwardID)
			// Deletion facts are authoritative even when a retry carries a
			// higher-revision PRESENT. Check them before the received-desired
			// merge's stale-outcome guard so callers receive the no-resurrection
			// error rather than an incidental revision error.
			if o.Outcome == ApplyApplied {
				if _, pending, _, tombstoned, err := loadForwardDeleteFenceTx(tx, o.ForwardID); err != nil {
					return err
				} else if pending || tombstoned {
					return fmt.Errorf("%w: forward %q", ErrTombstonedForward, o.ForwardID)
				}
			}
			mergedSpec, stillCurrent := mergedSpecs[o.ForwardID]
			if !stillCurrent || mergedSpec != spec {
				// A delayed outcome belongs to an older per-Forward desired
				// revision. A skip is already a no-op; any side-effect-bearing
				// outcome must fail closed so the caller rolls back live state
				// instead of acknowledging a result it did not durably apply.
				if o.Outcome == ApplySkipped {
					continue
				}
				return fmt.Errorf("%w: outcome for forward %q is stale", ErrDesiredRevisionConflict, o.ForwardID)
			}
			switch o.Outcome {
			case ApplyApplied:
				// A durable deletion tombstone is authoritative: an old snapshot
				// or Controller rollback must never resurrect this Forward.
				if tx.Bucket([]byte(bucketTombstones)).Get(key) != nil {
					return fmt.Errorf("%w: forward %q", ErrTombstonedForward, o.ForwardID)
				}
				candidate := *o.Applied
				existing, exists, err := loadAppliedRecordTx(appliedBucket, o.ForwardID)
				if err != nil {
					return err
				}
				if exists {
					switch {
					case candidate.SpecRevision < existing.State.SpecRevision:
						return fmt.Errorf("%w: forward %q candidate revision %d is older than durable revision %d", ErrAppliedRevisionConflict, o.ForwardID, candidate.SpecRevision, existing.State.SpecRevision)
					case candidate.SpecRevision == existing.State.SpecRevision:
						if !existing.HasServingSpec || !equivalentAppliedState(candidate, existing.State) || existing.ServingSpec != spec {
							return fmt.Errorf("%w: forward %q has conflicting equal revision %d", ErrAppliedRevisionConflict, o.ForwardID, candidate.SpecRevision)
						}
					}
				}
				raw, err := encodeAppliedRecord(candidate, spec)
				if err != nil {
					return err
				}
				if err := appliedBucket.Put(key, raw); err != nil {
					return err
				}
				report.AppliedCount++
			case ApplyDeleted:
				if existing, found, err := loadForwardDeleteIntentTx(tx.Bucket([]byte(bucketForwardDeleteIntents)), o.ForwardID); err != nil {
					return err
				} else if found && (existing.DeletionOperationID != spec.DeletionOperationID || existing.DesiredRevision != spec.DesiredRevision) {
					return fmt.Errorf("%w: forward %q", ErrForwardDeleteConflict, o.ForwardID)
				}
				tombstone := ForwardTombstone{
					ForwardID:           o.ForwardID,
					DeletionOperationID: spec.DeletionOperationID,
					DesiredRevision:     spec.DesiredRevision,
					CreatedAtUnix:       nowUnix(),
				}
				raw, err := json.Marshal(tombstone)
				if err != nil {
					return err
				}
				// Tombstone and applied-state removal are the same bbolt
				// transaction (state-model §4): a crash cannot leave the
				// Forward applied but un-tombstoned, or tombstoned but still
				// applied.
				if err := tombstoneBucket.Put(key, raw); err != nil {
					return err
				}
				if err := appliedBucket.Delete(key); err != nil {
					return err
				}
				// Activation mirrors are derived from applied state. Remove the
				// mirror in the same transaction so a crash or reconnect cannot
				// replay a deleted Forward's status.
				if err := tx.Bucket([]byte(bucketActivation)).Delete(key); err != nil {
					return err
				}
				report.DeletedCount++
			case ApplyFailed:
				if o.Err != nil {
					report.FailedForwards = append(report.FailedForwards, o.ForwardID)
				}
				report.FailedCount++
			case ApplySkipped:
				// No write; the decision lives in the caller's report.
			}
		}
		return nil
	})
	if err != nil {
		return ApplyReport{}, err
	}
	switch {
	case report.FailedCount == 0:
		report.Status = ApplyStatusFull
	case report.AppliedCount+report.DeletedCount > 0:
		report.Status = ApplyStatusPartial
	default:
		report.Status = ApplyStatusFailed
	}
	return report, nil
}

// SaveReceivedDesired persists a received desired snapshot without applying
// it. The transport layer stores the message here; the reconcile loop applies
// it later.
func (s *Store) SaveReceivedDesired(d protocol.DesiredState) error {
	if err := d.Validate(); err != nil {
		return fmt.Errorf("localstate: desired: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		merged, err := mergeReceivedDesiredTx(tx, d)
		if err != nil {
			return err
		}
		raw, err := json.Marshal(merged)
		if err != nil {
			return err
		}
		return tx.Bucket([]byte(bucketDesired)).Put([]byte(merged.NodeID), raw)
	})
}

// LoadReceivedDesired returns the last received desired snapshot for the
// node, if any.
func (s *Store) LoadReceivedDesired() (protocol.DesiredState, bool, error) {
	var d protocol.DesiredState
	var found bool
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketDesired)).ForEach(func(k, raw []byte) error {
			if found {
				return errors.New("localstate: multiple received desired snapshots in one Agent store")
			}
			if err := json.Unmarshal(raw, &d); err != nil {
				return fmt.Errorf("localstate: decode received desired: %w", err)
			}
			if err := d.Validate(); err != nil {
				return fmt.Errorf("localstate: stored desired: %w", err)
			}
			if string(k) != d.NodeID {
				return fmt.Errorf("localstate: desired node_id %q does not match storage key %q", d.NodeID, string(k))
			}
			found = true
			return nil
		})
	})
	return d, found, err
}

// GetAppliedRecord returns the durable applied record and its complete serving
// target. Legacy rows are returned with HasServingSpec=false and are valid for
// status/probe inspection but cannot safely drive restart recovery.
func (s *Store) GetAppliedRecord(forwardID string) (AppliedStateRecord, bool, error) {
	if forwardID == "" {
		return AppliedStateRecord{}, false, fmt.Errorf("localstate: applied forward id is required")
	}
	var record AppliedStateRecord
	var found bool
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		record, found, err = loadAppliedRecordTx(tx.Bucket([]byte(bucketApplied)), forwardID)
		return err
	})
	return record, found, err
}

// GetAppliedState returns the validated durable applied state for one Forward.
func (s *Store) GetAppliedState(forwardID string) (protocol.AppliedForwardState, bool, error) {
	record, found, err := s.GetAppliedRecord(forwardID)
	return record.State, found, err
}

// ListAppliedRecords returns every validated durable applied record.
func (s *Store) ListAppliedRecords() ([]AppliedStateRecord, error) {
	var records []AppliedStateRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketApplied)).ForEach(func(key, raw []byte) error {
			state, spec, hasSpec, err := decodeAppliedRecord(raw)
			if err != nil {
				return fmt.Errorf("localstate: decode applied state for %q: %w", string(key), err)
			}
			if err := validateAppliedRecord(string(key), state, spec, hasSpec); err != nil {
				return fmt.Errorf("localstate: applied state for %q: %w", string(key), err)
			}
			records = append(records, AppliedStateRecord{State: state, ServingSpec: spec, HasServingSpec: hasSpec})
			return nil
		})
	})
	return records, err
}

// ListAppliedStates returns every validated durable applied Forward record.
func (s *Store) ListAppliedStates() ([]protocol.AppliedForwardState, error) {
	records, err := s.ListAppliedRecords()
	if err != nil {
		return nil, err
	}
	states := make([]protocol.AppliedForwardState, 0, len(records))
	for _, record := range records {
		states = append(states, record.State)
	}
	return states, nil
}
