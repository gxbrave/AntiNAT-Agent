// P14 story-1 journal evacuation primitives (transfer-declared P07 localstate
// lifecycle ownership): transactional adjacency between the mapping journal
// bucket and the applied/tombstone rows so an evacuation never leaves a
// half-consistent boundary, plus the same-revision applied-record
// MappingJournalRef refresh that restart recovery needs.
package localstate

import (
	"errors"
	"fmt"

	bolt "go.etcd.io/bbolt"
)

// EvacuateJournalRecords removes the named mapping journal records in one
// bbolt transaction. Applied/tombstone rows live in the same store and are
// read/written transactionally adjacent to this bucket, which is what lets
// P14 decide an orphan boundary and delete it without a crash exposing a
// reappearing mapping ref.
func (s *Store) EvacuateJournalRecords(ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketMapping))
		for _, id := range ids {
			if id == "" {
				continue
			}
			if err := bucket.Delete([]byte(id)); err != nil {
				return fmt.Errorf("localstate: evacuate journal record %q: %w", id, err)
			}
		}
		return nil
	})
}

// RefreshAppliedJournalRef updates ONLY the MappingJournalRef field of a
// durable applied record at the SAME SpecRevision (same-revision LKG refresh,
// P12W-deferred P14 evacuation ownership). It refuses to change any other
// identity/version field: commit-desired remains the only writer of
// SpecRevision/DesiredRevision/strategy. Reporting updated=false means the
// record already carries the ref (or the row is legacy with no serving spec
// and is left alone).
func (s *Store) RefreshAppliedJournalRef(forwardID, journalRef string) (bool, error) {
	if forwardID == "" {
		return false, errors.New("localstate: applied forward id is required for journal ref refresh")
	}
	updated := false
	err := s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketApplied))
		raw := bucket.Get([]byte(forwardID))
		if raw == nil {
			return nil
		}
		state, spec, hasSpec, err := decodeAppliedRecord(raw)
		if err != nil {
			return fmt.Errorf("localstate: decode applied %q for journal ref refresh: %w", forwardID, err)
		}
		if state.ForwardID == "" || !hasSpec {
			// Legacy row (no serving spec): nothing to refresh without a target.
			return nil
		}
		if state.MappingJournalRef == journalRef {
			return nil
		}
		state.MappingJournalRef = journalRef
		encoded, err := encodeAppliedRecord(state, spec)
		if err != nil {
			return err
		}
		if err := bucket.Put([]byte(forwardID), encoded); err != nil {
			return err
		}
		updated = true
		return nil
	})
	return updated, err
}

// evictAppliedStatesTx removes the applied + activation mirrors for the given
// forwards in the caller's transaction (decommission cleanup share).
func evictAppliedStatesTx(tx *bolt.Tx, forwardIDs []string) error {
	applied := tx.Bucket([]byte(bucketApplied))
	activation := tx.Bucket([]byte(bucketActivation))
	for _, id := range forwardIDs {
		if err := applied.Delete([]byte(id)); err != nil {
			return fmt.Errorf("localstate: clear applied %q: %w", id, err)
		}
		if err := activation.Delete([]byte(id)); err != nil {
			return fmt.Errorf("localstate: clear activation mirror %q: %w", id, err)
		}
	}
	return nil
}
