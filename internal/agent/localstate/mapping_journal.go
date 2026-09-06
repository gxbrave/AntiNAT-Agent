// Durable mapping journal adapter (P12W Story 1): the Agent exposes the
// existing `mapping_journal` bucket (created since schema v1) through the
// traversal.JournalStore contract the Manager and Detector consume. No schema
// migration is needed; the bucket predates this adapter. The adapter shares
// the single bbolt lock with applied/tombstone rows so journal lifecycle rows
// stay transactionally adjacent to the Forward records P14 evacuates.
//
// The Manager invokes Get/Put/Delete while holding the acquisition's renewal
// lock, so every operation is a single bucket read/write transaction with no
// index maintenance: List and ListByForward are full-scan ForEach filters
// matching the MemoryJournal semantics.
package localstate

import (
	"fmt"

	bolt "go.etcd.io/bbolt"

	"github.com/gxbrave/AntiNAT-Agent/internal/traversal"
)

// mappingJournal is the bbolt traversal.JournalStore backing one Store.
type mappingJournal struct {
	store *Store
}

// MappingJournal returns the durable traversal.JournalStore view of the
// Agent's mapping_journal bucket.
func (s *Store) MappingJournal() traversal.JournalStore {
	return &mappingJournal{store: s}
}

// Put persists one record in a single bbolt write transaction.
func (j *mappingJournal) Put(record traversal.JournalRecord) error {
	raw, err := traversal.EncodeJournalRecord(record)
	if err != nil {
		return err
	}
	return j.store.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketMapping)).Put([]byte(record.ID), raw)
	})
}

// Get reads one record in a single bbolt read transaction.
func (j *mappingJournal) Get(id string) (traversal.JournalRecord, bool, error) {
	if id == "" {
		return traversal.JournalRecord{}, false, fmt.Errorf("localstate: mapping journal id is required")
	}
	var record traversal.JournalRecord
	var ok bool
	err := j.store.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket([]byte(bucketMapping)).Get([]byte(id))
		if raw == nil {
			return nil
		}
		decoded, err := traversal.DecodeJournalRecord(raw)
		if err != nil {
			return fmt.Errorf("localstate: mapping journal record %q: %w", id, err)
		}
		record = decoded
		ok = true
		return nil
	})
	return record, ok, err
}

// Delete removes one record in a single bbolt write transaction.
func (j *mappingJournal) Delete(id string) error {
	if id == "" {
		return fmt.Errorf("localstate: mapping journal id is required")
	}
	return j.store.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketMapping)).Delete([]byte(id))
	})
}

// List returns every record (full-scan, no index).
func (j *mappingJournal) List() ([]traversal.JournalRecord, error) {
	return j.list(func(traversal.JournalRecord) bool { return true })
}

// ListByForward returns the records owned by one forward.
func (j *mappingJournal) ListByForward(forwardID string) ([]traversal.JournalRecord, error) {
	return j.list(func(record traversal.JournalRecord) bool {
		return record.ForwardID == forwardID
	})
}

func (j *mappingJournal) list(filter func(traversal.JournalRecord) bool) ([]traversal.JournalRecord, error) {
	var records []traversal.JournalRecord
	err := j.store.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketMapping)).ForEach(func(key, raw []byte) error {
			record, err := traversal.DecodeJournalRecord(raw)
			if err != nil {
				return fmt.Errorf("localstate: mapping journal record %q: %w", string(key), err)
			}
			if filter(record) {
				records = append(records, record)
			}
			return nil
		})
	})
	return records, err
}
