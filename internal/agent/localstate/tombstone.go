// Forward delete tombstones (docs/state-model.md §4).
//
// Deletion is always an explicit ABSENT plus a deletion_operation_id; a full
// snapshot that merely omits a Forward never implies deletion. The tombstone
// is written in the same bbolt transaction as the applied-state removal
// (applied.go CommitDesired), before any stop side effect, and is GC'd only
// after the Controller's durable receipt for the deletion operation exists.
package localstate

import (
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// ForwardTombstone durably records a Forward deletion intent.
type ForwardTombstone struct {
	ForwardID           string `json:"forward_id"`
	DeletionOperationID string `json:"deletion_operation_id"`
	DesiredRevision     uint64 `json:"desired_revision,omitempty"`
	CreatedAtUnix       int64  `json:"created_at_unix"`
}

// ErrTombstoneNotGCReady reports a tombstone whose deletion operation has not
// yet reached a durable Controller receipt; GC is refused.
var ErrTombstoneNotGCReady = fmt.Errorf("localstate: forward tombstone cannot be GC'd before the deletion operation is durably receipted")

// ErrTombstonedForward reports an attempt to apply a Forward that carries a
// durable deletion tombstone. Deletion intent followed by crash, an old
// snapshot, or a Controller rollback must never resurrect the Forward.
var ErrTombstonedForward = fmt.Errorf("localstate: forward has a durable deletion tombstone and cannot be resurrected")

func nowUnix() int64 { return time.Now().Unix() }

// TombstoneExists reports whether a durable tombstone exists for forwardID.
func loadForwardTombstoneTx(bucket *bolt.Bucket, forwardID string) (ForwardTombstone, bool, error) {
	raw := bucket.Get([]byte(forwardID))
	if raw == nil {
		return ForwardTombstone{}, false, nil
	}
	var tombstone ForwardTombstone
	if err := json.Unmarshal(raw, &tombstone); err != nil {
		return ForwardTombstone{}, false, fmt.Errorf("localstate: decode tombstone %q: %w", forwardID, err)
	}
	if tombstone.ForwardID != forwardID || tombstone.DeletionOperationID == "" {
		return ForwardTombstone{}, false, fmt.Errorf("localstate: invalid tombstone %q", forwardID)
	}
	return tombstone, true, nil
}

// TombstoneExists reports whether a durable final tombstone exists for forwardID.
func (s *Store) TombstoneExists(forwardID string) (bool, error) {
	_, found, err := s.GetForwardTombstone(forwardID)
	return found, err
}

// GetForwardTombstone loads one durable final tombstone.
func (s *Store) GetForwardTombstone(forwardID string) (ForwardTombstone, bool, error) {
	if forwardID == "" {
		return ForwardTombstone{}, false, fmt.Errorf("localstate: tombstone forward id is required")
	}
	var tombstone ForwardTombstone
	var found bool
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		tombstone, found, err = loadForwardTombstoneTx(tx.Bucket([]byte(bucketTombstones)), forwardID)
		return err
	})
	return tombstone, found, err
}

// ListTombstones returns every durable forward tombstone.
func (s *Store) ListTombstones() ([]ForwardTombstone, error) {
	var tombstones []ForwardTombstone
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketTombstones)).ForEach(func(key, raw []byte) error {
			ts, found, err := loadForwardTombstoneTx(tx.Bucket([]byte(bucketTombstones)), string(key))
			if err != nil {
				return err
			}
			if found {
				tombstones = append(tombstones, ts)
			}
			return nil
		})
	})
	return tombstones, err
}

// GCForwardTombstone removes a tombstone only after the Controller's durable
// receipt for its deletion operation exists (state-model §4: tombstone GC
// waits for the durable receipt / sufficient high-water). Otherwise the GC is
// refused so a replay of an old snapshot can never resurrect the Forward.
func (s *Store) GCForwardTombstone(forwardID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketTombstones))
		ts, found, err := loadForwardTombstoneTx(bucket, forwardID)
		if err != nil {
			return err
		}
		if !found {
			return nil // already GC'd
		}
		if _, pending, err := loadForwardDeleteIntentTx(tx.Bucket([]byte(bucketForwardDeleteIntents)), forwardID); err != nil {
			return err
		} else if pending {
			return fmt.Errorf("%w: forward %q still has pending cleanup", ErrTombstoneNotGCReady, forwardID)
		}
		ops := tx.Bucket([]byte(bucketOperations))
		if ops.Get(receiptKey(ts.DeletionOperationID)) == nil {
			return fmt.Errorf("%w: forward %q deletion operation %q", ErrTombstoneNotGCReady, forwardID, ts.DeletionOperationID)
		}
		return bucket.Delete([]byte(forwardID))
	})
}
