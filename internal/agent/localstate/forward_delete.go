package localstate

import (
	"encoding/json"
	"errors"
	"fmt"

	bolt "go.etcd.io/bbolt"
)

// ForwardDeleteIntent is the durable, reversible fence for a Forward delete.
// It is written before a delete can perform cleanup and remains until cleanup
// succeeds. A final ForwardTombstone is the permanent no-resurrection fact;
// this row covers the crash window before and during cleanup.
type ForwardDeleteIntent struct {
	ForwardID           string `json:"forward_id"`
	DeletionOperationID string `json:"deletion_operation_id"`
	DesiredRevision     uint64 `json:"desired_revision"`
	CreatedAtUnix       int64  `json:"created_at_unix"`
}

var (
	// ErrForwardDeleteConflict reports a delete whose semantic identity differs
	// from the durable intent already fencing the Forward.
	ErrForwardDeleteConflict = errors.New("localstate: forward delete intent conflicts with persisted intent")
	// ErrForwardDeleteNotFound reports an operation-specific completion request
	// for a Forward without the requested durable pending intent.
	ErrForwardDeleteNotFound = errors.New("localstate: forward delete intent not found")
	// ErrForwardDeleteNotCommitted reports an attempt to clear a pending intent
	// before the final tombstone has been durably committed.
	ErrForwardDeleteNotCommitted = errors.New("localstate: forward delete intent has no committed tombstone")
	// ErrForwardDeletePending reports an apply attempt fenced by a pending
	// deletion. It is wrapped with ErrTombstonedForward by CommitDesired so
	// callers that only understand the original tombstone sentinel still fail
	// closed.
	ErrForwardDeletePending = errors.New("localstate: forward delete remains pending cleanup")
)

func validateForwardDeleteIntent(intent ForwardDeleteIntent) error {
	if intent.ForwardID == "" {
		return errors.New("localstate: forward delete intent requires a forward id")
	}
	if intent.DeletionOperationID == "" {
		return errors.New("localstate: forward delete intent requires a deletion operation id")
	}
	if intent.DesiredRevision == 0 {
		return errors.New("localstate: forward delete intent requires a non-zero desired revision")
	}
	if intent.CreatedAtUnix == 0 {
		return errors.New("localstate: forward delete intent requires a creation time")
	}
	return nil
}

func loadForwardDeleteFenceTx(tx *bolt.Tx, forwardID string) (ForwardDeleteIntent, bool, ForwardTombstone, bool, error) {
	intent, pending, err := loadForwardDeleteIntentTx(tx.Bucket([]byte(bucketForwardDeleteIntents)), forwardID)
	if err != nil {
		return ForwardDeleteIntent{}, false, ForwardTombstone{}, false, err
	}
	tombstone, tombstoned, err := loadForwardTombstoneTx(tx.Bucket([]byte(bucketTombstones)), forwardID)
	if err != nil {
		return ForwardDeleteIntent{}, false, ForwardTombstone{}, false, err
	}
	return intent, pending, tombstone, tombstoned, nil
}

func loadForwardDeleteIntentTx(bucket *bolt.Bucket, forwardID string) (ForwardDeleteIntent, bool, error) {
	raw := bucket.Get([]byte(forwardID))
	if raw == nil {
		return ForwardDeleteIntent{}, false, nil
	}
	var intent ForwardDeleteIntent
	if err := json.Unmarshal(raw, &intent); err != nil {
		return ForwardDeleteIntent{}, false, fmt.Errorf("localstate: decode forward delete intent %q: %w", forwardID, err)
	}
	if err := validateForwardDeleteIntent(intent); err != nil {
		return ForwardDeleteIntent{}, false, fmt.Errorf("localstate: forward delete intent %q: %w", forwardID, err)
	}
	if intent.ForwardID != forwardID {
		return ForwardDeleteIntent{}, false, fmt.Errorf("localstate: forward delete intent forward_id %q does not match key %q", intent.ForwardID, forwardID)
	}
	return intent, true, nil
}

// putForwardDeleteIntentTx idempotently persists one delete fence. A completed
// tombstone makes a same-identity insertion a no-op; a different identity is
// rejected rather than reopening a completed deletion lifecycle.
func putForwardDeleteIntentTx(tx *bolt.Tx, intent ForwardDeleteIntent) (bool, error) {
	if err := validateForwardDeleteIntent(intent); err != nil {
		return false, err
	}
	bucket := tx.Bucket([]byte(bucketForwardDeleteIntents))
	if existing, found, err := loadForwardDeleteIntentTx(bucket, intent.ForwardID); err != nil {
		return false, err
	} else if found {
		if existing.DeletionOperationID != intent.DeletionOperationID || existing.DesiredRevision != intent.DesiredRevision {
			return false, fmt.Errorf("%w: forward %q", ErrForwardDeleteConflict, intent.ForwardID)
		}
		return false, nil
	}

	// A final tombstone is authoritative even if the pending row was already
	// completed. Treat the exact semantic deletion as idempotent, but never
	// recreate a pending row after cleanup has finished.
	if raw := tx.Bucket([]byte(bucketTombstones)).Get([]byte(intent.ForwardID)); raw != nil {
		var tombstone ForwardTombstone
		if err := json.Unmarshal(raw, &tombstone); err != nil {
			return false, fmt.Errorf("localstate: decode tombstone %q: %w", intent.ForwardID, err)
		}
		if tombstone.DeletionOperationID != intent.DeletionOperationID ||
			(tombstone.DesiredRevision != 0 && tombstone.DesiredRevision != intent.DesiredRevision) {
			return false, fmt.Errorf("%w: forward %q", ErrForwardDeleteConflict, intent.ForwardID)
		}
		return false, nil
	}

	raw, err := json.Marshal(intent)
	if err != nil {
		return false, err
	}
	if err := bucket.Put([]byte(intent.ForwardID), raw); err != nil {
		return false, err
	}
	return true, nil
}

// PutForwardDeleteIntent durably installs one idempotent Forward delete fence.
func (s *Store) PutForwardDeleteIntent(intent ForwardDeleteIntent) (bool, error) {
	if intent.CreatedAtUnix == 0 {
		intent.CreatedAtUnix = nowUnix()
	}
	returnValue := false
	err := s.db.Update(func(tx *bolt.Tx) error {
		var err error
		returnValue, err = putForwardDeleteIntentTx(tx, intent)
		return err
	})
	return returnValue, err
}

// PutForwardDeleteIntents installs all delete fences in one transaction. It is
// used for a full desired snapshot so every ABSENT intent is durable before a
// sibling PRESENT apply hook can run.
func (s *Store) PutForwardDeleteIntents(intents []ForwardDeleteIntent) error {
	prepared := make([]ForwardDeleteIntent, len(intents))
	seen := make(map[string]struct{}, len(intents))
	for i, intent := range intents {
		if intent.CreatedAtUnix == 0 {
			intent.CreatedAtUnix = nowUnix()
		}
		if err := validateForwardDeleteIntent(intent); err != nil {
			return err
		}
		if _, ok := seen[intent.ForwardID]; ok {
			return fmt.Errorf("%w: duplicate forward %q in batch", ErrForwardDeleteConflict, intent.ForwardID)
		}
		seen[intent.ForwardID] = struct{}{}
		prepared[i] = intent
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		for _, intent := range prepared {
			if _, err := putForwardDeleteIntentTx(tx, intent); err != nil {
				return err
			}
		}
		return nil
	})
}

// GetForwardDeleteIntent returns one pending delete fence.
func (s *Store) GetForwardDeleteIntent(forwardID string) (ForwardDeleteIntent, bool, error) {
	if forwardID == "" {
		return ForwardDeleteIntent{}, false, errors.New("localstate: forward delete intent forward id is required")
	}
	var intent ForwardDeleteIntent
	var found bool
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		intent, found, err = loadForwardDeleteIntentTx(tx.Bucket([]byte(bucketForwardDeleteIntents)), forwardID)
		return err
	})
	return intent, found, err
}

// ListForwardDeleteIntents returns every pending delete fence.
func (s *Store) ListForwardDeleteIntents() ([]ForwardDeleteIntent, error) {
	intents := make([]ForwardDeleteIntent, 0)
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketForwardDeleteIntents)).ForEach(func(key, raw []byte) error {
			var intent ForwardDeleteIntent
			if err := json.Unmarshal(raw, &intent); err != nil {
				return fmt.Errorf("localstate: decode forward delete intent %q: %w", string(key), err)
			}
			if err := validateForwardDeleteIntent(intent); err != nil {
				return fmt.Errorf("localstate: forward delete intent %q: %w", string(key), err)
			}
			if intent.ForwardID != string(key) {
				return fmt.Errorf("localstate: forward delete intent forward_id %q does not match key %q", intent.ForwardID, string(key))
			}
			intents = append(intents, intent)
			return nil
		})
	})
	return intents, err
}

// CompleteForwardDeleteIntent clears a pending fence only after the matching
// final tombstone exists. Completion is idempotent once the row is gone.
func (s *Store) CompleteForwardDeleteIntent(forwardID, deletionOperationID string) error {
	if forwardID == "" || deletionOperationID == "" {
		return errors.New("localstate: forward delete completion identity is required")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketForwardDeleteIntents))
		intent, found, err := loadForwardDeleteIntentTx(bucket, forwardID)
		if err != nil {
			return err
		}
		if !found {
			return nil
		}
		if intent.DeletionOperationID != deletionOperationID {
			return fmt.Errorf("%w: forward %q", ErrForwardDeleteConflict, forwardID)
		}
		tombstone, found, err := loadForwardTombstoneTx(tx.Bucket([]byte(bucketTombstones)), forwardID)
		if err != nil {
			return err
		}
		if !found || tombstone.DeletionOperationID != deletionOperationID {
			return fmt.Errorf("%w: forward %q", ErrForwardDeleteNotCommitted, forwardID)
		}
		return bucket.Delete([]byte(forwardID))
	})
}

// ForwardDeleteFence returns both deletion facts in one consistent read. Either
// fact is sufficient to fence a PRESENT apply; pending distinguishes cleanup
// that still needs a stop retry from a completed deletion.
func (s *Store) ForwardDeleteFence(forwardID string) (ForwardDeleteIntent, bool, ForwardTombstone, bool, error) {
	if forwardID == "" {
		return ForwardDeleteIntent{}, false, ForwardTombstone{}, false, errors.New("localstate: forward delete fence forward id is required")
	}
	var intent ForwardDeleteIntent
	var pending bool
	var tombstone ForwardTombstone
	var tombstoned bool
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		intent, pending, err = loadForwardDeleteIntentTx(tx.Bucket([]byte(bucketForwardDeleteIntents)), forwardID)
		if err != nil {
			return err
		}
		tombstone, tombstoned, err = loadForwardTombstoneTx(tx.Bucket([]byte(bucketTombstones)), forwardID)
		return err
	})
	return intent, pending, tombstone, tombstoned, err
}
