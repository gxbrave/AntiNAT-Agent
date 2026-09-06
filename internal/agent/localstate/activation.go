package localstate

import (
	"encoding/json"
	"fmt"

	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
	bolt "go.etcd.io/bbolt"
)

type ActivationSnapshot struct {
	ForwardID  string                    `json:"forward_id"`
	Activation string                    `json:"activation"`
	Generation uint64                    `json:"generation"`
	States     protocol.ActivationStates `json:"states"`
}

func validateActivationSnapshot(key string, snapshot ActivationSnapshot) error {
	if snapshot.ForwardID == "" || snapshot.Activation == "" {
		return fmt.Errorf("localstate: activation snapshot identity is required")
	}
	if key != "" && snapshot.ForwardID != key {
		return fmt.Errorf("localstate: activation forward_id %q does not match storage key %q", snapshot.ForwardID, key)
	}
	if snapshot.Generation == 0 {
		return fmt.Errorf("localstate: activation snapshot generation must be non-zero")
	}
	want := protocol.ActivationID(snapshot.ForwardID, snapshot.Generation)
	if snapshot.Activation != fmt.Sprintf("%x", want[:]) {
		return fmt.Errorf("localstate: activation snapshot identity does not match forward %q generation %d", snapshot.ForwardID, snapshot.Generation)
	}
	if err := snapshot.States.Validate(); err != nil {
		return fmt.Errorf("localstate: activation snapshot for %q: %w", snapshot.ForwardID, err)
	}
	return nil
}

// SaveActivationSnapshot durably records the local activation mirror before a
// reconnect/restart can reopen a listener. The key is the forward identity so
// stale events cannot overwrite another forward's evidence.
func (s *Store) SaveActivationSnapshot(snapshot ActivationSnapshot) error {
	if err := validateActivationSnapshot(snapshot.ForwardID, snapshot); err != nil {
		return err
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketActivation)).Put([]byte(snapshot.ForwardID), raw)
	})
}

func (s *Store) LoadActivationSnapshot(forwardID string) (ActivationSnapshot, bool, error) {
	if forwardID == "" {
		return ActivationSnapshot{}, false, fmt.Errorf("localstate: activation snapshot forward id is required")
	}
	var snapshot ActivationSnapshot
	var present bool
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket([]byte(bucketActivation)).Get([]byte(forwardID))
		if raw == nil {
			return nil
		}
		present = true
		if err := json.Unmarshal(append([]byte(nil), raw...), &snapshot); err != nil {
			return fmt.Errorf("localstate: decode activation snapshot for %q: %w", forwardID, err)
		}
		return validateActivationSnapshot(forwardID, snapshot)
	})
	return snapshot, present, err
}

// DeleteActivationSnapshot removes a local activation mirror when a probe
// admission transaction is compensated before its first snapshot was written.
func (s *Store) DeleteActivationSnapshot(forwardID string) error {
	if forwardID == "" {
		return fmt.Errorf("localstate: activation snapshot forward id is required")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketActivation)).Delete([]byte(forwardID))
	})
}

func (s *Store) ListActivationSnapshots(limit int) ([]ActivationSnapshot, error) {
	out, _, err := s.ListActivationSnapshotsPage(limit, "")
	return out, err
}

// ListActivationSnapshotsPage reads one keyset-paginated page. The cursor is
// the last forward-id returned by the previous page; an empty cursor starts at
// the first bucket key. nextCursor is empty when the page reached the end.
func (s *Store) ListActivationSnapshotsPage(limit int, after string) ([]ActivationSnapshot, string, error) {
	if limit <= 0 {
		limit = 256
	}
	out := make([]ActivationSnapshot, 0, limit)
	var nextCursor string
	err := s.db.View(func(tx *bolt.Tx) error {
		cursor := tx.Bucket([]byte(bucketActivation)).Cursor()
		var key, raw []byte
		if after == "" {
			key, raw = cursor.First()
		} else {
			key, raw = cursor.Seek([]byte(after))
			if key != nil && string(key) == after {
				key, raw = cursor.Next()
			}
		}
		for key != nil && len(out) < limit {
			if raw != nil {
				var snapshot ActivationSnapshot
				if err := json.Unmarshal(raw, &snapshot); err != nil {
					return fmt.Errorf("localstate: decode activation snapshot for %q: %w", string(key), err)
				}
				if err := validateActivationSnapshot(string(key), snapshot); err != nil {
					return err
				}
				out = append(out, snapshot)
			}
			key, raw = cursor.Next()
		}
		if len(out) == limit && key != nil {
			nextCursor = string(out[len(out)-1].ForwardID)
		}
		return nil
	})
	return out, nextCursor, err
}
