// P14 Story 2: durable node-decommission rows (transfer-declared P07 localstate
// lifecycle ownership).
//
// The DECOMMISSIONING/DECOMMISSIONED terminal markers live in the marker file
// (marker.go) and are the durability authority; the rows here are the
// phase-journal companions the deep spec §6-part requires: the decommission
// intent is persisted BEFORE any external side effect and the cleanup tombstone
// carries every allowed Agent key hash / credential version across a rotation
// overlap so no secret survives decommission and none is ever re-admitted.
//
// Both rows use reserved prefixes under the existing operation_results bucket
// (same pattern as op:/receipt:), so no Agent bbolt schema migration is needed.
package localstate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	bolt "go.etcd.io/bbolt"
)

var (
	keyDecommissionIntent          = []byte("decommission-intent:")
	keyCleanupTombstone            = []byte("cleanup-tombstone:")
	keyDecommissionIntentCanonical = []byte("decommission-intent:current")
	keyCleanupTombstoneCanonical   = []byte("cleanup-tombstone:current")
	// ErrDecommissionConflict rejects a second decommission intent whose
	// operation identity differs from the durable one.
	ErrDecommissionConflict = errors.New("localstate: decommission intent conflicts with persisted intent")
)

// DecommissionIntent is the durable intent recorded before any Forward stop.
type DecommissionIntent struct {
	OperationID        string   `json:"operation_id"`
	NodeID             string   `json:"node_id"`
	Force              bool     `json:"force,omitempty"`
	DeadlineUnix       int64    `json:"deadline_unix,omitempty"`
	AllowedKeyHashes   []string `json:"allowed_key_hashes,omitempty"`
	CredentialVersions []uint32 `json:"credential_versions,omitempty"`
	CreatedAtUnix      int64    `json:"created_at_unix"`
}

// AgentCleanupTombstone is the terminal cleanup fact for this node. It holds
// every allowed Agent key hash / credential version across the rotation overlap
// so a later enrollment/rotation can never re-admit a secret the decommission
// cleared.
type AgentCleanupTombstone struct {
	OperationID        string   `json:"operation_id"`
	NodeID             string   `json:"node_id"`
	Force              bool     `json:"force,omitempty"`
	AllowedKeyHashes   []string `json:"allowed_key_hashes,omitempty"`
	CredentialVersions []uint32 `json:"credential_versions,omitempty"`
	CreatedAtUnix      int64    `json:"created_at_unix"`
}

// PutDecommissionIntent persists the durable intent, refusing a different
// operation identity once one exists.
func (s *Store) PutDecommissionIntent(intent DecommissionIntent) (bool, error) {
	if intent.OperationID == "" || intent.NodeID == "" {
		return false, errors.New("localstate: decommission intent requires operation and node id")
	}
	raw, err := json.Marshal(intent)
	if err != nil {
		return false, err
	}
	created := false
	err = s.db.Update(func(tx *bolt.Tx) error {
		ops := tx.Bucket([]byte(bucketOperations))
		if existing := ops.Get(keyDecommissionIntentCanonical); existing != nil {
			var old DecommissionIntent
			if err := json.Unmarshal(existing, &old); err != nil {
				return fmt.Errorf("localstate: decode decommission intent: %w", err)
			}
			if old.OperationID != intent.OperationID || old.NodeID != intent.NodeID {
				return fmt.Errorf("%w: existing %s/%s vs new %s/%s", ErrDecommissionConflict, old.OperationID, old.NodeID, intent.OperationID, intent.NodeID)
			}
			return nil
		}
		// Migrate a legacy operation-keyed singleton if present, but reject when
		// the first durable fact belongs to another node/operation.
		var legacy *DecommissionIntent
		if err := ops.ForEach(func(k, value []byte) error {
			if !bytes.HasPrefix(k, keyDecommissionIntent) || bytes.Equal(k, keyDecommissionIntentCanonical) {
				return nil
			}
			var old DecommissionIntent
			if err := json.Unmarshal(value, &old); err != nil {
				return err
			}
			legacy = &old
			return nil
		}); err != nil {
			return err
		}
		if legacy != nil && (legacy.OperationID != intent.OperationID || legacy.NodeID != intent.NodeID) {
			return fmt.Errorf("%w: existing %s/%s vs new %s/%s", ErrDecommissionConflict, legacy.OperationID, legacy.NodeID, intent.OperationID, intent.NodeID)
		}
		if err := ops.Put(keyDecommissionIntentCanonical, raw); err != nil {
			return err
		}
		key := append(append([]byte{}, keyDecommissionIntent...), []byte(intent.OperationID)...)
		if err := ops.Put(key, raw); err != nil {
			return err
		}
		created = true
		return nil
	})
	return created, err
}

// LoadDecommissionIntent returns the durable intent, if any.
func (s *Store) LoadDecommissionIntent() (DecommissionIntent, bool, error) {
	var intent DecommissionIntent
	found := false
	err := s.db.View(func(tx *bolt.Tx) error {
		ops := tx.Bucket([]byte(bucketOperations))
		return ops.ForEach(func(key, raw []byte) error {
			if !bytes.HasPrefix(key, keyDecommissionIntent) || bytes.Equal(key, keyDecommissionIntentCanonical) {
				return nil
			}
			if found {
				return errors.New("localstate: multiple decommission intents in one Agent store")
			}
			if err := json.Unmarshal(raw, &intent); err != nil {
				return fmt.Errorf("localstate: decode decommission intent: %w", err)
			}
			found = true
			return nil
		})
	})
	return intent, found, err
}

// WriteAgentCleanupTombstone persists the terminal cleanup tombstone.
func (s *Store) WriteAgentCleanupTombstone(ts AgentCleanupTombstone) error {
	if ts.OperationID == "" || ts.NodeID == "" {
		return errors.New("localstate: cleanup tombstone requires operation and node id")
	}
	raw, err := json.Marshal(ts)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		ops := tx.Bucket([]byte(bucketOperations))
		if existing := ops.Get(keyCleanupTombstoneCanonical); existing != nil {
			var old AgentCleanupTombstone
			if err := json.Unmarshal(existing, &old); err != nil {
				return fmt.Errorf("localstate: decode cleanup tombstone: %w", err)
			}
			if old.OperationID != ts.OperationID || old.NodeID != ts.NodeID {
				return fmt.Errorf("%w: cleanup tombstone %s/%s vs %s/%s", ErrDecommissionConflict, old.OperationID, old.NodeID, ts.OperationID, ts.NodeID)
			}
			return nil
		}
		var legacy *AgentCleanupTombstone
		if err := ops.ForEach(func(k, value []byte) error {
			if !bytes.HasPrefix(k, keyCleanupTombstone) || bytes.Equal(k, keyCleanupTombstoneCanonical) {
				return nil
			}
			var old AgentCleanupTombstone
			if err := json.Unmarshal(value, &old); err != nil {
				return err
			}
			legacy = &old
			return nil
		}); err != nil {
			return err
		}
		if legacy != nil && (legacy.OperationID != ts.OperationID || legacy.NodeID != ts.NodeID) {
			return fmt.Errorf("%w: cleanup tombstone %s/%s vs %s/%s", ErrDecommissionConflict, legacy.OperationID, legacy.NodeID, ts.OperationID, ts.NodeID)
		}
		if err := ops.Put(keyCleanupTombstoneCanonical, raw); err != nil {
			return err
		}
		return ops.Put(append(append([]byte{}, keyCleanupTombstone...), []byte(ts.OperationID)...), raw)
	})
}

// LoadAgentCleanupTombstone returns the terminal cleanup tombstone, if any.
func (s *Store) LoadAgentCleanupTombstone() (AgentCleanupTombstone, bool, error) {
	var ts AgentCleanupTombstone
	found := false
	err := s.db.View(func(tx *bolt.Tx) error {
		ops := tx.Bucket([]byte(bucketOperations))
		return ops.ForEach(func(key, raw []byte) error {
			if !bytes.HasPrefix(key, keyCleanupTombstone) || bytes.Equal(key, keyCleanupTombstoneCanonical) {
				return nil
			}
			if found {
				return errors.New("localstate: multiple cleanup tombstones in one Agent store")
			}
			if err := json.Unmarshal(raw, &ts); err != nil {
				return fmt.Errorf("localstate: decode cleanup tombstone: %w", err)
			}
			found = true
			return nil
		})
	})
	return ts, found, err
}

// ClearForwardStateForDecommission removes every Forward LKG/secret/job row in
// one transaction: applied records, activation mirrors, deletion tombstones,
// pending delete intents, the mapping journal, received desired, the hook
// queue and the keyring. Node identity (controller pins, epochs, inbox/outbox
// and operation results) is deliberately retained so the decommission ACK with
// its minimal identity can still be delivered and receipted.
func (s *Store) ClearForwardStateForDecommission() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		for _, name := range []string{bucketApplied, bucketActivation, bucketTombstones,
			bucketForwardDeleteIntents, bucketDesired, bucketHookQueue, bucketKeyring} {
			b := tx.Bucket([]byte(name))
			returnKeys := make([][]byte, 0)
			if err := b.ForEach(func(k, _ []byte) error {
				returnKeys = append(returnKeys, append([]byte{}, k...))
				return nil
			}); err != nil {
				return fmt.Errorf("localstate: enumerate %s for decommission: %w", name, err)
			}
			for _, k := range returnKeys {
				if err := b.Delete(k); err != nil {
					return fmt.Errorf("localstate: clear %s for decommission: %w", name, err)
				}
			}
		}
		mapping := tx.Bucket([]byte(bucketMapping))
		var records [][]byte
		if err := mapping.ForEach(func(k, _ []byte) error {
			records = append(records, append([]byte{}, k...))
			return nil
		}); err != nil {
			return fmt.Errorf("localstate: enumerate mapping journal for decommission: %w", err)
		}
		for _, k := range records {
			if err := mapping.Delete(k); err != nil {
				return fmt.Errorf("localstate: clear mapping journal for decommission: %w", err)
			}
		}
		return nil
	})
}

// CleanupTombstoneAllowed protects against re-admitting a decreed dead key: an
// enrollment/rotation for this node must prove the presented key hash is NOT in
// the terminal tombstone.
func (s *Store) CleanupTombstoneAllowedKeyHashes() ([]string, bool, error) {
	ts, found, err := s.LoadAgentCleanupTombstone()
	if err != nil {
		return nil, false, err
	}
	if !found {
		return nil, false, nil
	}
	return append([]string(nil), ts.AllowedKeyHashes...), true, nil
}
