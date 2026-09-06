// Controller pin persistence (P08 extension of the declared P07 control
// persistence interface — the controller_pins bucket exists in the frozen
// schema but had no accessors).
//
// The Agent pins the Controller signing key at enrollment (v0.8 §6.3: the
// Agent persists controller_instance_id and verifies every controller-signed
// message against the pin; §8.3: the pin set is fsynced before ACK and the
// highest generation is persisted to prevent downgrade).
package localstate

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"

	bolt "go.etcd.io/bbolt"
)

// ErrPinDowngrade refuses saving a controller pin whose generation is lower
// than the persisted one (anti-downgrade, v0.8 §8.3).
var ErrPinDowngrade = errors.New("localstate: controller pin generation downgrade refused")

// ControllerPin is the pinned Controller identity: instance id, key id, the
// Controller signing public key, and the key generation.
type ControllerPin struct {
	InstanceID   string `json:"instance_id"`
	KeyID        string `json:"key_id"`
	PublicKeyRaw []byte `json:"public_key"`
	Generation   uint64 `json:"generation"`
}

// PublicKey returns the pinned Ed25519 public key.
func (p ControllerPin) PublicKey() ed25519.PublicKey {
	return ed25519.PublicKey(p.PublicKeyRaw)
}

// SaveControllerPin upserts the pin for a controller instance. A lower
// generation than the persisted one is refused (downgrade protection); the
// same or higher generation replaces the entry.
func (s *Store) SaveControllerPin(pin ControllerPin) error {
	if pin.InstanceID == "" || pin.KeyID == "" || len(pin.PublicKeyRaw) != ed25519.PublicKeySize {
		return errors.New("localstate: invalid controller pin")
	}
	if pin.Generation == 0 {
		return errors.New("localstate: controller pin generation must be non-zero")
	}
	raw, err := json.Marshal(pin)
	if err != nil {
		return fmt.Errorf("localstate: encode controller pin: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketControllerPins))
		key := []byte(pin.InstanceID)
		if existing := b.Get(key); existing != nil {
			var old ControllerPin
			if err := json.Unmarshal(existing, &old); err != nil {
				return fmt.Errorf("localstate: decode existing controller pin: %w", err)
			}
			if old.Generation > pin.Generation {
				return ErrPinDowngrade
			}
		}
		return b.Put(key, raw)
	})
}

// ControllerPin returns the pinned controller for an instance.
func (s *Store) ControllerPin(instanceID string) (ControllerPin, bool, error) {
	var pin ControllerPin
	found := false
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket([]byte(bucketControllerPins)).Get([]byte(instanceID))
		if raw == nil {
			return nil
		}
		if err := json.Unmarshal(raw, &pin); err != nil {
			return fmt.Errorf("localstate: decode controller pin: %w", err)
		}
		found = true
		return nil
	})
	return pin, found, err
}

// ListControllerPins returns every pinned controller.
func (s *Store) ListControllerPins() ([]ControllerPin, error) {
	var pins []ControllerPin
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketControllerPins)).ForEach(func(_, v []byte) error {
			var pin ControllerPin
			if err := json.Unmarshal(v, &pin); err != nil {
				return fmt.Errorf("localstate: decode controller pin: %w", err)
			}
			pins = append(pins, pin)
			return nil
		})
	})
	return pins, err
}
