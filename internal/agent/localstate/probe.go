// Durable armed probe operations (schema v2, docs/protocol.md §7.2).
//
// The agent persists each outstanding probe operation with its monotonic
// deadline BEFORE answering probe_armed (RDY1). A crash mid-probe therefore
// never loses an armed operation: on restart the controller can re-request
// the provider without re-arming, and the ingress gate refuses frames whose
// operation is gone.
package localstate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
	"github.com/gxbrave/AntiNAT-Agent/internal/security"
)

// ArmedProbe is one durable armed probe operation. Deadline is the
// monotonic-clock deadline derived from the arm's ttl_ms. Consumed rows are
// retained as durable replay fences through ReceiptDeadline, independent of
// whether the control receipt has been sent or semantically acknowledged.
type ArmedProbe struct {
	Arm protocol.ProbeArm
	// ForwardID binds ingress admission to the listener that received the
	// controller arm. It is part of the durable operation, not inferred from
	// the source address or probe id.
	ForwardID string
	Digest    [32]byte
	Deadline  time.Time
	// ArmedAt is the wall-clock anchor persisted alongside Deadline. A restart
	// whose wall clock is before this anchor cannot prove elapsed TTL and must
	// fail closed instead of reviving the operation.
	ArmedAt     time.Time
	Consumed    bool
	Receipt     []byte
	ReceiptSent bool
	// ChallengeHash binds the consumed receipt and ACK to the exact WAN1
	// challenge that was durably joined.
	ChallengeHash [32]byte
	// ACK retains the exact same-path ACK1 bytes after durable consumption.
	// ACKSent distinguishes a successful provider write from an ACK that still
	// needs replay after a partial/failed connection write.
	ACK     []byte
	ACKSent bool
	// ReceiptAcknowledged records semantic Controller acknowledgement separately
	// from transport delivery. The consumed row remains a replay fence until
	// ReceiptDeadline even after this flag is set.
	ReceiptAcknowledged bool
	// ReceiptMessageID retains the historical field name but stores the
	// semantic operation id expected from the controller's receipt payload.
	ReceiptMessageID string
	// ReceiptDeadline bounds a consumed tombstone even if the controller is
	// permanently unavailable.
	ReceiptDeadline time.Time
}

var (
	ErrProbeConsumed = errors.New("localstate: probe id already consumed")
	ErrProbeConflict = errors.New("localstate: probe id conflicts with existing arm")
	ErrProbeNotFound = errors.New("localstate: probe id not found")
)

const defaultProbeScanLimit = 256

const probeReceiptIndexPrefix = "receipt/"

// ErrProbeAdmissionConflict means the durable applied forward or activation
// snapshot changed while an ARM admission was being committed.
var ErrProbeAdmissionConflict = errors.New("localstate: probe admission conflict")

func probeReceiptIndexKey(operationID string) []byte {
	return []byte(probeReceiptIndexPrefix + operationID)
}

func isProbeOperationKey(key []byte) bool {
	return len(key) == 16 && !bytes.HasPrefix(key, []byte(probeReceiptIndexPrefix))
}

// SaveArmedProbe durably persists an armed probe operation. Re-saving the
// same unconsumed probe id replaces the row only when the arm material is
// identical; consumed ids are permanent replay fences.
func (s *Store) SaveArmedProbe(arm protocol.ProbeArm, deadline time.Time) error {
	return s.SaveArmedProbeForForward(arm, "", deadline)
}

// SaveArmedProbeForForward persists an armed operation and its listener
// ownership in one bbolt write. Replays must match both the arm material and
// the forward binding.
func (s *Store) SaveArmedProbeForForward(arm protocol.ProbeArm, forwardID string, deadline time.Time) error {
	armedAt := time.Time{}
	if arm.TTLMS > 0 {
		armedAt = deadline.Add(-time.Duration(arm.TTLMS) * time.Millisecond)
	}
	rec := ArmedProbe{
		Arm: arm, ForwardID: forwardID, Digest: arm.Digest(), Deadline: deadline,
		ArmedAt: armedAt,
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("localstate: encode armed probe: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketProbeOps))
		if old := bucket.Get(arm.ProbeID[:]); old != nil {
			var existing ArmedProbe
			if err := json.Unmarshal(old, &existing); err != nil {
				return fmt.Errorf("localstate: decode existing armed probe: %w", err)
			}
			if existing.Consumed {
				return ErrProbeConsumed
			}
			if existing.ForwardID != rec.ForwardID || existing.Digest != rec.Digest || !bytes.Equal(existing.Arm.Canonical(), arm.Canonical()) {
				return ErrProbeConflict
			}
		}
		return bucket.Put(arm.ProbeID[:], raw)
	})
}

// LoadArmedProbe returns the armed operation for a probe id, if present.
func (s *Store) LoadArmedProbe(probeID [16]byte) (ArmedProbe, bool, error) {
	var rec ArmedProbe
	found := false
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket([]byte(bucketProbeOps)).Get(probeID[:])
		if raw == nil {
			return nil
		}
		if err := json.Unmarshal(raw, &rec); err != nil {
			return fmt.Errorf("localstate: decode armed probe: %w", err)
		}
		found = true
		return nil
	})
	return rec, found, err
}

// CommitProbeAdmission durably records the activated snapshot and ARM1 in one
// bbolt transaction. The applied revision, activation identity, and previous
// snapshot are checked inside that transaction so a stale admission cannot
// publish an ARM for a newer or rolled-back forward.
func (s *Store) CommitProbeAdmission(forwardID string, expectedRevision uint64, activation string, arm protocol.ProbeArm, deadline time.Time, before, after protocol.ActivationStates) error {
	if forwardID == "" || expectedRevision == 0 || activation == "" {
		return ErrProbeAdmissionConflict
	}
	if err := arm.Validate(); err != nil {
		return err
	}
	if err := before.Validate(); err != nil {
		return err
	}
	if err := after.Validate(); err != nil {
		return err
	}
	wantActivation := protocol.ActivationID(forwardID, expectedRevision)
	if activation != hex.EncodeToString(wantActivation[:]) || arm.Activation != wantActivation {
		return ErrProbeAdmissionConflict
	}
	armedAt := time.Time{}
	if arm.TTLMS > 0 {
		armedAt = deadline.Add(-time.Duration(arm.TTLMS) * time.Millisecond)
	}
	rec := ArmedProbe{Arm: arm, ForwardID: forwardID, Digest: arm.Digest(), Deadline: deadline, ArmedAt: armedAt}
	rawArm, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	snapshot := ActivationSnapshot{ForwardID: forwardID, Activation: activation, Generation: expectedRevision, States: after}
	rawSnapshot, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		applied, found, err := loadAppliedRecordTx(tx.Bucket([]byte(bucketApplied)), forwardID)
		if err != nil {
			return err
		}
		if !found || applied.State.SpecRevision != expectedRevision {
			return ErrProbeAdmissionConflict
		}
		oldSnapshotRaw := tx.Bucket([]byte(bucketActivation)).Get([]byte(forwardID))
		if oldSnapshotRaw != nil {
			var old ActivationSnapshot
			if err := json.Unmarshal(oldSnapshotRaw, &old); err != nil {
				return err
			}
			if err := validateActivationSnapshot(forwardID, old); err != nil {
				return err
			}
			if old.Activation != activation || old.Generation != expectedRevision || old.States != before {
				return ErrProbeAdmissionConflict
			}
		}
		probeBucket := tx.Bucket([]byte(bucketProbeOps))
		if oldRaw := probeBucket.Get(arm.ProbeID[:]); oldRaw != nil {
			var existing ArmedProbe
			if err := json.Unmarshal(oldRaw, &existing); err != nil {
				return err
			}
			if existing.Consumed {
				return ErrProbeConsumed
			}
			if existing.ForwardID != forwardID || existing.Digest != rec.Digest || !bytes.Equal(existing.Arm.Canonical(), arm.Canonical()) {
				return ErrProbeConflict
			}
		}
		if err := validateActivationSnapshot(forwardID, snapshot); err != nil {
			return err
		}
		if err := tx.Bucket([]byte(bucketActivation)).Put([]byte(forwardID), rawSnapshot); err != nil {
			return err
		}
		if err := probeBucket.Put(arm.ProbeID[:], rawArm); err != nil {
			return err
		}
		return nil
	})
}

// DeleteArmedProbe removes an operation (normally only an expired row).
func (s *Store) DeleteArmedProbe(probeID [16]byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketProbeOps))
		raw := bucket.Get(probeID[:])
		if raw != nil {
			var rec ArmedProbe
			if err := json.Unmarshal(raw, &rec); err != nil {
				return err
			}
			if rec.ReceiptMessageID != "" {
				if err := bucket.Delete(probeReceiptIndexKey(rec.ReceiptMessageID)); err != nil {
					return err
				}
			}
		}
		return bucket.Delete(probeID[:])
	})
}

// MarkArmedProbeConsumed durably records the receipt before any network ACK
// or control-channel send. A consumed probe id can therefore never be rearmed
// after a process crash, and a failed receipt send can be retried later.
func (s *Store) MarkArmedProbeConsumed(probeID [16]byte, receipt []byte) error {
	return s.MarkArmedProbeConsumedWithReceipt(probeID, receipt, "", time.Now().Add(protocol.ProbeReplayWindow))
}

// MarkArmedProbeConsumedWithACK records the exact RCT1 and ACK1 material in
// one durable transaction before either network write.
func (s *Store) MarkArmedProbeConsumedWithACK(probeID [16]byte, receipt, ack []byte, challengeHash [32]byte, receiptMessageID string, receiptDeadline time.Time) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketProbeOps))
		raw := bucket.Get(probeID[:])
		if raw == nil {
			return ErrProbeNotFound
		}
		var rec ArmedProbe
		if err := json.Unmarshal(raw, &rec); err != nil {
			return fmt.Errorf("localstate: decode armed probe: %w", err)
		}
		if rec.Consumed {
			if rec.ReceiptMessageID != receiptMessageID || !bytes.Equal(rec.Receipt, receipt) || !bytes.Equal(rec.ACK, ack) || rec.ChallengeHash != challengeHash {
				return ErrProbeConflict
			}
			return nil
		}
		rec.Consumed = true
		rec.Receipt = append([]byte(nil), receipt...)
		rec.ReceiptSent = false
		rec.ReceiptMessageID = receiptMessageID
		rec.ReceiptDeadline = receiptDeadline
		rec.ChallengeHash = challengeHash
		rec.ACK = append([]byte(nil), ack...)
		rec.ACKSent = false
		updated, err := json.Marshal(rec)
		if err != nil {
			return fmt.Errorf("localstate: encode consumed probe: %w", err)
		}
		if err := bucket.Put(probeID[:], updated); err != nil {
			return err
		}
		if receiptMessageID != "" {
			return bucket.Put(probeReceiptIndexKey(receiptMessageID), probeID[:])
		}
		return nil
	})
}

// MarkArmedProbeConsumedWithReceipt records the deterministic controller
// receipt id and a bounded tombstone deadline in the same bbolt transaction as
// the consumed fence.
func (s *Store) MarkArmedProbeConsumedWithReceipt(probeID [16]byte, receipt []byte, receiptMessageID string, receiptDeadline time.Time) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketProbeOps))
		raw := bucket.Get(probeID[:])
		if raw == nil {
			return ErrProbeNotFound
		}
		var rec ArmedProbe
		if err := json.Unmarshal(raw, &rec); err != nil {
			return fmt.Errorf("localstate: decode armed probe: %w", err)
		}
		if !rec.Consumed {
			rec.Consumed = true
			rec.Receipt = append([]byte(nil), receipt...)
			rec.ReceiptSent = false
			rec.ReceiptMessageID = receiptMessageID
			rec.ReceiptDeadline = receiptDeadline
		} else {
			if rec.ReceiptMessageID == "" {
				rec.ReceiptMessageID = receiptMessageID
			}
			if rec.ReceiptDeadline.IsZero() {
				rec.ReceiptDeadline = receiptDeadline
			}
		}
		updated, err := json.Marshal(rec)
		if err != nil {
			return fmt.Errorf("localstate: encode consumed probe: %w", err)
		}
		if err := bucket.Put(probeID[:], updated); err != nil {
			return err
		}
		if rec.ReceiptMessageID != "" {
			if err := bucket.Put(probeReceiptIndexKey(rec.ReceiptMessageID), probeID[:]); err != nil {
				return err
			}
		}
		return nil
	})
}

// SetArmedProbeACK records the exact same-path ACK1 bytes before a provider
// write. The consumed row remains the replay fence even when the connection
// fails after a partial write.
func (s *Store) SetArmedProbeACK(probeID [16]byte, ack []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketProbeOps))
		raw := bucket.Get(probeID[:])
		if raw == nil {
			return ErrProbeNotFound
		}
		var rec ArmedProbe
		if err := json.Unmarshal(raw, &rec); err != nil {
			return fmt.Errorf("localstate: decode armed probe: %w", err)
		}
		if !rec.Consumed {
			return ErrProbeNotFound
		}
		rec.ACK = append([]byte(nil), ack...)
		rec.ACKSent = false
		updated, err := json.Marshal(rec)
		if err != nil {
			return fmt.Errorf("localstate: encode ACK-pending probe: %w", err)
		}
		return bucket.Put(probeID[:], updated)
	})
}

// MarkArmedProbeACKSent records that the exact ACK1 bytes were fully written
// to the provider connection.
func (s *Store) MarkArmedProbeACKSent(probeID [16]byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketProbeOps))
		raw := bucket.Get(probeID[:])
		if raw == nil {
			return ErrProbeNotFound
		}
		var rec ArmedProbe
		if err := json.Unmarshal(raw, &rec); err != nil {
			return fmt.Errorf("localstate: decode armed probe: %w", err)
		}
		rec.ACKSent = true
		updated, err := json.Marshal(rec)
		if err != nil {
			return fmt.Errorf("localstate: encode ACK-sent probe: %w", err)
		}
		return bucket.Put(probeID[:], updated)
	})
}

// MarkArmedProbeReceiptSent records that the durable receipt was accepted by
// the control-channel sender. The consumed row remains as a replay fence.
func (s *Store) MarkArmedProbeReceiptSent(probeID [16]byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketProbeOps))
		raw := bucket.Get(probeID[:])
		if raw == nil {
			return ErrProbeNotFound
		}
		var rec ArmedProbe
		if err := json.Unmarshal(raw, &rec); err != nil {
			return fmt.Errorf("localstate: decode armed probe: %w", err)
		}
		rec.ReceiptSent = true
		updated, err := json.Marshal(rec)
		if err != nil {
			return fmt.Errorf("localstate: encode receipted probe: %w", err)
		}
		return bucket.Put(probeID[:], updated)
	})
}

// AcknowledgeArmedProbeReceipt records semantic acknowledgement for the
// consumed tombstone identified by the controller's deterministic receipt
// operation id. It intentionally does not delete the row: the consumed
// probe/source/digest fence remains active through ReceiptDeadline. Missing
// rows are idempotent (a redelivered receipt after GC is harmless). Rows
// written by the previous envelope-id implementation are accepted once, but
// only when their stored receipt bytes derive the same semantic operation id.
func (s *Store) AcknowledgeArmedProbeReceipt(operationID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketProbeOps))
		acknowledgeMatch := func(probeID []byte, raw []byte) (bool, error) {
			var rec ArmedProbe
			if err := json.Unmarshal(raw, &rec); err != nil {
				return false, err
			}
			matches := rec.Consumed && rec.ReceiptMessageID == operationID
			if !matches && rec.Consumed && len(rec.Receipt) != 0 {
				sum := sha256.Sum256(rec.Receipt)
				semanticID := hex.EncodeToString(sum[:])
				legacyID := security.MessageID(semanticID, "probe_ingress_receipt")
				matches = operationID == semanticID && rec.ReceiptMessageID == hex.EncodeToString(legacyID[:])
			}
			if !matches {
				return false, nil
			}
			rec.ReceiptAcknowledged = true
			updated, err := json.Marshal(rec)
			if err != nil {
				return false, fmt.Errorf("localstate: encode acknowledged probe: %w", err)
			}
			if err := bucket.Put(probeID, updated); err != nil {
				return false, err
			}
			return true, nil
		}

		// New rows are indexed by their semantic operation id, so an
		// acknowledgement remains complete even when the retained tombstone is
		// beyond the bounded history scan.
		if probeID := bucket.Get(probeReceiptIndexKey(operationID)); len(probeID) == 16 {
			raw := bucket.Get(probeID)
			if raw != nil {
				matched, err := acknowledgeMatch(append([]byte(nil), probeID...), raw)
				if err != nil {
					return err
				}
				if matched {
					return nil
				}
			}
		}

		// Compatibility path for pre-index rows. It is intentionally bounded;
		// all newly written rows use the direct index above.
		scanned := 0
		return bucket.ForEach(func(k, raw []byte) error {
			if !isProbeOperationKey(k) || scanned >= defaultProbeScanLimit {
				return nil
			}
			scanned++
			_, err := acknowledgeMatch(append([]byte(nil), k...), raw)
			return err
		})
	})
}

// SweepArmedProbeTombstones bounds consumed replay fences. Unconsumed rows
// are retained until their arm deadline; consumed rows are retained until the
// controller receipt or the explicit receipt deadline, whichever comes first.
func (s *Store) SweepArmedProbeTombstones(now time.Time) error {
	return s.SweepArmedProbeTombstonesLimit(now, defaultProbeScanLimit)
}

// SweepArmedProbeTombstonesLimit bounds one cleanup transaction. Callers may
// repeat cleanup on subsequent ticks; a single tick must never scan an
// unbounded replay/history bucket.
func (s *Store) SweepArmedProbeTombstonesLimit(now time.Time, limit int) error {
	_, _, err := s.SweepArmedProbeTombstonesPage(now, limit, nil)
	return err
}

// SweepArmedProbeTombstonesPage removes one ordered bounded page and returns a
// cursor for the next page. Retained rows no longer starve expired rows behind
// them in the bbolt key order.
func (s *Store) SweepArmedProbeTombstonesPage(now time.Time, limit int, after []byte) ([]byte, bool, error) {
	if limit <= 0 {
		limit = defaultProbeScanLimit
	}
	var next []byte
	done := true
	err := s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketProbeOps))
		cursor := bucket.Cursor()
		var key, raw []byte
		var lastKey []byte
		if len(after) == 0 {
			key, raw = cursor.First()
		} else {
			key, raw = cursor.Seek(after)
			if bytes.Equal(key, after) {
				key, raw = cursor.Next()
			}
		}
		scanned := 0
		var remove [][]byte
		for ; key != nil; key, raw = cursor.Next() {
			if !isProbeOperationKey(key) {
				continue
			}
			if scanned >= limit {
				next = append([]byte(nil), lastKey...)
				done = false
				break
			}
			scanned++
			lastKey = append(lastKey[:0], key...)
			var rec ArmedProbe
			if err := json.Unmarshal(raw, &rec); err != nil {
				return fmt.Errorf("localstate: scan probe tombstones: %w", err)
			}
			if (!rec.Consumed && !now.Before(rec.Deadline)) ||
				(rec.Consumed && !rec.ReceiptDeadline.IsZero() && !now.Before(rec.ReceiptDeadline)) {
				remove = append(remove, append([]byte(nil), key...))
			}
		}
		for _, k := range remove {
			raw := bucket.Get(k)
			if raw != nil {
				var rec ArmedProbe
				if err := json.Unmarshal(raw, &rec); err != nil {
					return err
				}
				if rec.ReceiptMessageID != "" {
					if err := bucket.Delete(probeReceiptIndexKey(rec.ReceiptMessageID)); err != nil {
						return err
					}
				}
			}
			if err := bucket.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
	return next, done, err
}

// SetArmedProbeReceiptMessageID fills the deterministic receipt id after an
// older process has already consumed the row. It is idempotent and preserves
// the original receipt bytes/deadline.
func (s *Store) SetArmedProbeReceiptMessageID(probeID [16]byte, messageID string, deadline time.Time) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketProbeOps))
		raw := bucket.Get(probeID[:])
		if raw == nil {
			return ErrProbeNotFound
		}
		var rec ArmedProbe
		if err := json.Unmarshal(raw, &rec); err != nil {
			return err
		}
		if rec.Consumed {
			if rec.ReceiptMessageID == "" {
				rec.ReceiptMessageID = messageID
			}
			if rec.ReceiptDeadline.IsZero() {
				rec.ReceiptDeadline = deadline
			}
		}
		updated, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		if err := bucket.Put(probeID[:], updated); err != nil {
			return err
		}
		if rec.Consumed && rec.ReceiptMessageID != "" {
			if err := bucket.Put(probeReceiptIndexKey(rec.ReceiptMessageID), probeID[:]); err != nil {
				return err
			}
		}
		return nil
	})
}

// ListArmedProbesPage returns one ordered, bounded page and a cursor for the
// next page. The cursor is the last returned probe key; index rows are skipped
// without consuming the page budget.
func (s *Store) ListArmedProbesPage(limit int, after []byte) ([]ArmedProbe, []byte, bool, error) {
	if limit <= 0 {
		limit = defaultProbeScanLimit
	}
	var out []ArmedProbe
	var next []byte
	done := true
	err := s.db.View(func(tx *bolt.Tx) error {
		cursor := tx.Bucket([]byte(bucketProbeOps)).Cursor()
		var key, raw []byte
		var lastKey []byte
		if len(after) == 0 {
			key, raw = cursor.First()
		} else {
			key, raw = cursor.Seek(after)
			if bytes.Equal(key, after) {
				key, raw = cursor.Next()
			}
		}
		for ; key != nil; key, raw = cursor.Next() {
			if !isProbeOperationKey(key) {
				continue
			}
			if len(out) >= limit {
				next = append([]byte(nil), lastKey...)
				done = false
				return nil
			}
			var rec ArmedProbe
			if err := json.Unmarshal(raw, &rec); err != nil {
				return fmt.Errorf("localstate: decode armed probe: %w", err)
			}
			out = append(out, rec)
			lastKey = append(lastKey[:0], key...)
		}
		return nil
	})
	return out, next, done, err
}

// ListArmedProbes returns every durable armed operation (expired included;
// the caller filters by deadline). Used for restart recovery and bounded
// sweeping.
func (s *Store) ListArmedProbes() ([]ArmedProbe, error) {
	return s.ListArmedProbesLimit(defaultProbeScanLimit)
}

// ListArmedProbesLimit returns at most limit durable probe rows, keeping
// restart replay and receipt retry work proportional to the bounded active
// operation budget rather than total database history.
func (s *Store) ListArmedProbesLimit(limit int) ([]ArmedProbe, error) {
	if limit <= 0 {
		limit = defaultProbeScanLimit
	}
	var out []ArmedProbe
	err := s.db.View(func(tx *bolt.Tx) error {
		scanned := 0
		return tx.Bucket([]byte(bucketProbeOps)).ForEach(func(key, raw []byte) error {
			if !isProbeOperationKey(key) || scanned >= limit {
				return nil
			}
			scanned++
			var rec ArmedProbe
			if err := json.Unmarshal(raw, &rec); err != nil {
				return fmt.Errorf("localstate: decode armed probe: %w", err)
			}
			out = append(out, rec)
			return nil
		})
	})
	return out, err
}
