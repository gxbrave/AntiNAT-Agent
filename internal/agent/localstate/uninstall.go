// P14 Story 6: durable agent uninstall notice (M3 work package 6).
//
// The notice is a bounded best-effort single attempt: if the control session
// is online the notice (node_uninstall_notice) is queued for delivery and the
// local record marks it as an ONLINE attempt; if the agent is offline the
// controller's knowledge is UNKNOWN (no client can distinguish a lost notice
// from one about to arrive). The row never changes the terminal marker; the
// DECOMMISSIONED/terminal marker always prevents any LKG recovery afterward.
package localstate

import (
	"encoding/json"
	"errors"
	"fmt"

	bolt "go.etcd.io/bbolt"
)

var keyUninstallNotice = []byte("uninstall-notice:")

// UninstallNotice records one bounded uninstall-notice attempt.
type UninstallNotice struct {
	OperationID string `json:"operation_id"`
	// Connectivity reports whether the notice was sent while the control
	// session was online (true) or the agent was offline (false = UNKNOWN to
	// the controller).
	Connectivity bool   `json:"online"`
	QueuedAtUnix int64  `json:"queued_at_unix"`
	Status       string `json:"status"` // QUEUED | UNKNOWN
}

// RecordUninstallNotice durably records the bounded notice attempt.
func (s *Store) RecordUninstallNotice(notice UninstallNotice) error {
	if notice.OperationID == "" {
		return errors.New("localstate: uninstall notice requires an operation id")
	}
	status := "QUEUED"
	if !notice.Connectivity {
		status = "UNKNOWN"
	}
	notice.Status = status
	raw, err := json.Marshal(notice)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketOperations)).Put(
			append(append([]byte{}, keyUninstallNotice...), []byte(notice.OperationID)...), raw)
	})
}

// UninstallNoticeStatus returns the durable bounded notice outcome.
func (s *Store) UninstallNoticeStatus(operationID string) (UninstallNotice, bool, error) {
	var notice UninstallNotice
	var found bool
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket([]byte(bucketOperations)).Get(append(append([]byte{}, keyUninstallNotice...), []byte(operationID)...))
		if raw == nil {
			return nil
		}
		if err := json.Unmarshal(raw, &notice); err != nil {
			return fmt.Errorf("localstate: decode uninstall notice: %w", err)
		}
		found = true
		return nil
	})
	return notice, found, err
}
