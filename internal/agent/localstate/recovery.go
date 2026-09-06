// P14 Story 5: Agent RECOVERY_QUARANTINE (v0.8 §7.4).
package localstate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const recoveryQuarantineFile = "recovery.quarantine"

var ErrQuarantineOverTerminal = errors.New("localstate: cannot quarantine over a terminal DECOMMISSIONED marker")
var ErrRecoveryOperationMismatch = errors.New("localstate: recovery quarantine operation mismatch")

type RecoveryQuarantine struct {
	OperationID string `json:"operation_id"`
	Generation  uint64 `json:"generation"`
}

func loadRecoveryQuarantineUnlocked(dir string) (RecoveryQuarantine, bool, error) {
	raw, err := os.ReadFile(filepath.Join(dir, recoveryQuarantineFile))
	if err != nil {
		if errNotExist(err) {
			return RecoveryQuarantine{}, false, nil
		}
		return RecoveryQuarantine{}, false, fmt.Errorf("localstate: read recovery quarantine: %w", err)
	}
	var q RecoveryQuarantine
	if err := json.Unmarshal(raw, &q); err != nil || q.Generation == 0 {
		return RecoveryQuarantine{}, false, fmt.Errorf("localstate: invalid recovery quarantine")
	}
	return q, true, nil
}

// LoadRecoveryQuarantine reports whether the agent is quarantined. Legacy
// marker payloads are intentionally rejected: an unknown operation cannot
// authorize clearing a current recovery boundary.
func LoadRecoveryQuarantine(dir string) (bool, error) {
	_, found, err := LoadRecoveryQuarantineBinding(dir)
	return found, err
}

// LoadRecoveryQuarantineBinding returns the durable operation/generation.
func LoadRecoveryQuarantineBinding(dir string) (RecoveryQuarantine, bool, error) {
	var q RecoveryQuarantine
	var found bool
	err := withLifecycleLock(dir, func() error {
		var err error
		q, found, err = loadRecoveryQuarantineUnlocked(dir)
		return err
	})
	return q, found, err
}

func writeRecoveryQuarantineUnlocked(dir string, q RecoveryQuarantine) error {
	if q.OperationID == "" || q.Generation == 0 {
		return errors.New("localstate: recovery quarantine requires operation id and generation")
	}
	marker, err := loadMarkerUnlocked(dir)
	if err != nil {
		return err
	}
	if marker == MarkerDecommissioned {
		return ErrQuarantineOverTerminal
	}
	if current, found, err := loadRecoveryQuarantineUnlocked(dir); err != nil {
		return err
	} else if found {
		if current.OperationID == q.OperationID && current.Generation == q.Generation {
			return nil
		}
		if q.Generation <= current.Generation {
			return fmt.Errorf("%w: generation %d is not newer than %d", ErrRecoveryOperationMismatch, q.Generation, current.Generation)
		}
	}
	raw, err := json.Marshal(q)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, recoveryQuarantineFile)
	temporary, err := os.CreateTemp(dir, ".antinat-quarantine-*")
	if err != nil {
		return fmt.Errorf("localstate: quarantine temp: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("localstate: quarantine chmod: %w", err)
	}
	if _, err := temporary.Write(raw); err != nil {
		temporary.Close()
		return fmt.Errorf("localstate: quarantine write: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("localstate: quarantine fsync: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("localstate: quarantine close: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("localstate: quarantine rename: %w", err)
	}
	return syncDirectory(dir)
}

// WriteRecoveryQuarantine records a legacy-compatible generated binding. New
// callers should use WriteRecoveryQuarantineForOperation. It remains useful for
// the old localstate-only tests; controller-authenticated clears cannot use it.
func WriteRecoveryQuarantine(dir string) error {
	return WriteRecoveryQuarantineForOperation(dir, "legacy", 1)
}

// WriteRecoveryQuarantineForOperation durably records the current restore
// operation and generation under the same lock as marker operations.
func WriteRecoveryQuarantineForOperation(dir, operationID string, generation uint64) error {
	return withLifecycleLock(dir, func() error {
		return writeRecoveryQuarantineUnlocked(dir, RecoveryQuarantine{OperationID: operationID, Generation: generation})
	})
}

// WriteNextRecoveryQuarantineForOperation allocates the next generation and
// writes it while holding one lifecycle lock, preventing concurrent callers
// from selecting the same generation.
func WriteNextRecoveryQuarantineForOperation(dir, operationID string) (RecoveryQuarantine, error) {
	var result RecoveryQuarantine
	err := withLifecycleLock(dir, func() error {
		current, found, err := loadRecoveryQuarantineUnlocked(dir)
		if err != nil {
			return err
		}
		generation := uint64(1)
		if found {
			generation = current.Generation + 1
		}
		result = RecoveryQuarantine{OperationID: operationID, Generation: generation}
		return writeRecoveryQuarantineUnlocked(dir, result)
	})
	return result, err
}

// ClearRecoveryQuarantine removes the legacy binding. Real restore flows must
// call ClearRecoveryQuarantineForOperation with the exact operation/generation.
// Keeping the legacy form only for the explicitly legacy marker preserves old
// localstate callers without making it an authorization path for new markers.
func ClearRecoveryQuarantine(dir string) error {
	return withLifecycleLock(dir, func() error {
		q, found, err := loadRecoveryQuarantineUnlocked(dir)
		if err != nil {
			return err
		}
		if !found {
			return nil
		}
		if q.OperationID != "legacy" || q.Generation != 1 {
			return fmt.Errorf("%w: legacy clear cannot remove %q/%d", ErrRecoveryOperationMismatch, q.OperationID, q.Generation)
		}
		if err := os.Remove(filepath.Join(dir, recoveryQuarantineFile)); err != nil && !errNotExist(err) {
			return fmt.Errorf("localstate: clear recovery quarantine: %w", err)
		}
		return syncDirectory(dir)
	})
}

func ClearRecoveryQuarantineForOperation(dir, operationID string, generation uint64) error {
	if operationID == "" || generation == 0 {
		return ErrRecoveryOperationMismatch
	}
	return withLifecycleLock(dir, func() error {
		q, found, err := loadRecoveryQuarantineUnlocked(dir)
		if err != nil {
			return err
		}
		if !found {
			return nil
		}
		if q.OperationID != operationID || q.Generation != generation {
			return fmt.Errorf("%w: current %q/%d, requested %q/%d", ErrRecoveryOperationMismatch, q.OperationID, q.Generation, operationID, generation)
		}
		if marker, err := loadMarkerUnlocked(dir); err != nil {
			return err
		} else if marker == MarkerDecommissioned {
			return ErrQuarantineOverTerminal
		}
		if err := os.Remove(filepath.Join(dir, recoveryQuarantineFile)); err != nil && !errNotExist(err) {
			return fmt.Errorf("localstate: clear recovery quarantine: %w", err)
		}
		return syncDirectory(dir)
	})
}
