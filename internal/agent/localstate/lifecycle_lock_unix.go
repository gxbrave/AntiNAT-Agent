//go:build !windows

package localstate

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// withLifecycleLock serializes marker and recovery-quarantine disk operations
// across goroutines and processes sharing one Agent state directory.
func withLifecycleLock(dir string, fn func() error) error {
	if dir == "" {
		return fmt.Errorf("localstate: lifecycle lock requires a state directory")
	}
	if err := ensurePrivateDirectory(dir); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, ".lifecycle.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("localstate: open lifecycle lock: %w", err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("localstate: lock lifecycle state: %w", err)
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return fn()
}
