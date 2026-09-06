//go:build windows

package localstate

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
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
	var overlapped windows.Overlapped
	if err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &overlapped); err != nil {
		return fmt.Errorf("localstate: lock lifecycle state: %w", err)
	}
	defer windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &overlapped)
	return fn()
}
