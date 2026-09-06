// Story 2 RED: the OS single-instance lock must block a second same-UID
// process, recover immediately after an abrupt owner exit (flock releases on
// process death), and reject unsafe lock paths without touching a symlink
// target (v0.8 §4.1 rule 5: stop-old-before-start-new, one Agent instance).
package traversal

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstanceLockBlocksSecondProcess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.lock")
	lock, err := AcquireInstanceLock(path)
	if err != nil {
		t.Fatalf("acquire parent instance lock: %v", err)
	}
	defer lock.Close()

	command := exec.Command(os.Args[0], "-test.run=^TestInstanceLockHelper$")
	command.Env = append(os.Environ(), "ANTINAT_P09_LOCK_HELPER="+path)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("run competing process: %v\n%s", err, output)
	}
	if got := strings.TrimSpace(string(output)); !strings.Contains(got, "LOCK_BLOCKED") {
		t.Fatalf("competing process output = %q, want LOCK_BLOCKED", got)
	}
}

func TestInstanceLockHelper(t *testing.T) {
	path := os.Getenv("ANTINAT_P09_LOCK_HELPER")
	if path == "" {
		t.Skip("subprocess helper")
	}
	lock, err := AcquireInstanceLock(path)
	if errors.Is(err, ErrInstanceLocked) {
		fmt.Println("LOCK_BLOCKED")
		return
	}
	if err != nil {
		t.Fatalf("acquire helper instance lock: %v", err)
	}
	defer lock.Close()
	fmt.Println("LOCK_ACQUIRED")
}

func TestInstanceLockRecoversAfterAbruptOwnerExit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.lock")
	command := exec.Command(os.Args[0], "-test.run=^TestInstanceLockCrashHelper$")
	command.Env = append(os.Environ(), "ANTINAT_P09_LOCK_CRASH_HELPER="+path)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("crash helper: %v\n%s", err, output)
	}
	lock, err := AcquireInstanceLock(path)
	if err != nil {
		t.Fatalf("acquire after abrupt owner exit: %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestInstanceLockCrashHelper(t *testing.T) {
	path := os.Getenv("ANTINAT_P09_LOCK_CRASH_HELPER")
	if path == "" {
		t.Skip("subprocess helper")
	}
	lock, err := AcquireInstanceLock(path)
	if err != nil {
		t.Fatalf("acquire crash-helper lock: %v", err)
	}
	fmt.Fprintln(os.Stdout, "LOCK_CRASHED_OWNER")
	_ = lock
	os.Exit(0)
}

func TestInstanceLockRejectsSymlinkWithoutTouchingTarget(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	path := filepath.Join(directory, "agent.lock")
	if err := os.WriteFile(target, []byte("must-remain"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireInstanceLock(path); err == nil {
		t.Fatal("symlink lock path unexpectedly acquired")
	}
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "must-remain" {
		t.Fatalf("symlink target changed to %q", content)
	}
}

func TestInstanceLockRejectsUnsafeParentDirectory(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o777); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "agent.lock")
	if _, err := AcquireInstanceLock(path); !errors.Is(err, ErrInvalidLockPath) {
		t.Fatalf("world-writable parent error = %v, want ErrInvalidLockPath", err)
	}
}
