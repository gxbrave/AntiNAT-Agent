//go:build !windows

package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestR13TokenInputRejectsAmbiguousSources(t *testing.T) {
	if _, err := openTokenInput(3, "/tmp/token"); !errors.Is(err, errTokenSourceConflict) {
		t.Fatalf("fd+file accepted: %v", err)
	}
	if _, err := openTokenInput(2, ""); !errors.Is(err, errTokenFDInvalid) {
		t.Fatalf("fd 2 accepted: %v", err)
	}
}

func TestR13ProtectedFDReadsBoundedTokenWithoutPathCleanup(t *testing.T) {
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readEnd.Close()
	if _, err := io.WriteString(writeEnd, "  fd-token\n"); err != nil {
		t.Fatal(err)
	}
	_ = writeEnd.Close()
	input, err := openTokenInput(int(readEnd.Fd()), "")
	if err != nil {
		t.Fatal(err)
	}
	if input.token != "fd-token" {
		t.Fatalf("token = %q, want fd-token", input.token)
	}
	if err := input.commit(); err != nil {
		t.Fatalf("protected fd commit: %v", err)
	}
	if input.path != "" {
		t.Fatalf("protected fd unexpectedly has cleanup path %q", input.path)
	}
	_ = input.close()
}

func TestR13ProtectedFDIsMarkedCloseOnExec(t *testing.T) {
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readEnd.Close()
	flags, err := unix.FcntlInt(readEnd.Fd(), unix.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(readEnd.Fd(), unix.F_SETFD, flags&^unix.FD_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(writeEnd, "fd-token"); err != nil {
		t.Fatal(err)
	}
	_ = writeEnd.Close()
	input, err := openTokenInput(int(readEnd.Fd()), "")
	if err != nil {
		t.Fatal(err)
	}
	defer input.close()
	got, err := unix.FcntlInt(input.file.Fd(), unix.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got&unix.FD_CLOEXEC == 0 {
		t.Fatal("protected token fd remains inheritable across exec")
	}
}

func TestR13TokenFileRequiresOwnerOnlyRegular0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte("file-token"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := openTokenInput(-1, path); err == nil {
		t.Fatal("0644 token file accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Chmod(path, 0o4600); err != nil {
		t.Fatal(err)
	}
	if _, err := openTokenInput(-1, path); err == nil {
		t.Fatal("setuid 0600 token file accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	input, err := openTokenInput(-1, path)
	if err != nil {
		t.Fatal(err)
	}
	if input.token != "file-token" {
		t.Fatalf("file token = %q", input.token)
	}
	if err := input.abort(); err != nil {
		t.Fatalf("abort token file: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file removed after enrollment failure: %v", err)
	}
	input, err = openTokenInput(-1, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := input.commit(); err != nil {
		t.Fatalf("commit token file: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("original token remains after commit: %v", err)
	}
}

func TestR13EnrollmentCompletionDeletesOnlyAfterSuccessfulNew(t *testing.T) {
	dir := t.TempDir()
	failurePath := filepath.Join(dir, "failure-token")
	if err := os.WriteFile(failurePath, []byte("failure-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	failureInput, err := openTokenInput(-1, failurePath)
	if err != nil {
		t.Fatal(err)
	}
	enrollmentErr := errors.New("enrollment failed")
	if err := finalizeEnrollmentToken(failureInput, enrollmentErr); !errors.Is(err, enrollmentErr) {
		t.Fatalf("failed enrollment result = %v, want original error", err)
	}
	if _, err := os.Stat(failurePath); err != nil {
		t.Fatalf("failed enrollment removed retry token: %v", err)
	}
	_ = failureInput.close()

	successPath := filepath.Join(dir, "success-token")
	if err := os.WriteFile(successPath, []byte("success-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	successInput, err := openTokenInput(-1, successPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := finalizeEnrollmentToken(successInput, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(successPath); !os.IsNotExist(err) {
		t.Fatalf("successful enrollment left consumed token: %v", err)
	}
	_ = successInput.close()
}

func TestR13TokenFileRejectsSymlinkDirectoryAndFIFO(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := openTokenInput(-1, link); err == nil {
		t.Fatal("symlink token accepted")
	}
	if _, err := openTokenInput(-1, dir); err == nil {
		t.Fatal("directory token accepted")
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openTokenInput(-1, fifo); err == nil {
		t.Fatal("FIFO token accepted")
	}
}

func TestR13TokenFileRejectsSymlinkedParent(t *testing.T) {
	root := t.TempDir()
	realParent := filepath.Join(root, "real-parent")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(realParent, "token"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "parent-alias")
	if err := os.Symlink(realParent, alias); err != nil {
		t.Fatal(err)
	}
	input, err := openTokenInput(-1, filepath.Join(alias, "token"))
	if input != nil {
		_ = input.close()
	}
	if err == nil {
		t.Fatal("token file beneath symlinked parent was accepted")
	}
}

func TestR13TokenFileReplacementNeverDeletesReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	input, err := openTokenInput(-1, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, filepath.Join(dir, "original-renamed")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := input.commit(); err == nil {
		t.Fatal("path replacement commit unexpectedly succeeded")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "replacement" {
		t.Fatalf("replacement damaged: data=%q err=%v", data, err)
	}
	_ = input.close()
}

func TestR13TokenErrorsNeverContainSecret(t *testing.T) {
	secret := strings.Repeat("s", 64)
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte(secret), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := openTokenInput(-1, path)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("token error leaked secret: %v", err)
	}
}
