//go:build !windows

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const maxEnrollmentTokenBytes = 4096
const maxEnrollmentTokenChars = 256

var (
	errTokenSourceConflict = errors.New("token input sources conflict")
	errTokenFDInvalid      = errors.New("token fd is invalid or unsafe")
	errTokenFileUnsafe     = errors.New("token file is not an owner-only regular file")
	errTokenTooLarge       = errors.New("token input exceeds size limit")
	errTokenMalformed      = errors.New("token input is malformed")
	errTokenReplaced       = errors.New("token file changed before cleanup")
)

type tokenInput struct {
	token     string
	path      string
	file      *os.File
	dir       *os.File
	base      string
	dev       uint64
	ino       uint64
	closeOnce bool
}

// openTokenInput accepts exactly one protected descriptor or one secure file
// path. A path is never read through a symlink and is deleted only after a
// successful enrollment commit and an identity re-check.
func openTokenInput(fd int, path string) (*tokenInput, error) {
	if fd >= 0 && path != "" {
		return nil, errTokenSourceConflict
	}
	if fd >= 0 {
		if fd <= 2 {
			return nil, errTokenFDInvalid
		}
		unix.CloseOnExec(fd)
		file := os.NewFile(uintptr(fd), "antinat-enrollment-token-fd")
		if file == nil {
			return nil, errTokenFDInvalid
		}
		input, err := readTokenFile(file)
		if err != nil {
			_ = file.Close()
			return nil, err
		}
		input.file = file
		input.closeOnce = true
		return input, nil
	}
	if path == "" {
		return nil, errTokenFDInvalid
	}
	parentPath := filepath.Dir(path)
	base := filepath.Base(path)
	if base == "." || base == string(os.PathSeparator) {
		return nil, errTokenFileUnsafe
	}
	dirFD, err := unix.Open(parentPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errTokenFileUnsafe
	}
	parent := os.NewFile(uintptr(dirFD), "antinat-enrollment-token-parent")
	if parent == nil {
		_ = unix.Close(dirFD)
		return nil, errTokenFileUnsafe
	}
	defer func() {
		if parent != nil {
			_ = parent.Close()
		}
	}()
	var parentStat unix.Stat_t
	if err := unix.Fstat(dirFD, &parentStat); err != nil || !secureTokenParentStat(&parentStat) {
		return nil, errTokenFileUnsafe
	}
	tokenFD, err := unix.Openat(dirFD, base, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errTokenFileUnsafe
	}
	file := os.NewFile(uintptr(tokenFD), "antinat-enrollment-token-file")
	if file == nil {
		_ = unix.Close(tokenFD)
		return nil, errTokenFileUnsafe
	}
	var tokenStat unix.Stat_t
	if err := unix.Fstat(tokenFD, &tokenStat); err != nil || !secureTokenStat(&tokenStat) {
		_ = file.Close()
		return nil, errTokenFileUnsafe
	}
	input, err := readTokenFile(file)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	input.file = file
	input.path = path
	input.dir = parent
	input.base = base
	input.dev, input.ino = uint64(tokenStat.Dev), uint64(tokenStat.Ino)
	parent = nil
	input.closeOnce = true
	return input, nil
}

func secureTokenParentStat(stat *unix.Stat_t) bool {
	return stat != nil && stat.Mode&unix.S_IFMT == unix.S_IFDIR &&
		stat.Mode&0o022 == 0 && int(stat.Uid) == os.Geteuid()
}

func secureTokenStat(stat *unix.Stat_t) bool {
	return stat != nil && stat.Mode&unix.S_IFMT == unix.S_IFREG &&
		stat.Mode&0o7777 == 0o600 && int(stat.Uid) == os.Geteuid() && stat.Nlink == 1
}

func readTokenFile(file *os.File) (*tokenInput, error) {
	raw, err := io.ReadAll(io.LimitReader(file, maxEnrollmentTokenBytes+1))
	if err != nil {
		return nil, errTokenMalformed
	}
	if len(raw) > maxEnrollmentTokenBytes {
		return nil, errTokenTooLarge
	}
	token := strings.TrimSpace(string(raw))
	if token == "" || len(token) > maxEnrollmentTokenChars || strings.IndexFunc(token, func(r rune) bool {
		return r == '\r' || r == '\n' || r == '\t' || r == ' '
	}) >= 0 {
		return nil, errTokenMalformed
	}
	return &tokenInput{token: token}, nil
}

// commit is called only after the enrollment transaction succeeds.
func (in *tokenInput) commit() error {
	if in == nil || in.path == "" {
		return nil
	}
	if in.dir == nil || in.base == "" {
		return errTokenReplaced
	}
	var current unix.Stat_t
	if err := unix.Fstatat(int(in.dir.Fd()), in.base, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
		!secureTokenStat(&current) || uint64(current.Dev) != in.dev || uint64(current.Ino) != in.ino {
		return errTokenReplaced
	}
	if err := unix.Unlinkat(int(in.dir.Fd()), in.base, 0); err != nil {
		return errTokenReplaced
	}
	if err := unix.Fsync(int(in.dir.Fd())); err != nil {
		return errTokenReplaced
	}
	return nil
}

func (in *tokenInput) abort() error { return nil }

func (in *tokenInput) close() error {
	if in == nil || !in.closeOnce {
		return nil
	}
	in.closeOnce = false
	var closeErr error
	if in.file != nil {
		closeErr = in.file.Close()
	}
	if in.dir != nil {
		if err := in.dir.Close(); closeErr == nil {
			closeErr = err
		}
	}
	if closeErr != nil {
		return fmt.Errorf("token input close failed")
	}
	return nil
}
