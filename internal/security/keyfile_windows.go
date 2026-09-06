// Platform key-file persistence (Windows): the node key blob is protected
// with DPAPI (CryptProtectData) at rest and never written in plaintext.
//go:build windows

package security

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/gxbrave/AntiNAT-Agent/internal/security/framecrypto"
)

func framecryptoSign(priv []byte, msg []byte) ([]byte, error) {
	return framecrypto.Sign(priv, msg)
}

// withKeyLock serializes key creation. Windows DPAPI blobs are bound to the
// user's credentials and the agent runs one process per state directory; the
// lock is a no-op here (the Windows path is cross-build evidence, not a
// runtime target in this milestone).
func withKeyLock(dir string, fn func() error) error {
	return fn()
}

// protectDPAPI wraps plaintext with the current user's DPAPI key. The
// returned slice is a Go-owned copy: the deferred LocalFree runs after the
// return expression is evaluated, so returning unsafe.Slice into the DPAPI
// buffer would hand the caller a use-after-free slice (FIX1 F2).
func protectDPAPI(plain []byte) ([]byte, error) {
	in := windows.DataBlob{Size: uint32(len(plain))}
	if len(plain) > 0 {
		in.Data = &plain[0]
	}
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, nil, 0, nil, 0, &out); err != nil {
		return nil, fmt.Errorf("security: dpapi protect: %w", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	raw := unsafe.Slice(out.Data, int(out.Size))
	copied := make([]byte, len(raw))
	copy(copied, raw)
	return copied, nil
}

// unprotectDPAPI unwraps a DPAPI-protected blob. The returned slice is a
// Go-owned copy (see protectDPAPI: the DPAPI buffer is freed by the deferred
// LocalFree after the return value is computed).
func unprotectDPAPI(blob []byte) ([]byte, error) {
	if len(blob) == 0 {
		return nil, fmt.Errorf("security: empty dpapi blob")
	}
	in := windows.DataBlob{Size: uint32(len(blob)), Data: &blob[0]}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, 0, &out); err != nil {
		return nil, fmt.Errorf("security: dpapi unprotect: %w", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	raw := unsafe.Slice(out.Data, int(out.Size))
	copied := make([]byte, len(raw))
	copy(copied, raw)
	return copied, nil
}

// loadKeyFile reads a DPAPI-protected key file. Windows file permissions are
// not a sufficient at-rest guarantee, so the plaintext never touches disk.
func loadKeyFile(path string) ([]byte, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return unprotectDPAPI(blob)
}

// writeKeyFileAtomic persists the DPAPI-protected blob atomically.
func writeKeyFileAtomic(path string, plain []byte) error {
	protected, err := protectDPAPI(plain)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".node-key-*")
	if err != nil {
		return fmt.Errorf("security: create key temp: %w", err)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if _, err := temp.Write(protected); err != nil {
		temp.Close()
		return fmt.Errorf("security: key write: %w", err)
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return fmt.Errorf("security: key fsync: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("security: key close: %w", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("security: key rename: %w", err)
	}
	return nil
}
