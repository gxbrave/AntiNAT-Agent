// Controller signing keyring (Story 1/2).
//
// The Controller signs enrollment transcripts and session handshakes with a
// single Ed25519 signing key persisted secret-safe (0600 atomic file on Unix,
// DPAPI on Windows). The key ID is derived deterministically from the public
// key so it is stable across reloads and rotation generations can be tracked
// (generation downgrade fails closed).
package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/gxbrave/AntiNAT-Agent/internal/security/framecrypto"
)

// KeyringFile is the Controller signing key filename.
const KeyringFile = "controller-signing.key"

// KeyringStagedFile is the legacy non-active successor key filename. New
// lifecycle operations use operation-specific staged paths so one operation's
// recovery cannot remove another operation's successor.
const KeyringStagedFile = "controller-signing.key.stage"

// KeyringStagedPrefix prefixes operation-specific successor key filenames.
// The operation identity is represented by a SHA-256 digest in the suffix, so
// arbitrary operation IDs cannot escape the keyring directory.
const KeyringStagedPrefix = "controller-signing.key.stage."

// maxSupportedGeneration is the highest keyring generation this build
// understands. A file carrying a higher generation was written by a newer
// AntiNAT build and load fails closed (mirrors the bbolt schema gate).
// P14 rotation raises the bound to support generation increments.
const maxSupportedGeneration uint64 = 256

// keyringMagic identifies the keyring file format.
var keyringMagic = [4]byte{'A', 'N', 'K', 'C'}

// Keyring is the Controller signing key with its generation.
type Keyring struct {
	priv       ed25519.PrivateKey
	generation uint64
}

// LoadOrCreateKeyring loads the Controller signing key from dir, generating
// and durably persisting a fresh key when none exists. A future generation
// (downgrade protection) fails closed.
func LoadOrCreateKeyring(dir string, generation uint64) (*Keyring, error) {
	if generation == 0 {
		return nil, errors.New("security: keyring generation must be non-zero")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("security: create keyring dir: %w", err)
	}
	path := filepath.Join(dir, KeyringFile)
	raw, err := loadKeyFile(path)
	if err == nil {
		return parseKeyring(raw)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	// Same creator-lock pattern as the node key: concurrent LoadOrCreate
	// callers converge on one keyring file.
	var result *Keyring
	err = withKeyLock(dir, func() error {
		if raw2, err2 := loadKeyFile(path); err2 == nil {
			k, err := parseKeyring(raw2)
			if err == nil {
				result = k
			}
			return err
		}
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("security: generate keyring: %w", err)
		}
		kr := &Keyring{priv: priv, generation: generation}
		if err := kr.saveAtomic(path); err != nil {
			return err
		}
		raw3, err := loadKeyFile(path)
		if err != nil {
			return fmt.Errorf("security: reload keyring after write: %w", err)
		}
		k, err := parseKeyring(raw3)
		if err == nil {
			result = k
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func parseKeyring(raw []byte) (*Keyring, error) {
	if len(raw) != 4+8+ed25519.PrivateKeySize {
		return nil, errors.New("security: keyring file has invalid length")
	}
	if string(raw[:4]) != string(keyringMagic[:]) {
		return nil, errors.New("security: keyring file has invalid magic")
	}
	generation := binary.BigEndian.Uint64(raw[4:12])
	if generation == 0 {
		return nil, errors.New("security: keyring file has zero generation")
	}
	if generation > maxSupportedGeneration {
		return nil, fmt.Errorf("security: keyring generation %d is newer than this build supports (%d)", generation, maxSupportedGeneration)
	}
	priv := ed25519.PrivateKey(append([]byte(nil), raw[12:]...))
	return &Keyring{priv: priv, generation: generation}, nil
}

func (k *Keyring) saveAtomic(path string) error {
	blob := make([]byte, 0, 4+8+ed25519.PrivateKeySize)
	blob = append(blob, keyringMagic[:]...)
	var g [8]byte
	binary.BigEndian.PutUint64(g[:], k.generation)
	blob = append(blob, g[:]...)
	blob = append(blob, k.priv...)
	return writeKeyFileAtomic(path, blob)
}

// Rotate writes a successor keyring at generation+1 atomically (same temp +
// fsync + rename + parent-fsync pattern as the initial write) and returns the
// new Keyring. The old Keyring remains the signer for the overlap window until
// the rotation operation reaches RETIRED; the successor's public key is what
// the signed rotation certificate binds. This historical API is retained for
// callers that explicitly request activation; lifecycle.PrepareRotation uses
// GenerateNewKeyringKey plus Stage instead so journal intent precedes activation.
func (k *Keyring) Rotate(dir string) (*Keyring, error) {
	if k.generation >= maxSupportedGeneration {
		return nil, fmt.Errorf("security: keyring rotation beyond supported generation %d", maxSupportedGeneration)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("security: rotate generate key: %w", err)
	}
	next := &Keyring{priv: priv, generation: k.generation + 1}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("security: rotation dir: %w", err)
	}
	if err := next.saveAtomic(filepath.Join(dir, KeyringFile)); err != nil {
		return nil, fmt.Errorf("security: rotate persist keyring: %w", err)
	}
	return next, nil
}

// GenerateSuccessor creates successor key material without touching the active
// signer file. Callers can journal intent and then Stage the returned key.
func (k *Keyring) GenerateSuccessor() (*Keyring, error) {
	if k.generation >= maxSupportedGeneration {
		return nil, fmt.Errorf("security: keyring rotation beyond supported generation %d", maxSupportedGeneration)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("security: generate successor key: %w", err)
	}
	return &Keyring{priv: priv, generation: k.generation + 1}, nil
}

// Stage persists successor key material separately from the active signer.
// It is retained as a compatibility API for callers that use the historical
// single staging slot; lifecycle rotation uses StageForOperation instead.
func (k *Keyring) Stage(dir string) error {
	if k == nil || k.generation == 0 {
		return errors.New("security: staged key is empty")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("security: stage key dir: %w", err)
	}
	if err := k.saveAtomic(filepath.Join(dir, KeyringStagedFile)); err != nil {
		return fmt.Errorf("security: stage successor keyring: %w", err)
	}
	return nil
}

// stagedOperationPath derives a directory-confined path from the operation
// identity. Hashing rather than sanitizing prevents separators and other path
// syntax in an operation ID from escaping the keyring directory.
func stagedOperationPath(dir, operationID string) (string, error) {
	if dir == "" {
		return "", errors.New("security: staged key directory is required")
	}
	if operationID == "" {
		return "", errors.New("security: staged key operation id is required")
	}
	sum := sha256.Sum256([]byte(operationID))
	return filepath.Join(dir, KeyringStagedPrefix+hex.EncodeToString(sum[:])), nil
}

// StageForOperation persists successor key material in a path bound to one
// durable rotation operation. It never overwrites another operation's stage.
func (k *Keyring) StageForOperation(dir, operationID string) error {
	if k == nil || k.generation == 0 {
		return errors.New("security: staged key is empty")
	}
	path, err := stagedOperationPath(dir, operationID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("security: stage key dir: %w", err)
	}
	if err := k.saveAtomic(path); err != nil {
		return fmt.Errorf("security: stage successor keyring: %w", err)
	}
	return nil
}

// LoadStagedKeyring loads and validates the historical staging file.
func LoadStagedKeyring(dir string) (*Keyring, error) {
	raw, err := loadKeyFile(filepath.Join(dir, KeyringStagedFile))
	if err != nil {
		return nil, err
	}
	return parseKeyring(raw)
}

// LoadStagedKeyringForOperation loads only the stage belonging to operationID.
func LoadStagedKeyringForOperation(dir, operationID string) (*Keyring, error) {
	path, err := stagedOperationPath(dir, operationID)
	if err != nil {
		return nil, err
	}
	raw, err := loadKeyFile(path)
	if err != nil {
		return nil, err
	}
	return parseKeyring(raw)
}

// RemoveStaged removes the historical staging file. It is idempotent and
// fsyncs the containing directory.
func RemoveStaged(dir string) error {
	return removeStagedPath(filepath.Join(dir, KeyringStagedFile), dir)
}

// RemoveStagedForOperation removes only operationID's successor material. It
// cannot delete a stage belonging to any other operation.
func RemoveStagedForOperation(dir, operationID string) error {
	path, err := stagedOperationPath(dir, operationID)
	if err != nil {
		return err
	}
	return removeStagedPath(path, dir)
}

func removeStagedPath(path, dir string) error {
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("security: remove staged keyring: %w", err)
	}
	if err := syncStagedDirectory(dir); err != nil {
		return fmt.Errorf("security: remove staged keyring directory sync: %w", err)
	}
	return nil
}

func syncStagedDirectory(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	return syncDirForStaging(dir)
}

// ActivateStaged atomically promotes the historical staged successor material
// to the active signer only after the caller has durably journaled PREPARED.
func ActivateStaged(dir string) (*Keyring, error) {
	return activateStagedPath(dir, filepath.Join(dir, KeyringStagedFile))
}

// ActivateStagedForOperation promotes only operationID's staged successor.
func ActivateStagedForOperation(dir, operationID string) (*Keyring, error) {
	path, err := stagedOperationPath(dir, operationID)
	if err != nil {
		return nil, err
	}
	return activateStagedPath(dir, path)
}

func activateStagedPath(dir, path string) (*Keyring, error) {
	raw, err := loadKeyFile(path)
	if err != nil {
		return nil, fmt.Errorf("security: load staged keyring: %w", err)
	}
	next, err := parseKeyring(raw)
	if err != nil {
		return nil, err
	}
	if err := withKeyLock(dir, func() error {
		if err := os.Rename(path, filepath.Join(dir, KeyringFile)); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("security: activate staged keyring: %w", err)
	}
	return next, nil
}

// PublicKey returns the Controller signing public key.
func (k *Keyring) PublicKey() ed25519.PublicKey {
	return k.priv.Public().(ed25519.PublicKey)
}

// KeyID returns the deterministic key ID (hex of the first 8 bytes of the
// public key hash) — stable across reloads and used in enrollment results,
// session welcomes, and envelope headers.
func (k *Keyring) KeyID() string {
	sum := sha256.Sum256(k.PublicKey())
	return hex.EncodeToString(sum[:8])
}

// Generation returns the key generation (anti-downgrade).
func (k *Keyring) Generation() uint64 { return k.generation }

// Sign signs msg with the Controller signing key.
func (k *Keyring) Sign(msg []byte) ([]byte, error) {
	return framecrypto.Sign(k.priv, msg)
}

// PrivateKey returns the signing private key (used to build control
// envelopes; the Keyring remains the only owner of the key material).
func (k *Keyring) PrivateKey() ed25519.PrivateKey {
	return k.priv
}

// VerifyKeyringSignature verifies msg/sig against the given public key.
func VerifyKeyringSignature(pub ed25519.PublicKey, msg, sig []byte) bool {
	return framecrypto.Verify(pub, msg, sig)
}
