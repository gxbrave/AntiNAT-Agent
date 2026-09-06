// Agent node identity key (Story 2: secret-safe bootstrap).
//
// The node key is the Agent's Ed25519 identity used for enrollment possession
// proofs and control-frame signing. It is persisted secret-safe: the file is
// written atomically with owner-only permissions on Unix and DPAPI-protected
// on Windows (see keyfile_unix.go / keyfile_windows.go). Key material never
// appears in errors or logs.
package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// NodeKeyFile is the node identity key filename inside the Agent key dir.
const NodeKeyFile = "node.key"

// nodeKeyMagic identifies the node key file format.
var nodeKeyMagic = [4]byte{'A', 'N', 'K', '1'}

// NodeKey is an Agent Ed25519 identity with its credential version.
type NodeKey struct {
	priv    ed25519.PrivateKey
	version uint32
}

// LoadOrCreateNodeKey loads the node key from dir, generating and durably
// persisting a fresh key when none exists. Concurrent callers converge on one
// key: the winner's file wins and losers reload it.
func LoadOrCreateNodeKey(dir string, version uint32) (*NodeKey, error) {
	if version == 0 {
		return nil, errors.New("security: node key credential version must be non-zero")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("security: create key dir: %w", err)
	}
	path := filepath.Join(dir, NodeKeyFile)
	raw, err := loadKeyFile(path)
	if err == nil {
		return parseNodeKey(raw)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	// Generate a fresh key and persist atomically under the creator lock; the
	// file is authoritative. Concurrent creators serialize on the lock: the
	// winner writes, every other caller reloads the final file content.
	var result *NodeKey
	err = withKeyLock(dir, func() error {
		if raw2, err2 := loadKeyFile(path); err2 == nil {
			k, err := parseNodeKey(raw2)
			if err == nil {
				result = k
			}
			return err
		}
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("security: generate node key: %w", err)
		}
		k := &NodeKey{priv: priv, version: version}
		if err := k.saveAtomic(path); err != nil {
			return err
		}
		raw3, err := loadKeyFile(path)
		if err != nil {
			return fmt.Errorf("security: reload node key after write: %w", err)
		}
		k, err = parseNodeKey(raw3)
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

// parseNodeKey validates the file layout before any copy.
func parseNodeKey(raw []byte) (*NodeKey, error) {
	if len(raw) != 4+4+ed25519.PrivateKeySize {
		return nil, errors.New("security: node key file has invalid length")
	}
	if string(raw[:4]) != string(nodeKeyMagic[:]) {
		return nil, errors.New("security: node key file has invalid magic")
	}
	version := binary.BigEndian.Uint32(raw[4:8])
	if version == 0 {
		return nil, errors.New("security: node key file has zero credential version")
	}
	priv := ed25519.PrivateKey(append([]byte(nil), raw[8:]...))
	return &NodeKey{priv: priv, version: version}, nil
}

// saveAtomic writes the key file via temp + fsync + rename + parent fsync so
// a crash never leaves a torn key file.
func (k *NodeKey) saveAtomic(path string) error {
	blob := make([]byte, 0, 4+4+ed25519.PrivateKeySize)
	blob = append(blob, nodeKeyMagic[:]...)
	var v [4]byte
	binary.BigEndian.PutUint32(v[:], k.version)
	blob = append(blob, v[:]...)
	blob = append(blob, k.priv...)
	return writeKeyFileAtomic(path, blob)
}

// PublicKey returns the Ed25519 public key.
func (k *NodeKey) PublicKey() ed25519.PublicKey {
	return k.priv.Public().(ed25519.PublicKey)
}

// PublicKeyHash returns sha256 of the public key (the frozen
// node_credentials.public_key_hash binding).
func (k *NodeKey) PublicKeyHash() [32]byte {
	return sha256.Sum256(k.PublicKey())
}

// CredentialVersion returns the agent credential version carried by the key.
func (k *NodeKey) CredentialVersion() uint32 { return k.version }

// PrivateKey returns the Ed25519 private key (used to build control
// envelopes; the NodeKey remains the only owner of the key material).
func (k *NodeKey) PrivateKey() ed25519.PrivateKey {
	return k.priv
}

// Sign signs msg with the node key.
func (k *NodeKey) Sign(msg []byte) ([]byte, error) {
	return framecryptoSign(k.priv, msg)
}
