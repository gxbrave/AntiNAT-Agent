// Detection-profile cache (P12W Story 5): a state-dir JSON file mirroring
// the independent-file pattern of localstate/marker.go — atomic temp + fsync
// + rename + parent-directory fsync with mode 0600 — so a crash never leaves
// a torn profile and an interrupted write is never mistaken for a profile.
// The cache is deliberately NOT an agent bbolt migration (D3): the detection
// profile is capability evidence, not durability-critical Forward state.
package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/gxbrave/AntiNAT-Agent/internal/traversal"
)

// profileFile is the detection-profile cache filename. It mirrors marker.go's
// naming inside the Agent state directory.
const profileFile = "detection.profile"

// profileStore reads and writes the detection-profile cache under one mutex.
// Every Save is an atomic replace; a missing file means "no profile yet".
type profileStore struct {
	dir string
	mu  sync.Mutex
}

// newProfileStore returns a profile cache rooted at the Agent state dir.
func newProfileStore(dir string) *profileStore {
	return &profileStore{dir: dir}
}

// path is the cache file location.
func (p *profileStore) path() string { return filepath.Join(p.dir, profileFile) }

// Save durably replaces the cached detection profile.
func (p *profileStore) Save(profile traversal.Profile) error {
	if p == nil || p.dir == "" {
		return fmt.Errorf("agent: profile store has no state directory")
	}
	raw, err := json.Marshal(profile)
	if err != nil {
		return fmt.Errorf("agent: encode detection profile: %w", err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := os.MkdirAll(p.dir, 0o700); err != nil {
		return fmt.Errorf("agent: profile dir: %w", err)
	}
	temporary, err := os.CreateTemp(p.dir, ".antinat-profile-*")
	if err != nil {
		return fmt.Errorf("agent: create profile temp: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("agent: profile chmod: %w", err)
	}
	if _, err := temporary.Write(raw); err != nil {
		temporary.Close()
		return fmt.Errorf("agent: profile write: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("agent: profile fsync: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("agent: profile close: %w", err)
	}
	if err := os.Rename(temporaryPath, p.path()); err != nil {
		return fmt.Errorf("agent: profile rename: %w", err)
	}
	dir, err := os.Open(p.dir)
	if err != nil {
		return fmt.Errorf("agent: profile parent: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("agent: profile parent fsync: %w", err)
	}
	return nil
}

// Load returns the cached detection profile and whether one exists.
func (p *profileStore) Load() (traversal.Profile, bool, error) {
	if p == nil || p.dir == "" {
		return traversal.Profile{}, false, fmt.Errorf("agent: profile store has no state directory")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	raw, err := os.ReadFile(p.path())
	if err != nil {
		if errNotExist(err) {
			return traversal.Profile{}, false, nil
		}
		return traversal.Profile{}, false, fmt.Errorf("agent: read detection profile: %w", err)
	}
	var profile traversal.Profile
	if err := json.Unmarshal(raw, &profile); err != nil {
		return traversal.Profile{}, false, fmt.Errorf("agent: decode detection profile: %w", err)
	}
	return profile, true, nil
}

// errNotExist reports whether err is os.ErrNotExist (or wrapped).
func errNotExist(err error) bool { return os.IsNotExist(err) }
