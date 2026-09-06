// Terminal decommission marker (docs/state-model.md §3.4, v0.8 §9.2).
package localstate

import (
	"fmt"
	"os"
	"path/filepath"
)

const markerFile = "terminal.marker"

type MarkerState string

const (
	MarkerActive          MarkerState = ""
	MarkerDecommissioning MarkerState = "DECOMMISSIONING"
	MarkerDecommissioned  MarkerState = "DECOMMISSIONED"
)

func (m MarkerState) String() string {
	if m == "" {
		return "ACTIVE"
	}
	return string(m)
}

var validMarkerStates = map[MarkerState]bool{
	MarkerDecommissioning: true,
	MarkerDecommissioned:  true,
}

func loadMarkerUnlocked(dir string) (MarkerState, error) {
	raw, err := os.ReadFile(filepath.Join(dir, markerFile))
	if err != nil {
		if errNotExist(err) {
			return MarkerActive, nil
		}
		return "", fmt.Errorf("localstate: read terminal marker: %w", err)
	}
	state := MarkerState(string(raw))
	if !validMarkerStates[state] {
		return "", fmt.Errorf("localstate: invalid terminal marker %q", string(raw))
	}
	return state, nil
}

// LoadMarker reads the terminal marker under the shared lifecycle lock.
func LoadMarker(dir string) (MarkerState, error) {
	var state MarkerState
	err := withLifecycleLock(dir, func() error {
		var err error
		state, err = loadMarkerUnlocked(dir)
		return err
	})
	return state, err
}

func writeMarkerUnlocked(dir string, state MarkerState) error {
	if !validMarkerStates[state] {
		return fmt.Errorf("localstate: refusing to write invalid terminal marker %q", string(state))
	}
	path := filepath.Join(dir, markerFile)
	current, err := loadMarkerUnlocked(dir)
	if err != nil {
		return err
	}
	if current == MarkerDecommissioned && state != MarkerDecommissioned {
		return fmt.Errorf("localstate: terminal marker is already DECOMMISSIONED; refusing %s", state)
	}
	if current == state {
		return nil
	}
	temporary, err := os.CreateTemp(dir, ".antinat-marker-*")
	if err != nil {
		return fmt.Errorf("localstate: create marker temp: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("localstate: marker chmod: %w", err)
	}
	if _, err := temporary.WriteString(string(state)); err != nil {
		temporary.Close()
		return fmt.Errorf("localstate: marker write: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("localstate: marker fsync: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("localstate: marker close: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("localstate: marker rename: %w", err)
	}
	if err := syncDirectory(dir); err != nil {
		return fmt.Errorf("localstate: marker parent fsync: %w", err)
	}
	return nil
}

// WriteMarker atomically advances the marker under the shared process/file lock.
func WriteMarker(dir string, state MarkerState) error {
	return withLifecycleLock(dir, func() error {
		return writeMarkerUnlocked(dir, state)
	})
}
