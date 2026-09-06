// Shared terminal marker / reconcile latch (docs/state-model.md §3.4).
//
// The terminal marker and the reconcile desired-apply path share one
// exclusive latch: after the marker starts (DECOMMISSIONING is written) no
// concurrent desired apply may start a new actor. First engagement wins; the
// latch never reopens.
package localstate

import (
	"errors"
	"sync"
)

// ErrTerminalEngaged reports a refused actor start because the terminal
// marker has engaged and no new actor may start.
var ErrTerminalEngaged = errors.New("localstate: terminal marker engaged; no new actor may start")

// Latch is the exclusive terminal/reconcile latch.
type Latch struct {
	mu      sync.Mutex
	engaged bool
	actors  map[string]struct{}
}

// NewLatch returns an un-engaged latch.
func NewLatch() *Latch {
	return &Latch{actors: make(map[string]struct{})}
}

// TryEngage engages the latch once. The first caller wins and later calls
// return false; the latch never reopens.
func (l *Latch) TryEngage() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.engaged {
		return false
	}
	l.engaged = true
	return true
}

// Engaged reports whether the terminal marker has engaged.
func (l *Latch) Engaged() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.engaged
}

// RegisterActor tracks a started actor. After the latch is engaged no new
// actor may start.
func (l *Latch) RegisterActor(name string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.engaged {
		return ErrTerminalEngaged
	}
	l.actors[name] = struct{}{}
	return nil
}

// UnregisterActor untracks a stopped actor.
func (l *Latch) UnregisterActor(name string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.actors, name)
}

// ActiveCount returns the number of tracked (running) actors.
func (l *Latch) ActiveCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.actors)
}
