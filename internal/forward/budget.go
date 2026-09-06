// Bounded per-Forward resource accounting (v0.8 §4.4, §4.5): connections,
// FDs, and the pessimistic per-connection buffer reservation are each
// bounded, and exhaustion returns an explicit reason. The pessimistic
// buffer is the worst case the standard library may fall back to for an
// eligible copy (2 x 32 KiB per direction); it is always reserved — never
// assumed to be pool-controlled.
package forward

import (
	"errors"
	"fmt"
	"sync"
)

// PessimisticBufferBytesPerConnection is the worst-case fallback buffer
// reservation per direction (32 KiB x 2), frozen by the v0.8 §4.4 evidence
// shape.
const PessimisticBufferBytesPerConnection = 2 * 32 * 1024

// LimitKind names the budget axis that was exhausted.
type LimitKind string

const (
	LimitConnections       LimitKind = "connections"
	LimitFDs               LimitKind = "fds"
	LimitPessimisticBuffer LimitKind = "pessimistic_buffer_bytes"
)

// ErrBudgetExceeded is the sentinel for any budget exhaustion.
var ErrBudgetExceeded = errors.New("forward: budget limit exceeded")

// BudgetExceededError is the explicit exhaustion reason: which axis, the
// configured limit, and the current usage.
type BudgetExceededError struct {
	Kind    LimitKind
	Limit   int64
	Current int64
}

func (e *BudgetExceededError) Error() string {
	return fmt.Sprintf("forward: %s budget limit exceeded (limit %d, current %d)", e.Kind, e.Limit, e.Current)
}

// Is matches the ErrBudgetExceeded sentinel.
func (e *BudgetExceededError) Is(target error) bool {
	return target == ErrBudgetExceeded
}

// Limits configures the per-Forward budget. A zero limit means unlimited on
// that axis; negative limits are rejected.
type Limits struct {
	MaxConnections            int
	MaxFDs                    int
	MaxPessimisticBufferBytes int64
}

// BudgetSnapshot is a point-in-time usage view.
type BudgetSnapshot struct {
	Connections            int
	FDs                    int
	PessimisticBufferBytes int64
}

// Budget is the bounded accounting state for one Forward. Reserve is
// called once per accepted session; Release exactly once per successful
// Reserve.
type Budget struct {
	mu sync.Mutex

	limits      Limits
	connections int
	fds         int
	bufferBytes int64
}

// NewBudget validates and returns a budget. Negative limits are rejected
// because they would make exhaustion impossible to reason about.
func NewBudget(limits Limits) (*Budget, error) {
	if limits.MaxConnections < 0 || limits.MaxFDs < 0 || limits.MaxPessimisticBufferBytes < 0 {
		return nil, errors.New("forward: negative budget limit")
	}
	return &Budget{limits: limits}, nil
}

// Reserve charges one connection, one FD, and the pessimistic buffer
// reservation, or returns the explicit *BudgetExceededError for the first
// axis that is exhausted (no partial charge on failure). The FD-axis unit
// is one accepted client socket per session: each session additionally
// holds the backend target socket outside this unit, so MaxFDs=N bounds
// accepted sessions with up to ~2N OS descriptors in play.
func (b *Budget) Reserve() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.limits.MaxConnections > 0 && b.connections >= b.limits.MaxConnections {
		return &BudgetExceededError{
			Kind:    LimitConnections,
			Limit:   int64(b.limits.MaxConnections),
			Current: int64(b.connections),
		}
	}
	if b.limits.MaxFDs > 0 && b.fds >= b.limits.MaxFDs {
		return &BudgetExceededError{
			Kind:    LimitFDs,
			Limit:   int64(b.limits.MaxFDs),
			Current: int64(b.fds),
		}
	}
	if b.limits.MaxPessimisticBufferBytes > 0 &&
		b.bufferBytes+PessimisticBufferBytesPerConnection > b.limits.MaxPessimisticBufferBytes {
		return &BudgetExceededError{
			Kind:    LimitPessimisticBuffer,
			Limit:   b.limits.MaxPessimisticBufferBytes,
			Current: b.bufferBytes,
		}
	}

	b.connections++
	b.fds++
	b.bufferBytes += PessimisticBufferBytesPerConnection
	return nil
}

// Release frees one session's charges. Callers must pair it with a
// successful Reserve.
func (b *Budget) Release() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.connections > 0 {
		b.connections--
	}
	if b.fds > 0 {
		b.fds--
	}
	b.bufferBytes -= PessimisticBufferBytesPerConnection
	if b.bufferBytes < 0 {
		b.bufferBytes = 0
	}
}

// Snapshot returns the current usage.
func (b *Budget) Snapshot() BudgetSnapshot {
	b.mu.Lock()
	defer b.mu.Unlock()
	return BudgetSnapshot{
		Connections:            b.connections,
		FDs:                    b.fds,
		PessimisticBufferBytes: b.bufferBytes,
	}
}
