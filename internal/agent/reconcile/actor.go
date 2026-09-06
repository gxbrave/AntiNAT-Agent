// Bounded actor lifecycle and panic-isolating supervisor (P07 Story 6).
//
// Each Forward runs as an Actor with a bounded Start/Run/Stop lifecycle. The
// Supervisor runs every actor in its own goroutine with panic recovery, so
// one actor's panic or failure can never stop a sibling or the reconcile
// control loop, and reports a per-actor result on a bounded Results channel.
package reconcile

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Actor is the bounded per-Forward lifecycle interface. Start must become
// ready (or fail) within the supervisor's start timeout; Run is the actor's
// main loop; Stop is the graceful shutdown hook.
type Actor interface {
	Name() string
	Start(ctx context.Context) error
	Run(ctx context.Context) error
	Stop(ctx context.Context) error
}

// ActorOutcome is the supervisor's reported per-actor result kind.
type ActorOutcome int

const (
	ActorCompleted ActorOutcome = iota
	ActorFailed
	ActorPanicked
	ActorStartFailed
	ActorStopFailed
)

func (o ActorOutcome) String() string {
	switch o {
	case ActorCompleted:
		return "COMPLETED"
	case ActorFailed:
		return "FAILED"
	case ActorPanicked:
		return "PANICKED"
	case ActorStartFailed:
		return "START_FAILED"
	case ActorStopFailed:
		return "STOP_FAILED"
	}
	return "UNKNOWN"
}

// ErrActorPanicked wraps a recovered panic value.
var ErrActorPanicked = errors.New("reconcile: actor panicked")

// ErrSupervisorFull reports a start refused by a lifecycle bound.
var ErrSupervisorFull = errors.New("reconcile: supervisor lifecycle bound reached")

// ActorResult is one supervisor result report.
type ActorResult struct {
	Actor   string
	Outcome ActorOutcome
	Err     error
}

// Supervisor runs Actors with panic isolation and bounded concurrency.
type Supervisor struct {
	maxConcurrent int
	startTimeout  time.Duration
	stopTimeout   time.Duration
	baseCtx       context.Context
	cancel        context.CancelFunc

	mu      sync.Mutex
	active  map[string]struct{}
	results chan ActorResult
	wg      sync.WaitGroup
}

// SupervisorOption configures a Supervisor.
type SupervisorOption func(*Supervisor)

// WithMaxConcurrentActors bounds how many actors may run at once (default 16).
func WithMaxConcurrentActors(n int) SupervisorOption {
	return func(s *Supervisor) { s.maxConcurrent = n }
}

// WithStartTimeout bounds how long Start may take to become ready (default
// 10s).
func WithStartTimeout(d time.Duration) SupervisorOption {
	return func(s *Supervisor) { s.startTimeout = d }
}

// WithStopTimeout bounds how long Stop may take (default 5s).
func WithStopTimeout(d time.Duration) SupervisorOption {
	return func(s *Supervisor) { s.stopTimeout = d }
}

// NewSupervisor returns a Supervisor whose Results channel buffers every
// actor that may run concurrently.
func NewSupervisor(opts ...SupervisorOption) *Supervisor {
	base, cancel := context.WithCancel(context.Background())
	s := &Supervisor{
		maxConcurrent: 16,
		startTimeout:  10 * time.Second,
		stopTimeout:   5 * time.Second,
		baseCtx:       base,
		cancel:        cancel,
		active:        make(map[string]struct{}),
	}
	for _, opt := range opts {
		opt(s)
	}
	s.results = make(chan ActorResult, s.maxConcurrent+8)
	return s
}

// Start begins an actor lifecycle: Start is called synchronously with the
// start timeout, then Run runs in its own goroutine under panic recovery. A
// start failure is reported as ActorStartFailed and returned.
func (s *Supervisor) Start(ctx context.Context, a Actor) error {
	s.mu.Lock()
	if len(s.active) >= s.maxConcurrent {
		s.mu.Unlock()
		return fmt.Errorf("%w: max %d actors", ErrSupervisorFull, s.maxConcurrent)
	}
	if _, running := s.active[a.Name()]; running {
		s.mu.Unlock()
		return fmt.Errorf("%w: actor %q already running", ErrSupervisorFull, a.Name())
	}
	s.active[a.Name()] = struct{}{}
	s.mu.Unlock()

	startCtx, cancel := context.WithTimeout(s.baseCtx, s.startTimeout)
	err := a.Start(startCtx)
	cancel()
	if err != nil {
		s.finish(a.Name(), ActorStartFailed, fmt.Errorf("reconcile: actor %q start: %w", a.Name(), err))
		return err
	}
	// wg.Add happens only on the launch path: runActor owns the matching
	// wg.Done, so a failed start (including the bounded start-timeout path)
	// must never increment the WaitGroup — otherwise StopAll()/Wait() would
	// block forever waiting for a Done() that can never run.
	s.wg.Add(1)
	go s.runActor(a)
	return nil
}

// runActor executes one actor's Run with panic recovery, then runs Stop, and
// reports the single lifecycle result. Run runs on the supervisor base
// context so StopAll can cancel every actor.
func (s *Supervisor) runActor(a Actor) {
	defer s.wg.Done()
	var runErr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				runErr = fmt.Errorf("%w: %v", ErrActorPanicked, r)
			}
		}()
		runErr = a.Run(s.baseCtx)
	}()
	switch {
	case runErr != nil && errors.Is(runErr, ErrActorPanicked):
		s.finish(a.Name(), ActorPanicked, runErr)
	case runErr != nil:
		s.finish(a.Name(), ActorFailed, runErr)
	default:
		stopCtx, cancel := context.WithTimeout(s.baseCtx, s.stopTimeout)
		stopErr := a.Stop(stopCtx)
		cancel()
		if stopErr != nil {
			s.finish(a.Name(), ActorStopFailed, fmt.Errorf("reconcile: actor %q stop: %w", a.Name(), stopErr))
			return
		}
		s.finish(a.Name(), ActorCompleted, nil)
	}
}

// finish records one actor result. Reporting is best-effort: a full bounded
// Results channel (the caller is not draining) drops the report instead of
// blocking, so a completing actor (and its deferred wg.Done) is never pinned
// and Wait/StopAll cannot deadlock on an undrained channel.
func (s *Supervisor) finish(name string, outcome ActorOutcome, err error) {
	s.mu.Lock()
	delete(s.active, name)
	s.mu.Unlock()
	select {
	case s.results <- ActorResult{Actor: name, Outcome: outcome, Err: err}:
	default:
	}
}

// Results returns the per-actor result channel.
func (s *Supervisor) Results() <-chan ActorResult { return s.results }

// Wait blocks until every started actor has finished. A caller that never
// drains Results cannot deadlock shutdown: finish() drops the report when
// the bounded channel is full rather than blocking, so Wait always returns;
// drain Results for full per-actor reporting.
func (s *Supervisor) Wait() { s.wg.Wait() }

// StopAll cancels the supervisor base context so every running actor's Run
// sees ctx.Done(), then waits for all actors to finish their Stop hooks.
func (s *Supervisor) StopAll(ctx context.Context) error {
	s.cancel()
	s.Wait()
	return ctx.Err()
}
