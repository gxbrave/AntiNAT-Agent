// Per-Forward TCP traversal manager (Story 7): composes one Forward's
// acquisition — plan resolution, listener ownership, gateway mapping,
// optional same-tuple STUN observation — into structured evidence and a
// pipeline verdict, then keeps the mapping alive under the §3.5 renewal
// contract: renew near 50% of the GRANTED lease with jitter; three
// consecutive failures degrade the mapping (keepalive_state DEGRADED) while
// renewals continue; the mapping is LOST only when the expiry safety margin
// is crossed, a gateway reboot is confirmed, or a renewal rewrites the
// external endpoint — then the publication goes stale (state-model §5) and
// the manager never revives the old candidate. Lifecycle callbacks are
// delivered off the renewal goroutine so a consumer that releases the
// acquisition from a callback cannot deadlock it. Release follows the
// mapping's ownership strength, is idempotent, and keeps the journal record
// whenever the gateway delete failed: the record is the only durable
// evidence of a mapping that may still be live.
package traversal

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
)

// ReleaseFunc releases one acquired listener.
type ReleaseFunc func() error

type listenerAcquireResult struct {
	listener  net.Listener
	actual    TupleKey
	releaseFn ReleaseFunc
}

func listenerAcquireContained(ctx context.Context, source ListenerSource, owner string, key TupleKey) (listenerAcquireResult, error) {
	return externalCallContained("listener acquire", func() (listenerAcquireResult, error) {
		listener, actual, releaseFn, err := source.Acquire(ctx, owner, key)
		return listenerAcquireResult{listener: listener, actual: actual, releaseFn: releaseFn}, err
	})
}

// ListenerSource acquires the production listener for one tuple. The
// composition root chooses the implementation: the plain PortRegistry for
// forwards without a same-tuple STUN observation, the stun shared-port
// registry when the upstream observation needs the same tuple (Linux gate).
// Implementations must be bounded-latency and honor their context: a call
// that blocks forever wedges the acquisition (injected-implementation
// contract; faults are converted to errors, hangs cannot be interrupted).
type ListenerSource interface {
	Acquire(ctx context.Context, owner string, key TupleKey) (net.Listener, TupleKey, ReleaseFunc, error)
}

// SameTupleDialer is the optional ListenerSource capability of originating
// an extra connection from a tuple the source acquired (shared-port reuse,
// v0.8 §4.2). The manager offers it to the STUN observation seam; a source
// without the capability passes no dial, and an honest observer must refuse
// to observe rather than classify a foreign socket's NAT binding.
type SameTupleDialer interface {
	DialFrom(ctx context.Context, bind TupleKey, remote string) (net.Conn, error)
}

// StunObserveRequest is one manager STUN observation.
type StunObserveRequest struct {
	// Server is the parsed stun+tcp:// endpoint.
	Server netip.AddrPort
	// Bind is the forward's own bound tuple: the observation MUST originate
	// from it.
	Bind TupleKey
	// Dial originates a TCP connection from Bind. Nil when the listener
	// source cannot rebind the tuple; then the observation must be refused.
	// The observer owns the returned conn and closes it.
	Dial func(ctx context.Context, remote string) (net.Conn, error)
	// Timeout bounds the Binding exchange.
	Timeout time.Duration
}

// StunObserveFunc performs one same-tuple STUN observation for the manager.
type StunObserveFunc func(ctx context.Context, req StunObserveRequest) (netip.AddrPort, error)

// PortRegistrySource adapts the agent-global PortRegistry.
type PortRegistrySource struct {
	Registry *PortRegistry
}

// Acquire implements ListenerSource.
func (s PortRegistrySource) Acquire(ctx context.Context, owner string, key TupleKey) (net.Listener, TupleKey, ReleaseFunc, error) {
	lease, err := s.Registry.Acquire(ctx, owner, key)
	if err != nil {
		return nil, TupleKey{}, nil, err
	}
	return lease.Listener, lease.Actual, lease.Release, nil
}

// ManagerOptions configure the manager.
type ManagerOptions struct {
	RouteTable RouteTable
	// Listeners acquires the production listener; nil uses the plain
	// PortRegistry.
	Listeners ListenerSource
	// Mappers are the available gateway mechanisms.
	Mappers map[MappingLayerKind]GatewayMapper
	// Journal persists mapping records; nil disables journaling (labs).
	Journal JournalStore
	// Clock is the renewal clock; default time.Now. Must not panic: the
	// clock has no error channel, so a panicking read degrades to the zero
	// time inside the containment boundary (a nonsense lease deadline).
	Clock func() time.Time
	// OnMappingDegraded fires once when three consecutive renewals failed
	// (keepalive_state DEGRADED): the mapping may still recover, and
	// renewals continue.
	//
	// All three callbacks run off the renewal goroutine in publication
	// order, are contained per event (a panicking callback cannot affect
	// the loop or later events), and may still be in flight when Release
	// returns — consumers must tolerate a trailing notification.
	OnMappingDegraded func(forwardID string, reason string)
	// OnMappingLost fires when the mapping is LOST: the lease expiry safety
	// margin was crossed, a gateway reboot was confirmed, or a renewal
	// rewrote the external endpoint. Publication state must go stale; the
	// manager never revives the old candidate.
	OnMappingLost func(forwardID string, reason string)
	// OnMappingRecovered fires when a successful renewal follows a DEGRADED
	// episode (keepalive_state HEALTHY again).
	OnMappingRecovered func(forwardID string)
	// DefaultLease is the requested lease when the request omits one;
	// default 1h (§3.5 provisional freeze).
	DefaultLease time.Duration
	// StunObserve performs the forward's upstream STUN observation from its
	// own tuple (injected; the stun package depends on traversal). Nil
	// disables the upstream STUN layer.
	StunObserve StunObserveFunc
}

// Manager composes per-Forward TCP traversal acquisitions.
type Manager struct {
	opts      ManagerOptions
	listeners ListenerSource
}

// AcquireRequest parameterizes one acquisition.
type AcquireRequest struct {
	ForwardID string
	Owner     string
	Spec      protocol.ForwardSpec
	// Plan is the resolved strategy plan (detection profile or operator
	// selection resolved the mapping layer).
	Plan PlanRequest
	// Lease is the requested mapping lease; 0 uses the default. The
	// gateway's granted lifetime is authoritative for pacing and expiry.
	Lease time.Duration
	// RenewalInterval / RenewalJitterMax pace the renewal loop (the
	// production loop paces at ~50% of the granted lease; tests inject
	// faster pacing).
	RenewalInterval  time.Duration
	RenewalJitterMax time.Duration
	// StunServer is the stun+tcp:// endpoint for the optional same-tuple
	// upstream observation; empty disables the STUN layer.
	StunServer string
}

// Acquisition is one live Forward traversal binding.
type Acquisition struct {
	ForwardID string
	// Listener is the production listener; the caller wires the forward
	// data plane to it. Release closes it.
	Listener net.Listener
	Bind     TupleKey
	// Verdict classifies the composed layer chain.
	Verdict PipelineVerdict
	// Layers is the structured evidence in composition order.
	Layers []LayerEvidence
	// Mapping is the live gateway mapping; nil for direct/manual. The
	// renewal goroutine rewrites it in place under renewMu: direct readers
	// race with it, so treat the field as a wiring handle and use
	// CurrentMapping for a locked snapshot.
	Mapping *GatewayMapping
	// JournalID references the journal record (mapping_journal_ref); empty
	// when the record was never durably written.
	JournalID string
	// journalAttemptID is the stable private identity used to reconcile and
	// clean up an ambiguous Put outcome (the store may commit then panic).
	// JournalID remains empty until durability is confirmed by Put or Get.
	journalAttemptID string
	// journalCreatedAt is the stable audit timestamp reused by renewal writes;
	// caching it avoids an external Journal.Get under renewMu on every renewal.
	journalCreatedAt int64
	// StunObserveError records a configured upstream observation that could
	// not be honored (no observer wired, no same-tuple dialer, transport
	// failure). A failed observation is never silently dropped; the gateway
	// evidence stands alone.
	StunObserveError error
	// journalError records a failed journal write. The JournalID reference
	// stays honest (never set for a record that was not durably written),
	// but the durable-state loss is surfaced through CurrentJournalError.
	// The renewal goroutine rewrites it under renewMu.
	journalError error

	manager   *Manager
	mapper    GatewayMapper
	releaseFn ReleaseFunc

	releaseOnce sync.Once
	releaseErr  error

	renewMu       sync.Mutex
	renewStop     chan struct{}
	renewDone     chan struct{}
	renewCancel   context.CancelFunc
	renewCtx      context.Context
	events        *lifecycleQueue
	renewOnceOnce sync.Once
	failedRenew   int
	degraded      bool
	degradedFired bool
	lostFired     bool
	// leaseDuration is the last granted lifetime; leaseDeadline is its
	// absolute expiry on the manager clock. The expiry safety margin is
	// leaseDuration/10 (§3.5's ±10% family).
	leaseDuration time.Duration
	leaseDeadline time.Time
}

// NewManager builds a manager. A nil route table is a constructor error:
// every strategy resolves its source from it.
func NewManager(opts ManagerOptions) *Manager {
	if opts.RouteTable == nil {
		panic("traversal: manager requires a route table")
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	if opts.DefaultLease <= 0 {
		opts.DefaultLease = time.Hour
	}
	listeners := opts.Listeners
	if listeners == nil {
		listeners = PortRegistrySource{Registry: NewPortRegistry()}
	}
	return &Manager{opts: opts, listeners: listeners}
}

// Acquire composes one Forward's traversal binding. The pipeline rules of
// EvaluateLayers gate the outcome: a strict final constraint violated by
// the observed layer fails the acquisition, and a FIRST_HOP candidate is
// returned with PublicCandidate=false so no publication can claim
// verification without the independent probe.
func (m *Manager) Acquire(ctx context.Context, req AcquireRequest) (*Acquisition, error) {
	if req.ForwardID == "" || req.Owner == "" {
		return nil, fmt.Errorf("traversal: acquisition requires forward and owner identities")
	}
	lease := req.Lease
	if lease <= 0 {
		lease = m.opts.DefaultLease
	}
	plan, err := PlanStrategy(req.Plan)
	if err != nil {
		return nil, err
	}

	acquisition := &Acquisition{
		ForwardID: req.ForwardID,
		manager:   m,
	}
	switch plan.Strategy {
	case protocol.StrategyDirectV4:
		if err := m.acquireDirect(ctx, req, acquisition); err != nil {
			return nil, err
		}
	case protocol.StrategyManualStaticV4:
		if err := m.acquireManual(ctx, req, plan, acquisition); err != nil {
			return nil, err
		}
	case protocol.StrategyExplicitGateway:
		if err := m.acquireGateway(ctx, req, plan, lease, acquisition); err != nil {
			m.releaseListenerQuietly(acquisition)
			return nil, err
		}
	default:
		return nil, fmt.Errorf("traversal: manager does not acquire strategy %q (stun-only and auto resolve before acquisition)", plan.Strategy)
	}
	return acquisition, nil
}

// acquireDirect binds the global source; the candidate is the source plus
// the actual port.
func (m *Manager) acquireDirect(ctx context.Context, req AcquireRequest, acquisition *Acquisition) error {
	selection, capability, err := Assess(m.opts.RouteTable)
	if err != nil {
		if capability == "" {
			return fmt.Errorf("traversal: route assessment: %w", err)
		}
		return NewCapabilityError(capability, err)
	}
	if !selection.Global {
		return NewCapabilityError(CapabilityNoGlobalV4Source,
			fmt.Errorf("selected interface %s has no global IPv4 source", selection.Interface))
	}
	listenerResult, err := listenerAcquireContained(ctx, m.listeners, req.Owner, TupleKey{
		Family: "ipv4", Protocol: "tcp", Address: selection.Source.String(), Port: req.Spec.RequestedLocalPort,
	})
	if err != nil {
		return fmt.Errorf("traversal: direct listener: %w", err)
	}
	acquisition.Listener = listenerResult.listener
	acquisition.Bind = listenerResult.actual
	acquisition.releaseFn = listenerResult.releaseFn
	candidate := netip.AddrPortFrom(selection.Source, listenerResult.actual.Port)
	acquisition.Layers = []LayerEvidence{{
		Kind:             LayerKindDirect,
		InternalEndpoint: candidate.String(),
		AssignedEndpoint: candidate.String(),
		Scope:            ScopeGlobalPublic,
		Ownership:        OwnershipNotApplicable,
		ParentLayer:      -1,
	}}
	verdict, err := EvaluateLayers(acquisition.Layers, PortPolicyAcceptAssigned)
	if err != nil {
		m.releaseListenerQuietly(acquisition)
		return err
	}
	acquisition.Verdict = verdict
	return nil
}

// acquireManual binds the listener and carries the operator endpoint as the
// candidate (probe-eligible only when the endpoint is global-class). The
// planned endpoint is the single source of truth; a disagreeing spec value
// is refused.
func (m *Manager) acquireManual(ctx context.Context, req AcquireRequest, plan StrategyPlan, acquisition *Acquisition) error {
	endpoint := plan.ManualExpectedEndpoint
	if endpoint == "" {
		return ErrOperatorEndpointRequired
	}
	if specEndpoint := req.Spec.ManualExpectedEndpoint; specEndpoint != "" && specEndpoint != endpoint {
		return fmt.Errorf("traversal: manual endpoint %q disagrees with the planned endpoint %q", specEndpoint, endpoint)
	}
	parsed, err := ParseManualEndpoint(endpoint)
	if err != nil {
		return fmt.Errorf("traversal: manual endpoint: %w", err)
	}
	listenerResult, err := listenerAcquireContained(ctx, m.listeners, req.Owner, TupleKey{
		Family: "ipv4", Protocol: "tcp", Address: "0.0.0.0", Port: req.Spec.RequestedLocalPort,
	})
	if err != nil {
		return fmt.Errorf("traversal: manual listener: %w", err)
	}
	acquisition.Listener = listenerResult.listener
	acquisition.Bind = listenerResult.actual
	acquisition.releaseFn = listenerResult.releaseFn
	acquisition.Layers = []LayerEvidence{{
		Kind:             LayerKindManual,
		InternalEndpoint: netip.AddrPortFrom(netip.AddrFrom4([4]byte{}), listenerResult.actual.Port).String(),
		AssignedEndpoint: parsed.String(),
		Scope:            ScopeOperatorInput,
		Ownership:        OwnershipNotApplicable,
		ParentLayer:      -1,
	}}
	verdict, err := EvaluateLayers(acquisition.Layers, plan.FinalEndpointConstraint)
	if err != nil {
		m.releaseListenerQuietly(acquisition)
		return err
	}
	acquisition.Verdict = verdict
	return nil
}

// acquireGateway discovers the mechanism, binds the listener on the
// default-route interface's own address, maps the tuple, optionally
// observes the same tuple via STUN, and starts renewal.
func (m *Manager) acquireGateway(ctx context.Context, req AcquireRequest, plan StrategyPlan, lease time.Duration, acquisition *Acquisition) error {
	mapper, ok := m.opts.Mappers[plan.MappingLayer]
	if !ok {
		return fmt.Errorf("traversal: no %s mapper is available on this node", plan.MappingLayer)
	}
	// Operator data errors fail before any side effect: an unparseable
	// stun+tcp:// endpoint must not silently downgrade the composition to
	// gateway-only evidence.
	if req.StunServer != "" {
		if _, err := parseStunTCPServer(req.StunServer); err != nil {
			return err
		}
	}
	if plan.GatewayPortPolicy == PortPolicyStrict && req.Spec.RequestedPublicPort == 0 {
		return errors.New("traversal: strict gateway port policy requires a requested public port")
	}
	source, err := m.sourceAddress()
	if err != nil {
		return err
	}
	control, err := externalCallContained("mapper discover", func() (ControlServer, error) {
		return mapper.Discover(ctx)
	})
	if err != nil {
		return fmt.Errorf("traversal: %s discovery: %w", plan.MappingLayer, err)
	}
	listenerResult, err := listenerAcquireContained(ctx, m.listeners, req.Owner, TupleKey{
		Family: "ipv4", Protocol: "tcp", Address: source.String(), Port: req.Spec.RequestedLocalPort,
	})
	if err != nil {
		return fmt.Errorf("traversal: gateway listener: %w", err)
	}
	acquisition.Listener = listenerResult.listener
	acquisition.Bind = listenerResult.actual
	acquisition.releaseFn = listenerResult.releaseFn
	acquisition.mapper = mapper

	mapping, err := externalCallContained("mapper map", func() (GatewayMapping, error) {
		return mapper.Map(ctx, GatewayMapRequest{
			InternalIP:            source,
			InternalPort:          listenerResult.actual.Port,
			RequestedExternalPort: req.Spec.RequestedPublicPort,
			Lease:                 lease,
			StrictPort:            plan.GatewayPortPolicy == PortPolicyStrict,
		})
	})
	if err != nil {
		// The listener is already bound; the outer Acquire releases it on this
		// error. A panicking Map cannot leak it past this boundary.
		return fmt.Errorf("traversal: %s map: %w", plan.MappingLayer, err)
	}
	acquisition.Mapping = &mapping
	// The granted lifetime is authoritative (§3.5): pacing and the expiry
	// safety margin derive from it, never from the request.
	if mapping.Lease > 0 {
		acquisition.leaseDuration = mapping.Lease
		acquisition.leaseDeadline = m.clockNow().Add(mapping.Lease)
	}
	gatewayEvidence := mapping.Evidence(control)
	acquisition.Layers = []LayerEvidence{gatewayEvidence}

	// Upstream STUN layer on the forward's own tuple (v0.8 §3.1 step 6,
	// §4.2): the injected observer MUST source the exchange from the bound
	// listener tuple through the same-tuple dialer — an observation from any
	// other local socket classifies a different NAT binding and never
	// enters this pipeline. A configured observation that cannot be honored
	// is recorded on the acquisition, never silently dropped.
	if req.StunServer != "" {
		server, _ := parseStunTCPServer(req.StunServer) // parse checked above
		switch {
		case m.opts.StunObserve == nil:
			acquisition.StunObserveError = errors.New("upstream STUN observation requested but no observer is wired in this build")
		default:
			var dial func(ctx context.Context, remote string) (net.Conn, error)
			if sameTuple, ok := m.listeners.(SameTupleDialer); ok {
				bind := listenerResult.actual
				dial = func(ctx context.Context, remote string) (net.Conn, error) {
					return sameTuple.DialFrom(ctx, bind, remote)
				}
			}
			observed, observeErr := externalCallContained("stun observe", func() (netip.AddrPort, error) {
				return m.opts.StunObserve(ctx, StunObserveRequest{
					Server:  server,
					Bind:    listenerResult.actual,
					Dial:    dial,
					Timeout: 5 * time.Second,
				})
			})
			if observeErr != nil {
				acquisition.StunObserveError = fmt.Errorf("upstream STUN observation %s: %w", req.StunServer, observeErr)
			} else {
				acquisition.Layers = append(acquisition.Layers, LayerEvidence{
					Kind:             LayerKindSTUN,
					ControlServer:    req.StunServer,
					InternalEndpoint: netip.AddrPortFrom(source, listenerResult.actual.Port).String(),
					AssignedEndpoint: observed.String(),
					Scope:            scopeForAddr(observed.Addr()),
					Ownership:        OwnershipObservedOnly,
					ParentLayer:      0,
				})
			}
		}
	}

	verdict, err := EvaluateLayers(acquisition.Layers, plan.FinalEndpointConstraint)
	if err != nil {
		// Release the mapping before failing: ownership strength applies
		// on the failure path too. The compensating delete must survive a
		// cancelled caller context — a live gateway mapping with no
		// durable journal record is the worst outcome (lifecycle review).
		if deleteErr := deleteMappingContained(context.WithoutCancel(ctx), mapper, mapping); deleteErr != nil {
			return errors.Join(err, deleteErr)
		}
		return err
	}
	acquisition.Verdict = verdict
	acquisition.JournalID, acquisition.journalAttemptID, acquisition.journalCreatedAt, acquisition.journalError = m.journalPut(
		req.ForwardID, acquisition.JournalID, acquisition.journalAttemptID, acquisition.journalCreatedAt, mapping,
	)
	m.startRenewal(req.ForwardID, acquisition, lease, req.RenewalInterval, req.RenewalJitterMax)
	return nil
}

// Release stops the renewal loop, deletes the mapping per its ownership
// strength and releases the listener. It is idempotent: later calls return
// the first outcome. A failed gateway delete keeps the journal record — it
// is the only durable evidence of a mapping that may still be live, and
// recovery/cleanup consumes it (state-model §2). Best-effort failures
// surface as a joined error: the caller decides whether a gateway mapping
// leak is acceptable (weak/best-effort mechanisms) or fatal.
func (a *Acquisition) Release(ctx context.Context) error {
	a.releaseOnce.Do(func() { a.releaseErr = a.release(ctx) })
	return a.releaseErr
}

func (a *Acquisition) release(ctx context.Context) error {
	a.stopRenewal()
	var errs []error
	mappingDeleted := true
	if a.Mapping != nil && a.mapper != nil {
		if err := deleteMappingContained(ctx, a.mapper, *a.Mapping); err != nil {
			errs = append(errs, err)
			mappingDeleted = false
		}
	}
	journalCleanupID := a.JournalID
	if journalCleanupID == "" {
		journalCleanupID = a.journalAttemptID
	}
	if mappingDeleted && a.manager != nil && journalCleanupID != "" && a.manager.opts.Journal != nil {
		if err := cleanupContained("journal delete", func() error {
			return a.manager.opts.Journal.Delete(journalCleanupID)
		}); err != nil {
			errs = append(errs, err)
		}
	}
	if a.releaseFn != nil {
		if err := cleanupContained("listener release", a.releaseFn); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// deleteMappingContained turns an adapter panic into an ordinary failed-delete
// outcome. Release must still close the listener and retain the journal record;
// letting the panic unwind through sync.Once would consume the once while
// skipping both cleanup steps and make every later Release a false success.
func deleteMappingContained(ctx context.Context, mapper GatewayMapper, mapping GatewayMapping) error {
	return cleanupContained("mapping delete", func() error { return mapper.Delete(ctx, mapping) })
}

// cleanupContained is the single panic boundary for manager-owned external
// cleanup callbacks. A faulty adapter or store must become an ordinary cleanup
// error so the Manager can continue the remaining teardown steps and preserve
// Release's stable sync.Once outcome.
func cleanupContained(operation string, cleanup func() error) error {
	_, err := externalCallContained(operation, func() (struct{}, error) {
		return struct{}{}, cleanup()
	})
	return err
}

// externalCallContained is the package-wide panic boundary for injected
// implementations. It converts a callback panic to the same error channel as
// an ordinary failure so callers can run their normal compensation/state
// transition logic; callers add their own context around the returned error.
// Implementations must still honor their context and return: an interface
// call that blocks forever cannot be forcibly interrupted, so injected
// implementations must be bounded-latency (documented on the interfaces).
func externalCallContained[T any](operation string, call func() (T, error)) (value T, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("%s panicked: %v", operation, recovered)
		}
	}()
	return call()
}

// ---------------------------------------------------------------------------
// Renewal loop (§3.5)
// ---------------------------------------------------------------------------

// Lifecycle event kinds delivered to the option callbacks.
const (
	eventDegraded = iota
	eventLost
	eventRecovered
)

// lifecycleEvent is one renewal-loop state transition. Events keep their
// publication order through the dispatcher.
type lifecycleEvent struct {
	kind   int
	reason string
}

// lifecycleQueue is an unbounded, ordered event queue between the renewal
// goroutine and the lifecycle dispatcher. Delivery NEVER blocks: a consumer
// callback runs on the dispatcher goroutine and may call Release, whose
// stopRenewal joins the renewal goroutine — a bounded send under renewMu
// could deadlock that join against the blocked callback (lab-review
// finding). The event rate is bounded by state transitions, so unbounded
// memory is not a practical risk.
type lifecycleQueue struct {
	mu     sync.Mutex
	cond   *sync.Cond
	events []lifecycleEvent
	closed bool
}

func newLifecycleQueue() *lifecycleQueue {
	q := &lifecycleQueue{}
	q.cond = sync.NewCond(&q.mu)
	return q
}

// push enqueues one event without ever blocking.
func (q *lifecycleQueue) push(event lifecycleEvent) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return // post-close transitions have no consumer left
	}
	q.events = append(q.events, event)
	q.cond.Signal()
}

// close marks the queue finished; a draining dispatcher returns after it
// has handled every queued event.
func (q *lifecycleQueue) close() {
	q.mu.Lock()
	q.closed = true
	q.cond.Broadcast()
	q.mu.Unlock()
}

// drain runs fn for every queued event in publication order and returns
// once the queue is closed and drained. fn runs OUTSIDE the queue lock: a
// callback may call Release, and close (on the renewal goroutine's exit
// path) must never wait for a callback to finish.
func (q *lifecycleQueue) drain(fn func(lifecycleEvent)) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for {
		for len(q.events) > 0 {
			event := q.events[0]
			q.events = q.events[1:]
			q.mu.Unlock()
			// Contain callback panics HERE, not at the dispatcher: a panic
			// unwinding through drain would run drain's deferred Unlock
			// while the mutex is NOT held — an unrecoverable fatal error
			// that kills the process (quality/security review, empirically
			// confirmed). Per-event containment also keeps later events
			// flowing past a broken callback.
			func() {
				defer func() { _ = recover() }()
				fn(event)
			}()
			q.mu.Lock()
		}
		if q.closed {
			return
		}
		q.cond.Wait()
	}
}

// deliver queues one lifecycle transition for the dispatcher. The renewal
// goroutine never runs option callbacks on its own stack and never blocks
// on delivery.
func (a *Acquisition) deliver(event lifecycleEvent) {
	if a.events == nil {
		return
	}
	a.events.push(event)
}

// startRenewal launches the renewal goroutine and its lifecycle dispatcher.
// The production pace renews near 50% of the GRANTED lease with ±10%
// jitter, re-derived after every grant; tests pace it faster via the
// request fields.
func (m *Manager) startRenewal(forwardID string, acquisition *Acquisition, lease time.Duration, requestedInterval, requestedJitter time.Duration) {
	productionPacing := requestedInterval <= 0
	interval := requestedInterval
	jitter := requestedJitter
	if productionPacing {
		granted := acquisition.grantedLeaseOrDefault(lease)
		interval = granted / 2
		jitter = granted / 10
	}
	acquisition.renewCtx, acquisition.renewCancel = context.WithCancel(context.Background())
	acquisition.renewStop = make(chan struct{})
	acquisition.renewDone = make(chan struct{})
	acquisition.events = newLifecycleQueue()

	go func() {
		// Callback panics are contained per event inside drain; this
		// recover is belt-and-braces for anything above the queue.
		defer func() { _ = recover() }()
		acquisition.events.drain(func(event lifecycleEvent) {
			switch event.kind {
			case eventDegraded:
				if m.opts.OnMappingDegraded != nil {
					m.opts.OnMappingDegraded(forwardID, event.reason)
				}
			case eventLost:
				if m.opts.OnMappingLost != nil {
					m.opts.OnMappingLost(forwardID, event.reason)
				}
			case eventRecovered:
				if m.opts.OnMappingRecovered != nil {
					m.opts.OnMappingRecovered(forwardID)
				}
			}
		})
	}()

	go func() {
		defer close(acquisition.renewDone)
		defer acquisition.events.close()
		timer := time.NewTimer(interval + jitterTime(jitter))
		defer timer.Stop()
		for {
			select {
			case <-acquisition.renewStop:
				return
			case <-timer.C:
			}
			nextInterval, nextJitter := m.renewOnce(forwardID, acquisition, lease, productionPacing)
			if acquisition.lost() {
				return
			}
			if productionPacing && nextInterval > 0 {
				interval, jitter = nextInterval, nextJitter
			}
			timer.Reset(interval + jitterTime(jitter))
		}
	}()
}

// renewOnce performs one renewal attempt under the §3.5 ladder: three
// consecutive failures degrade (DEGRADED); the expiry safety margin, a
// confirmed gateway reboot, or a rewritten external endpoint loses. It
// returns the next pacing when production pacing is active and the new
// grant changed it.
func (m *Manager) renewOnce(forwardID string, acquisition *Acquisition, requestedLease time.Duration, productionPacing bool) (time.Duration, time.Duration) {
	acquisition.renewMu.Lock()
	defer acquisition.renewMu.Unlock()
	if acquisition.Mapping == nil || acquisition.mapper == nil {
		return 0, 0
	}
	// Margin check independent of the attempt below: a long pause (GC,
	// suspend) can push the deadline into the margin without any recorded
	// failure.
	if !acquisition.lostFired && acquisition.withinExpiryMarginLocked(m.clockNow()) {
		acquisition.lostFired = true
		acquisition.deliver(lifecycleEvent{kind: eventLost, reason: "lease expiry safety margin crossed"})
		return 0, 0
	}
	renewed, err := externalCallContained("mapper renew", func() (GatewayMapping, error) {
		return acquisition.mapper.Renew(acquisition.renewCtx, *acquisition.Mapping, requestedLease)
	})
	if err != nil {
		// A panicking adapter is an ordinary renewal failure: it counts
		// toward the §3.5 ladder instead of vanishing into a blanket
		// recover (false-health behavior flagged by review).
		acquisition.failedRenew++
		if acquisition.failedRenew >= 3 && !acquisition.degradedFired {
			acquisition.degradedFired = true
			acquisition.degraded = true
			acquisition.deliver(lifecycleEvent{
				kind:   eventDegraded,
				reason: fmt.Sprintf("three consecutive renewals failed: %v", err),
			})
		}
		if !acquisition.lostFired && acquisition.withinExpiryMarginLocked(m.clockNow()) {
			acquisition.lostFired = true
			acquisition.deliver(lifecycleEvent{
				kind:   eventLost,
				reason: "lease expiry safety margin crossed without a successful renewal",
			})
		}
		return 0, 0
	}
	acquisition.failedRenew = 0
	if renewed.ServerRebooted {
		// A confirmed epoch rollback may have dropped every mapping: the
		// published endpoint is dead regardless of the renew response.
		if !acquisition.lostFired {
			acquisition.lostFired = true
			acquisition.deliver(lifecycleEvent{kind: eventLost, reason: "gateway rebooted (epoch rollback)"})
		}
		return 0, 0
	}
	if renewed.External != acquisition.Mapping.External {
		// A rewritten external endpoint invalidates the published candidate
		// (RFC 6887 §11.5): the observation and verification no longer
		// describe the mapping the gateway holds.
		if !acquisition.lostFired {
			acquisition.lostFired = true
			acquisition.deliver(lifecycleEvent{
				kind:   eventLost,
				reason: fmt.Sprintf("renewal rewrote the external endpoint %s -> %s", acquisition.Mapping.External, renewed.External),
			})
		}
		return 0, 0
	}
	if renewed.Lease > 0 {
		acquisition.leaseDuration = renewed.Lease
		acquisition.leaseDeadline = m.clockNow().Add(renewed.Lease)
	}
	if acquisition.degraded {
		acquisition.degraded = false
		acquisition.degradedFired = false
		acquisition.deliver(lifecycleEvent{kind: eventRecovered})
	}
	renewedCopy := renewed
	acquisition.Mapping = &renewedCopy
	acquisition.JournalID, acquisition.journalAttemptID, acquisition.journalCreatedAt, acquisition.journalError = m.journalPut(
		forwardID, acquisition.JournalID, acquisition.journalAttemptID, acquisition.journalCreatedAt, renewedCopy,
	)
	if productionPacing && renewedCopy.Lease > 0 {
		return renewedCopy.Lease / 2, renewedCopy.Lease / 10
	}
	return 0, 0
}

// lost reports whether the mapping is lost; the renewal loop exits and
// fires no further callbacks once it is.
func (a *Acquisition) lost() bool {
	a.renewMu.Lock()
	defer a.renewMu.Unlock()
	return a.lostFired
}

// withinExpiryMarginLocked reports whether the remaining lease has shrunk
// into the safety margin (lease/10, §3.5's ±10% family): no further
// renewal attempt can plausibly rescue the mapping. An unknown granted
// lifetime has no margin — the failure ladder still applies.
func (a *Acquisition) withinExpiryMarginLocked(now time.Time) bool {
	if a.leaseDeadline.IsZero() || a.leaseDuration <= 0 {
		return false
	}
	return !now.Before(a.leaseDeadline.Add(-a.leaseDuration / 10))
}

// grantedLeaseOrDefault returns the mapping's granted lifetime, falling
// back to the requested lease when the gateway granted nothing usable.
func (a *Acquisition) grantedLeaseOrDefault(fallback time.Duration) time.Duration {
	a.renewMu.Lock()
	defer a.renewMu.Unlock()
	if a.Mapping != nil && a.Mapping.Lease > 0 {
		return a.Mapping.Lease
	}
	return fallback
}

// CurrentMapping returns a locked snapshot of the live mapping. The renewal
// goroutine rewrites the Mapping field in place; readers must not take the
// field directly.
func (a *Acquisition) CurrentMapping() *GatewayMapping {
	a.renewMu.Lock()
	defer a.renewMu.Unlock()
	if a.Mapping == nil {
		return nil
	}
	snapshot := *a.Mapping
	return &snapshot
}

// CurrentJournalError returns the latest journal write failure under the same
// lock used by renewal. A nil result means the latest write succeeded (or no
// journal is configured); callers must not infer that an older failure did not
// occur.
func (a *Acquisition) CurrentJournalError() error {
	a.renewMu.Lock()
	defer a.renewMu.Unlock()
	return a.journalError
}

// journalPut persists one mapping record under a stable private attempt ID.
// JournalID is published only after durability is confirmed. createdAt is
// cached on Acquisition, so renewal never needs an external Get merely to
// preserve audit history. A Put panic is ambiguous (the store may have
// committed first), therefore a contained read-after-panic reconciles the
// exact attempted ID; otherwise the private ID is retained for retry/cleanup.
func (m *Manager) journalPut(forwardID, existingID, attemptID string, createdAt int64, mapping GatewayMapping) (string, string, int64, error) {
	if m.opts.Journal == nil {
		return "", "", 0, nil
	}
	now := m.clockNow()
	if createdAt == 0 {
		createdAt = now.Unix()
	}
	recordID := existingID
	if recordID == "" {
		recordID = attemptID
	}
	if recordID == "" {
		recordID = journalIDFor(forwardID, mapping)
	}
	state, stateErr := externalCallContained("journal state serialization", func() ([]byte, error) {
		if mapping.State == nil {
			return nil, nil
		}
		return json.Marshal(mapping.State)
	})
	if stateErr != nil {
		return existingID, recordID, createdAt, fmt.Errorf("traversal: journal put %s: %w", recordID, stateErr)
	}
	record := JournalRecord{
		ID: recordID, ForwardID: forwardID, Mechanism: mapping.Mechanism,
		Ownership: mapping.Ownership, Protocol: "tcp",
		InternalIP: mapping.InternalIP.String(), InternalPort: mapping.InternalPort,
		ExternalIP: mapping.External.Addr().String(), ExternalPort: mapping.External.Port(),
		LeaseExpiryUnix: now.Add(mapping.Lease).Unix(), Epoch: mapping.Epoch,
		Identity: mapping.Identity, State: state,
		CreatedAtUnix: createdAt, UpdatedAtUnix: now.Unix(),
	}
	// A Put panic is ambiguous: the store may have committed first. Ordinary
	// Put errors are NOT ambiguous — the failed write must surface on
	// CurrentJournalError immediately, with no read-back that could mistake
	// the previous generation's row for this attempt's outcome (network
	// review, S7l round). This one boundary site captures the panic flag
	// because the reconciliation decision depends on it.
	panicked := false
	putErr := func() (err error) {
		defer func() {
			if recovered := recover(); recovered != nil {
				panicked = true
				err = fmt.Errorf("journal put panicked: %v", recovered)
			}
		}()
		return m.opts.Journal.Put(record)
	}()
	if putErr == nil {
		return recordID, recordID, createdAt, nil
	}
	if panicked {
		// Reconcile only the genuinely ambiguous panic case: a durable row
		// counts as this attempt's outcome when its freshness fields match
		// the attempted record exactly. Renewals reuse the ID, so mere
		// presence proves nothing — the row found could be the previous
		// generation's.
		existing, getErr := externalCallContained("journal get", func() (JournalRecord, error) {
			record, ok, err := m.opts.Journal.Get(recordID)
			if err != nil || !ok {
				return JournalRecord{}, err
			}
			return record, nil
		})
		if getErr == nil && existing.UpdatedAtUnix == record.UpdatedAtUnix &&
			existing.LeaseExpiryUnix == record.LeaseExpiryUnix &&
			existing.ExternalPort == record.ExternalPort {
			return recordID, recordID, createdAt, nil
		}
	}
	return existingID, recordID, createdAt, fmt.Errorf("traversal: journal put %s: %w", recordID, putErr)
}

// journalIDFor derives a stable journal record ID per forward.
func journalIDFor(forwardID string, mapping GatewayMapping) string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure: a wall-clock suffix instead of a predictable
		// zeroed ID (quality/security review).
		binary.BigEndian.PutUint64(b[:], uint64(time.Now().UnixNano()))
	}
	return forwardID + "-" + string(mapping.Mechanism) + "-" + hex.EncodeToString(b[:])
}

// sourceAddress resolves the gateway acquisition source: the default-route
// interface's own IPv4 (v0.8 §3.2) — private is the expected shape behind
// a NAT CPE. The global-only Assess governs direct-v4 only, and a host
// with no usable source fails the acquisition instead of silently mapping
// loopback.
func (m *Manager) sourceAddress() (netip.Addr, error) {
	selection, err := DefaultRouteSource(m.opts.RouteTable)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("traversal: gateway source address: %w", err)
	}
	return selection.Source, nil
}

// clockNow reads the injected clock through the external-call boundary; the
// clock is operator-injected like every other callback in the options.
func (m *Manager) clockNow() time.Time {
	now, _ := externalCallContained("clock read", func() (time.Time, error) {
		return m.opts.Clock(), nil
	})
	return now
}

// releaseListenerQuietly releases the listener on failed acquisition paths.
func (m *Manager) releaseListenerQuietly(acquisition *Acquisition) {
	if acquisition.releaseFn != nil {
		_ = cleanupContained("listener release", acquisition.releaseFn) //nolint:errcheck
	}
}

// stopRenewal stops the renewal goroutine exactly once: the in-flight
// renewal is cancelled first (a hung mapper must not bound Release) and the
// loop exit is joined. The lifecycle dispatcher drains its remaining events
// asynchronously — joining it here would self-deadlock when Release is
// called from inside a callback, so consumers must tolerate a trailing
// notification arriving after Release returns.
func (a *Acquisition) stopRenewal() {
	a.renewOnceOnce.Do(func() {
		if a.renewCancel != nil {
			a.renewCancel()
		}
		if a.renewStop != nil {
			close(a.renewStop)
		}
	})
	if a.renewDone != nil {
		<-a.renewDone
	}
}

// jitterTime returns a random duration in [0, max).
func jitterTime(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure: a deterministic mid-window jitter loses
		// anti-synchronization for at most one interval instead of
		// collapsing to always-zero (quality/security review).
		return max / 2
	}
	return time.Duration(binary.BigEndian.Uint64(b[:]) % uint64(max))
}
