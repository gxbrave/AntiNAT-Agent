// Agent probe plane (Story 2): the durable probe_arm handler, the WAN1
// ingress gate on the published TCP listener, the same-path ACK1, and the
// RCT1 control receipt.
//
// The gate wraps the P09 listener BEFORE the proxy sees it: connections
// whose remote source matches an armed, unexpired probe are parsed for a
// WAN1 frame within a bounded deadline, verified against the frozen probe
// state machine, answered with an ACK1 on the same connection, and the RCT1
// receipt is pushed over the signed control channel. The probe connection is
// consumed and never handed to business. Every other source passes straight
// through to the proxy untouched (anti-oracle: no prefix sniffing of victim
// traffic, v0.8 §5.2).
package reconcile

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
	"github.com/gxbrave/AntiNAT-Agent/internal/security"
)

// ErrProbeArmRejected is the generic arm rejection (no detail leak).
var ErrProbeArmRejected = errors.New("reconcile: probe arm rejected")

// ErrProbeRecoveryOverflow is returned when durable replay/active fences do
// not fit in the configured recovery bounds. The listener must quarantine
// rather than route an unknown source to the business data plane.
var ErrProbeRecoveryOverflow = errors.New("reconcile: probe recovery capacity overflow")

// SendControlFunc pushes an A2C control message (probe_ingress_receipt).
type SendControlFunc func(ctx context.Context, messageType string, payload []byte) error

// ProbeManagerOptions configures the agent probe manager.
type ProbeManagerOptions struct {
	// Store is the agent localstate store (durable armed ops).
	Store *localstate.Store
	// NodeKey signs RDY1/ACK1/RCT1 frames.
	NodeKey *security.NodeKey
	// Clock is the monotonic clock; defaults to time.Now.
	Clock func() time.Time
	// SendControl pushes A2C control messages (probe_ingress_receipt).
	SendControl SendControlFunc
	// MaxReplayEntries bounds the in-memory replay fence.
	MaxReplayEntries int
	// SweepInterval bounds expired operation/tombstone retention.
	SweepInterval time.Duration
	// MaxActiveOperations bounds durable replay/recovery and in-memory armed
	// operations.
	MaxActiveOperations int
	// SendTimeout bounds receipt/control writes during retry.
	SendTimeout time.Duration
	// ReceiptRetryInterval controls same-session retries for receipts that
	// were transport-delivered but have not received a semantic ACK.
	ReceiptRetryInterval time.Duration
	// Marker is the durable terminal lifecycle state. Terminal markers suppress
	// probe-arm recovery and new probe admission; durable receipt rows remain
	// available for cleanup/retry.
	Marker localstate.MarkerState
}

// armedOp is one in-memory armed probe operation (loaded from bbolt at
// startup, persisted at arm time).
type armedOp struct {
	arm       protocol.ProbeArm
	forwardID string
	digest    [32]byte
	deadline  time.Time
	used      bool
}

// PreparedProbeArm contains all validated and signed material for an ARM1
// admission. Preparation has no durable side effect; the caller must either
// activate or abort it.
type PreparedProbeArm struct {
	Arm              protocol.ProbeArm
	ForwardID        string
	ExpectedRevision uint64
	Digest           [32]byte
	Deadline         time.Time
	RDY              []byte
	Existing         bool
}

type replaySource struct {
	source    [4]byte
	forwardID string
	digest    [32]byte
}

// ProbeManager implements the agent-side probe plane.
type ProbeManager struct {
	store *localstate.Store
	key   *security.NodeKey
	clock func() time.Time
	send  SendControlFunc

	mu                   sync.Mutex
	receiptMu            sync.Mutex
	ops                  map[[16]byte]*armedOp
	replay               map[[16]byte]time.Time
	replaySource         map[[16]byte]replaySource
	maxReplay            int
	maxActive            int
	recoveryErr          error
	sendTimeout          time.Duration
	receiptRetryInterval time.Duration
	sweepInterval        time.Duration
	marker               localstate.MarkerState
	sweepAfter           []byte
	cancel               context.CancelFunc
	wg                   sync.WaitGroup
}

// NewProbeManager builds the manager and recovers durable armed operations
// from bbolt (restart recovery; expired ops are dropped on first sweep).
func NewProbeManager(opts ProbeManagerOptions) *ProbeManager {
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	if opts.MaxReplayEntries <= 0 {
		opts.MaxReplayEntries = 4096
	}
	if opts.SweepInterval <= 0 {
		opts.SweepInterval = time.Minute
	}
	if opts.MaxActiveOperations <= 0 {
		opts.MaxActiveOperations = 256
	}
	if opts.SendTimeout <= 0 {
		opts.SendTimeout = 5 * time.Second
	}
	if opts.ReceiptRetryInterval <= 0 {
		opts.ReceiptRetryInterval = 500 * time.Millisecond
	}
	m := &ProbeManager{
		store:                opts.Store,
		key:                  opts.NodeKey,
		clock:                opts.Clock,
		send:                 opts.SendControl,
		ops:                  map[[16]byte]*armedOp{},
		replay:               map[[16]byte]time.Time{},
		replaySource:         map[[16]byte]replaySource{},
		maxReplay:            opts.MaxReplayEntries,
		maxActive:            opts.MaxActiveOperations,
		sendTimeout:          opts.SendTimeout,
		receiptRetryInterval: opts.ReceiptRetryInterval,
		sweepInterval:        opts.SweepInterval,
		marker:               opts.Marker,
	}
	if m.store != nil && m.marker == localstate.MarkerActive {
		// Replay tombstones may outlive active operations. Walk every durable
		// page so a consumed or armed source fence beyond the active-operation
		// page cannot be forgotten on restart.
		var after []byte
		for {
			probes, next, done, err := m.store.ListArmedProbesPage(m.maxActive, after)
			if err != nil {
				m.recoveryErr = err
				break
			}
			for _, p := range probes {
				now := m.clock()
				if p.Consumed {
					// A consumed row is a replay fence, not an active arm. Missing
					// receipt timing or a wall-clock rollback makes expiry
					// unknowable; retain it and quarantine rather than reopening
					// the source to the business path.
					if p.ReceiptDeadline.IsZero() || (!p.ArmedAt.IsZero() && now.Before(p.ArmedAt)) {
						m.recoveryErr = ErrProbeRecoveryOverflow
						continue
					}
					if !p.ReceiptDeadline.After(now) {
						_ = m.store.DeleteArmedProbe(p.Arm.ProbeID)
						continue
					}
					if len(m.replay) < m.maxReplay {
						m.replay[p.Arm.ProbeID] = p.ReceiptDeadline
						m.replaySource[p.Arm.ProbeID] = replaySource{
							source: p.Arm.ExpectedSourceIP, forwardID: p.ForwardID, digest: p.Digest,
						}
					} else {
						m.recoveryErr = ErrProbeRecoveryOverflow
					}
					continue
				}
				if p.Deadline.IsZero() || (!p.ArmedAt.IsZero() && now.Before(p.ArmedAt)) {
					// A malformed deadline or wall-clock rollback makes elapsed
					// TTL unknowable. Retain the row and fail closed.
					m.recoveryErr = ErrProbeRecoveryOverflow
					continue
				}
				if p.Deadline.After(now) {
					if len(m.ops) >= m.maxActive {
						m.recoveryErr = ErrProbeRecoveryOverflow
						continue
					}
					m.ops[p.Arm.ProbeID] = &armedOp{arm: p.Arm, forwardID: p.ForwardID, digest: p.Digest, deadline: p.Deadline}
				} else {
					_ = m.store.DeleteArmedProbe(p.Arm.ProbeID)
				}
			}
			if done {
				break
			}
			after = next
		}
	}
	return m
}

// Quarantined reports whether restart recovery could not account for every
// durable fence. It intentionally has no automatic clearing path: an operator
// must raise the configured capacity or explicitly restart after inspection.
func (m *ProbeManager) Quarantined() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.recoveryErr != nil
}

// Start launches the cancellable probe retention sweeper. It is separate from
// the listener gate so shutdown can wait for all state work before closing the
// local bbolt store.
func (m *ProbeManager) Start(parent context.Context) {
	m.mu.Lock()
	if m.cancel != nil {
		m.mu.Unlock()
		return
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	m.cancel = cancel
	m.wg.Add(1)
	m.mu.Unlock()
	go func() {
		defer m.wg.Done()
		sweepTicker := time.NewTicker(m.sweepInterval)
		defer sweepTicker.Stop()
		receiptTicker := time.NewTicker(m.receiptRetryInterval)
		defer receiptTicker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-receiptTicker.C:
				// ReceiptSent records only transport delivery. Keep retrying
				// on the healthy session until semantic acknowledgement.
				_ = m.RetryPendingReceipts(ctx)
			case now := <-sweepTicker.C:
				m.mu.Lock()
				m.sweep(now)
				after := append([]byte(nil), m.sweepAfter...)
				m.mu.Unlock()
				if m.store != nil {
					next, done, err := m.store.SweepArmedProbeTombstonesPage(now, m.maxActive, after)
					if err == nil {
						m.mu.Lock()
						if done {
							m.sweepAfter = nil
						} else {
							m.sweepAfter = next
						}
						m.mu.Unlock()
					}
				}
			}
		}
	}()
}

// Close stops the retention sweeper and waits for it to exit.
func (m *ProbeManager) Close() {
	_ = m.CloseContext(context.Background())
}

// CloseContext stops the retention sweeper and joins it subject to ctx. A
// caller deadline never turns an in-flight sweep or receipt retry into an
// unowned goroutine; a later caller may retry the join after cancellation has
// propagated.
func (m *ProbeManager) CloseContext(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	m.mu.Lock()
	cancel := m.cancel
	m.cancel = nil
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// PrepareProbeArm validates and signs an ARM1 without persisting it. App-level
// admission can therefore transition activation first and commit the ARM only
// after all identity and generation fences have passed.
func (m *ProbeManager) PrepareProbeArm(raw []byte, forwardID string) (PreparedProbeArm, error) {
	if m.marker != localstate.MarkerActive {
		return PreparedProbeArm{}, ErrProbeArmRejected
	}
	arm, err := protocol.ParseProbeArm(raw)
	if err != nil {
		return PreparedProbeArm{}, err
	}
	if m.store == nil || forwardID == "" {
		return PreparedProbeArm{}, ErrProbeArmRejected
	}
	applied, ok, err := m.store.GetAppliedState(forwardID)
	if err != nil {
		return PreparedProbeArm{}, err
	}
	if !ok || arm.Activation != protocol.ActivationID(forwardID, applied.SpecRevision) {
		return PreparedProbeArm{}, ErrProbeArmRejected
	}
	wantEndpoint := net.JoinHostPort(applied.ActualBindHost, fmt.Sprintf("%d", applied.ActualBindPort))
	endpointMatches := arm.Endpoint == wantEndpoint
	if !endpointMatches && applied.PublicPort != 0 {
		// A STUN-only or gateway forward may bind a private local tuple while
		// its independently observed public candidate is the probe endpoint.
		// ParseProbeArm has already enforced the global IPv4 endpoint rule; the
		// recorded candidate port is the remaining binding constraint.
		candidate, parseErr := netip.ParseAddrPort(arm.Endpoint)
		endpointMatches = parseErr == nil && candidate.Port() == applied.PublicPort
	}
	if !endpointMatches {
		return PreparedProbeArm{}, ErrProbeArmRejected
	}
	deadline := m.clock().Add(time.Duration(arm.TTLMS) * time.Millisecond)
	m.mu.Lock()
	_, alreadyArmed := m.ops[arm.ProbeID]
	capacity := len(m.ops) >= m.maxActive && !alreadyArmed
	m.mu.Unlock()
	if capacity {
		return PreparedProbeArm{}, ErrProbeArmRejected
	}
	if m.key == nil {
		return PreparedProbeArm{}, ErrProbeArmRejected
	}
	digest := arm.Digest()
	var rdy bytes.Buffer
	rdy.WriteString(protocol.ProbeMagicArmed)
	rdy.Write(digest[:])
	sig, err := m.key.Sign(rdy.Bytes())
	if err != nil {
		return PreparedProbeArm{}, err
	}
	rdy.Write(sig)
	return PreparedProbeArm{Arm: arm, ForwardID: forwardID, ExpectedRevision: applied.SpecRevision, Digest: digest, Deadline: deadline, RDY: rdy.Bytes(), Existing: alreadyArmed}, nil
}

// CommitPreparedProbeArm durably records a prepared ARM and then publishes it
// to the in-memory gate. RDY1 is returned by the caller only after this method
// succeeds, so a failed persistence step cannot expose an unbacked operation.
func (m *ProbeManager) CommitPreparedProbeArm(prepared PreparedProbeArm) error {
	if m.marker != localstate.MarkerActive {
		return ErrProbeArmRejected
	}
	if m.store == nil || prepared.ForwardID == "" || prepared.Arm.ProbeID == ([16]byte{}) || prepared.ExpectedRevision == 0 {
		return ErrProbeArmRejected
	}
	if err := m.store.SaveArmedProbeForForward(prepared.Arm, prepared.ForwardID, prepared.Deadline); err != nil {
		if errors.Is(err, localstate.ErrProbeConsumed) || errors.Is(err, localstate.ErrProbeConflict) {
			return ErrProbeArmRejected
		}
		return err
	}
	m.mu.Lock()
	m.ops[prepared.Arm.ProbeID] = &armedOp{arm: prepared.Arm, forwardID: prepared.ForwardID, digest: prepared.Digest, deadline: prepared.Deadline}
	m.mu.Unlock()
	return nil
}

// CommitPreparedProbeArmWithActivation commits the activation snapshot and ARM
// in one localstate transaction before publishing the in-memory operation.
func (m *ProbeManager) CommitPreparedProbeArmWithActivation(prepared PreparedProbeArm, activation string, before, after protocol.ActivationStates) error {
	if m.marker != localstate.MarkerActive {
		return ErrProbeArmRejected
	}
	if m.store == nil || prepared.ForwardID == "" || prepared.Arm.ProbeID == ([16]byte{}) || prepared.ExpectedRevision == 0 {
		return ErrProbeArmRejected
	}
	if activation != hex.EncodeToString(prepared.Arm.Activation[:]) {
		return ErrProbeArmRejected
	}
	if err := m.store.CommitProbeAdmission(prepared.ForwardID, prepared.ExpectedRevision, activation, prepared.Arm, prepared.Deadline, before, after); err != nil {
		if errors.Is(err, localstate.ErrProbeConsumed) || errors.Is(err, localstate.ErrProbeConflict) || errors.Is(err, localstate.ErrProbeAdmissionConflict) {
			return ErrProbeArmRejected
		}
		return err
	}
	m.mu.Lock()
	m.ops[prepared.Arm.ProbeID] = &armedOp{arm: prepared.Arm, forwardID: prepared.ForwardID, digest: prepared.Digest, deadline: prepared.Deadline}
	m.mu.Unlock()
	return nil
}

// AbortPreparedProbeArm removes only an operation published by this manager.
// It never deletes an unrelated durable row for a preparation that failed
// before commit.
func (m *ProbeManager) AbortPreparedProbeArm(prepared PreparedProbeArm) error {
	if m.store == nil || prepared.Arm.ProbeID == ([16]byte{}) {
		return nil
	}
	m.mu.Lock()
	op, committed := m.ops[prepared.Arm.ProbeID]
	if committed && (op.forwardID != prepared.ForwardID || op.digest != prepared.Digest) {
		committed = false
	}
	if committed {
		delete(m.ops, prepared.Arm.ProbeID)
	}
	m.mu.Unlock()
	if !committed {
		return nil
	}
	return m.store.DeleteArmedProbe(prepared.Arm.ProbeID)
}

// HandleProbeArm validates, persists, and publishes one ARM1. It retains the
// direct manager API used by lower-level tests while the App uses prepare and
// commit around activation admission.
func (m *ProbeManager) HandleProbeArm(ctx context.Context, raw []byte, forwardID string) ([]byte, error) {
	if m.marker != localstate.MarkerActive {
		return nil, ErrProbeArmRejected
	}
	prepared, err := m.PrepareProbeArm(raw, forwardID)
	if err != nil {
		return nil, err
	}
	if err := m.CommitPreparedProbeArm(prepared); err != nil {
		return nil, err
	}
	return prepared.RDY, nil
}

// RetryPendingACKs replays durable ACK1 material whose provider write did not
// complete. The source connection is not reused; callers must provide a fresh
// accepted provider path that is already known to belong to the operation.
// The normal gate invokes this only when it has a fresh matching WAN1 frame.
func (m *ProbeManager) RetryPendingACK(probeID [16]byte, conn net.Conn, writeTimeout time.Duration) error {
	if m.store == nil || conn == nil {
		return ErrProbeArmRejected
	}
	rec, ok, err := m.store.LoadArmedProbe(probeID)
	if err != nil {
		return err
	}
	if !ok || !rec.Consumed || rec.ACKSent || len(rec.ACK) == 0 {
		return ErrProbeArmRejected
	}
	if writeTimeout <= 0 {
		writeTimeout = 2 * time.Second
	}
	if err := conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return err
	}
	if _, err := writeFull(conn, rec.ACK); err != nil {
		return err
	}
	return m.store.MarkArmedProbeACKSent(probeID)
}

// RetryPendingReceipts resends consumed receipts that were durably recorded
// but not semantically acknowledged by the Controller. ReceiptSent records
// only a prior transport write; the Controller may have disconnected before
// processing it, so it must not suppress a reconnect retry.
func (m *ProbeManager) RetryPendingReceipts(ctx context.Context) error {
	m.receiptMu.Lock()
	defer m.receiptMu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	if m.store == nil || m.send == nil {
		return nil
	}
	var firstErr error
	var after []byte
	for {
		probes, next, done, err := m.store.ListArmedProbesPage(m.maxActive, after)
		if err != nil {
			return err
		}
		for _, probe := range probes {
			if !probe.Consumed || probe.ReceiptAcknowledged || len(probe.Receipt) == 0 {
				continue
			}
			messageID := probe.ReceiptMessageID
			if messageID == "" {
				messageID = probeReceiptOperationID(probe.Receipt)
				_ = m.store.SetArmedProbeReceiptMessageID(probe.Arm.ProbeID, messageID, probe.Deadline.Add(protocol.ProbeReplayWindow))
			}
			sendCtx, cancel := context.WithTimeout(ctx, m.sendTimeout)
			err := m.send(sendCtx, "probe_ingress_receipt", probe.Receipt)
			cancel()
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			if err := m.store.MarkArmedProbeReceiptSent(probe.Arm.ProbeID); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if done {
			return firstErr
		}
		after = next
	}
}

// AcknowledgeReceipt records the controller semantic receipt for a probe
// ingress message while retaining the matching durable replay tombstone until
// its ReceiptDeadline.
func (m *ProbeManager) AcknowledgeReceipt(operationID string) error {
	if m.store == nil {
		return nil
	}
	return m.store.AcknowledgeArmedProbeReceipt(operationID)
}

// sweep evicts expired operations and replay entries.
func (m *ProbeManager) sweep(now time.Time) {
	for id, op := range m.ops {
		if !now.Before(op.deadline) {
			delete(m.ops, id)
			if m.store != nil {
				// Consuming the ingress operation turns the row into the
				// receipt replay tombstone. Its lifetime is ReceiptDeadline,
				// not the original arm deadline.
				rec, found, err := m.store.LoadArmedProbe(id)
				if err == nil && found && rec.Consumed {
					continue
				}
				_ = m.store.DeleteArmedProbe(id)
			}
		}
	}
	for id, expire := range m.replay {
		if !now.Before(expire) {
			delete(m.replay, id)
			delete(m.replaySource, id)
		}
	}
}

// hasArmedBySource reports whether a source currently has an armed operation.
// The gate uses this only to decide whether to consume a bounded probe attempt;
// frame-to-operation demultiplexing happens after the frame is parsed.
func (m *ProbeManager) hasArmedBySource(ip [4]byte, forwardIDs ...string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweep(m.clock())
	forwardID := ""
	if len(forwardIDs) > 0 {
		forwardID = forwardIDs[0]
	}
	for _, op := range m.ops {
		_, replayed := m.replay[op.arm.ProbeID]
		if op.arm.ExpectedSourceIP == ip && (forwardID == "" || op.forwardID == forwardID) &&
			(!op.used || replayed) {
			return true
		}
	}
	for id, binding := range m.replaySource {
		if _, active := m.replay[id]; active && binding.source == ip &&
			(forwardID == "" || binding.forwardID == forwardID) {
			return true
		}
	}
	return false
}

// handleIngress consumes one accepted connection from the expected provider
// source: reads the WAN1 frame with a bounded deadline, verifies it against
// the armed operation, writes the ACK1 on the same connection, and sends the
// RCT1 receipt over the control channel. Every failure is a generic drop
// with zero authenticated material (anti-oracle).
func (m *ProbeManager) handleIngress(conn net.Conn, source [4]byte, readTimeout time.Duration, forwardIDs ...string) {
	defer conn.Close()
	deadline := time.Now().Add(readTimeout)
	if err := conn.SetReadDeadline(deadline); err != nil {
		return
	}

	// Two-phase bounded read: fixed header (magic + digest + ids +
	// activation + 1-byte endpoint length), then the endpoint + trailer.
	const fixed = 4 + 32 + 16 + 16 + 16 + 1
	head := make([]byte, fixed)
	if _, err := readFull(conn, head); err != nil {
		return // truncated: generic drop
	}
	endpointLen := int(head[fixed-1])
	frameLen := fixed + endpointLen + 16 + 32 + 64
	if endpointLen == 0 || frameLen > 4+32+16+16+16+1+protocol.ProbeEndpointMax+16+32+64 {
		return
	}
	rest := make([]byte, frameLen-fixed)
	if _, err := readFull(conn, rest); err != nil {
		return
	}
	raw := append(head, rest...)
	frame, err := protocol.ParseProviderFrame(raw)
	if err != nil {
		return
	}

	// Demultiplex only after parsing and authenticating the frame. Selecting
	// the first operation by source alone lets one provider starve another
	// operation armed on the same source IP.
	now := m.clock()
	forwardID := ""
	if len(forwardIDs) > 0 {
		forwardID = forwardIDs[0]
	}
	m.mu.Lock()
	m.sweep(now)
	if m.recoveryErr != nil {
		m.mu.Unlock()
		return
	}
	if _, replayed := m.replay[frame.ProbeID]; replayed {
		// A consumed probe id is normally a generic replay drop. The one
		// exception is a byte-for-byte authenticated WAN1 retry while ACK1 is
		// durably pending: this is the only bounded way to recover a provider
		// connection after a partial write without reopening the business path.
		binding, bound := m.replaySource[frame.ProbeID]
		m.mu.Unlock()
		if !bound || binding.digest != frame.ArmDigest || binding.source != source ||
			(forwardID != "" && binding.forwardID != forwardID) {
			return
		}
		m.replayPendingACK(conn, source, frame, readTimeout)
		return
	}
	var op *armedOp
	for _, candidate := range m.ops {
		if candidate.used || !now.Before(candidate.deadline) || candidate.arm.ExpectedSourceIP != source ||
			(forwardID != "" && candidate.forwardID != forwardID) ||
			candidate.arm.ProbeID != frame.ProbeID || candidate.digest != frame.ArmDigest {
			continue
		}
		arm := candidate.arm
		if frame.ProviderID == arm.ProviderID &&
			frame.Activation == arm.Activation &&
			frame.Endpoint == arm.Endpoint &&
			frame.ExpiryOpaque == arm.ExpiryOpaque &&
			ed25519.Verify(arm.ProviderKey(), frame.SigningBytes(), frame.Signature) {
			op = candidate
			break
		}
	}
	if op == nil {
		m.mu.Unlock()
		return // generic REJECTED/DROPPED
	}
	// A recovered or misconfigured manager may have durable arms but no node
	// signing key. Fail closed before consuming the arm or attempting to write
	// an unauthenticated ACK1/RCT1; a later key restoration can retry it. Keep
	// the replay-pending ACK path above available because it reuses a durable,
	// already-signed ACK and does not need the live key.
	if m.key == nil {
		m.mu.Unlock()
		return
	}
	if len(m.replay) >= m.maxReplay {
		m.mu.Unlock()
		return
	}
	op.used = true
	receiptDeadline := op.deadline.Add(protocol.ProbeReplayWindow)
	m.replay[frame.ProbeID] = receiptDeadline
	m.replaySource[frame.ProbeID] = replaySource{
		source: source, forwardID: op.forwardID, digest: op.digest,
	}
	m.mu.Unlock()

	// ACK1 on the same connection.
	chash := frame.ChallengeHash()
	var ack bytes.Buffer
	ack.WriteString(protocol.ProbeMagicACK)
	ack.Write(op.digest[:])
	ack.Write(chash[:])
	sig, err := m.key.Sign(ack.Bytes())
	if err != nil {
		return
	}
	ack.Write(sig)

	// RCT1 is built and durably recorded before the network ACK. If the
	// process crashes after ACK, restart recovery can still resend this exact
	// receipt; if sending fails, the consumed row remains pending.
	var rct bytes.Buffer
	rct.WriteString(protocol.ProbeMagicReceipt)
	rct.Write(op.digest[:])
	rct.Write(chash[:])
	rct.Write(op.arm.ProviderID[:])
	rsig, err := m.key.Sign(rct.Bytes())
	if err != nil {
		return
	}
	rct.Write(rsig)
	receiptOperationID := probeReceiptOperationID(rct.Bytes())
	// Install the write deadline before consuming durable state. A connection
	// whose deadline cannot be installed must not receive an ACK or create a
	// receipt that the controller could mistake for successful delivery.
	if err := conn.SetWriteDeadline(time.Now().Add(readTimeout)); err != nil {
		m.mu.Lock()
		op.used = false
		delete(m.replay, frame.ProbeID)
		delete(m.replaySource, frame.ProbeID)
		m.mu.Unlock()
		return
	}
	if m.store == nil {
		m.mu.Lock()
		op.used = false
		delete(m.replay, frame.ProbeID)
		delete(m.replaySource, frame.ProbeID)
		m.mu.Unlock()
		return
	}
	if err := m.store.MarkArmedProbeConsumedWithACK(op.arm.ProbeID, rct.Bytes(), ack.Bytes(), chash, receiptOperationID, op.deadline.Add(protocol.ProbeReplayWindow)); err != nil {
		m.mu.Lock()
		op.used = false
		delete(m.replay, frame.ProbeID)
		delete(m.replaySource, frame.ProbeID)
		m.mu.Unlock()
		return
	}

	if _, err := writeFull(conn, ack.Bytes()); err != nil {
		return
	}
	_ = m.store.MarkArmedProbeACKSent(op.arm.ProbeID)
	if m.send != nil {
		ctx, cancel := context.WithTimeout(context.Background(), readTimeout)
		err := m.send(ctx, "probe_ingress_receipt", rct.Bytes())
		cancel()
		if err == nil {
			_ = m.store.MarkArmedProbeReceiptSent(op.arm.ProbeID)
		}
	}
}

// replayPendingACK verifies the full WAN1 binding against the durable arm and
// replays ACK1 only when that exact operation still has an unsent ACK. A fresh
// challenge is rejected because it would make the stored ACK semantically
// unrelated to the ingress frame.
func (m *ProbeManager) replayPendingACK(conn net.Conn, source [4]byte, frame protocol.ProviderFrame, timeout time.Duration) {
	rec, ok, err := m.store.LoadArmedProbe(frame.ProbeID)
	if err != nil || !ok || !rec.Consumed || rec.ACKSent || len(rec.ACK) == 0 || rec.Arm.ExpectedSourceIP != source ||
		rec.Digest != frame.ArmDigest || rec.Arm.ProviderID != frame.ProviderID || rec.Arm.Activation != frame.Activation ||
		rec.Arm.Endpoint != frame.Endpoint || rec.Arm.ExpiryOpaque != frame.ExpiryOpaque || rec.ChallengeHash != frame.ChallengeHash() ||
		!ed25519.Verify(rec.Arm.ProviderKey(), frame.SigningBytes(), frame.Signature) {
		return
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return
	}
	if _, err := writeFull(conn, rec.ACK); err != nil {
		return
	}
	_ = m.store.MarkArmedProbeACKSent(frame.ProbeID)
}

// probeReceiptOperationID derives the semantic id carried in the controller's
// message_receipt payload. control.Client.SendMessage domain-separates the
// transport envelope id from this digest, so the durable tombstone must store
// the digest rather than the envelope id.
func probeReceiptOperationID(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// ProbeGateOptions configures the listener gate.
type ProbeGateOptions struct {
	// ForwardID names the forward this listener belongs to.
	ForwardID string
	// ReadTimeout bounds the WAN1 parse (v0.8 §5.2 bounded deadline).
	ReadTimeout time.Duration
	// MaxConcurrent bounds provider-source probe goroutines.
	MaxConcurrent int
}

// ProbeGate is a net.Listener wrapper that consumes probe ingress from the
// armed provider source and passes every other connection to the business
// accept path untouched.
type ProbeGate struct {
	inner           net.Listener
	mgr             *ProbeManager
	opts            ProbeGateOptions
	slots           chan struct{}
	mu              sync.Mutex
	closed          bool
	active          map[net.Conn]struct{}
	wg              sync.WaitGroup
	closeMu         sync.Mutex
	closeInProgress bool
	closeDone       chan struct{}
	closeComplete   bool
	closeErr        error
}

// NewProbeGate wraps inner with the probe ingress gate.
func NewProbeGate(inner net.Listener, mgr *ProbeManager, opts ProbeGateOptions) *ProbeGate {
	if opts.ReadTimeout <= 0 {
		opts.ReadTimeout = 2 * time.Second
	}
	if opts.MaxConcurrent <= 0 {
		opts.MaxConcurrent = 64
	}
	return &ProbeGate{
		inner: inner, mgr: mgr, opts: opts, slots: make(chan struct{}, opts.MaxConcurrent),
		active: make(map[net.Conn]struct{}),
	}
}

// Accept returns the next business connection. Probe connections from the
// armed provider source are consumed internally and never returned.
func (g *ProbeGate) Accept() (net.Conn, error) {
	for {
		if g.mgr != nil && g.mgr.Quarantined() {
			return nil, ErrProbeRecoveryOverflow
		}
		conn, err := g.inner.Accept()
		if err != nil {
			return nil, err
		}
		if g.isClosed() {
			_ = conn.Close()
			return nil, net.ErrClosed
		}
		remoteIP := remoteIPv4(conn)
		if remoteIP == nil || g.mgr == nil {
			return conn, nil // non-IPv4 or unconfigured probe plane: business path
		}
		if !g.mgr.hasArmedBySource(*remoteIP, g.opts.ForwardID) {
			return conn, nil // not the provider source: straight to business
		}
		// Provider source with an armed op: bounded probe-frame parse. Never
		// create an unbounded goroutine per source-matching connection.
		select {
		case g.slots <- struct{}{}:
			if !g.track(conn) {
				<-g.slots
				_ = conn.Close()
				return nil, net.ErrClosed
			}
			go func(conn net.Conn, source [4]byte) {
				defer g.untrack(conn)
				defer func() { <-g.slots }()
				g.mgr.handleIngress(conn, source, g.opts.ReadTimeout, g.opts.ForwardID)
			}(conn, *remoteIP)
		default:
			_ = conn.Close() // generic resource-bound drop
		}
	}
}

// Close closes the underlying listener, all active provider connections, and
// joins their ingress workers before returning. A failed listener close remains
// retryable so its owner can eventually release the registry lease.
func (g *ProbeGate) Close() error {
	g.closeMu.Lock()
	if g.closeComplete {
		err := g.closeErr
		g.closeMu.Unlock()
		return err
	}
	if g.closeInProgress {
		done := g.closeDone
		g.closeMu.Unlock()
		<-done
		g.closeMu.Lock()
		err := g.closeErr
		g.closeMu.Unlock()
		return err
	}
	g.closeInProgress = true
	g.closeDone = make(chan struct{})
	done := g.closeDone
	g.closeMu.Unlock()

	g.mu.Lock()
	g.closed = true
	active := make([]net.Conn, 0, len(g.active))
	for conn := range g.active {
		active = append(active, conn)
	}
	g.mu.Unlock()

	err := g.inner.Close()
	for _, conn := range active {
		_ = conn.Close()
	}
	g.wg.Wait()

	g.closeMu.Lock()
	g.closeErr = err
	g.closeComplete = err == nil || errors.Is(err, net.ErrClosed)
	g.closeInProgress = false
	close(done)
	g.closeMu.Unlock()
	return err
}

func (g *ProbeGate) isClosed() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.closed
}

func (g *ProbeGate) track(conn net.Conn) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return false
	}
	g.active[conn] = struct{}{}
	g.wg.Add(1)
	return true
}

func (g *ProbeGate) untrack(conn net.Conn) {
	g.mu.Lock()
	delete(g.active, conn)
	g.mu.Unlock()
	g.wg.Done()
}

// Addr returns the underlying listener address.
func (g *ProbeGate) Addr() net.Addr { return g.inner.Addr() }

// remoteIPv4 returns the remote address as a 4-byte IPv4, or nil.
func remoteIPv4(conn net.Conn) *[4]byte {
	tcp, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return nil
	}
	ip4 := tcp.IP.To4()
	if ip4 == nil {
		return nil
	}
	var out [4]byte
	copy(out[:], ip4)
	return &out
}

// readFull reads exactly len(buf) bytes or returns an error.
func readFull(conn net.Conn, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := conn.Read(buf[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// writeFull writes all bytes or returns the first error.
func writeFull(conn net.Conn, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := conn.Write(buf[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}
