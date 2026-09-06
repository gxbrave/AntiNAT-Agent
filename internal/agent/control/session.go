package control

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
	"github.com/gxbrave/AntiNAT-Agent/internal/security"
)

// Control channel bounds (mirror the hub).
const (
	// maxEnvelopeBytes bounds one WS message (frame + header + payload + sig).
	maxEnvelopeBytes = 13 + protocol.MaxHeaderBytes + protocol.MaxPayloadBytes + 64
	// sessionIdleTimeout closes a session receiving no frames.
	sessionIdleTimeout = 3 * time.Minute
	// outboxPumpInterval is the outbox claim/send cadence.
	outboxPumpInterval = 50 * time.Millisecond
)

// ClientOptions configures the Agent control session client.
type ClientOptions struct {
	// Endpoint is the controller base URL (http:// or https://).
	Endpoint string
	// NodeID is the agent's node identity (store-form string).
	NodeID string
	// Store is the agent localstate store (journal + pins).
	Store *localstate.Store
	// Key is the agent node identity key.
	Key *security.NodeKey
	// Heartbeat is the A2C heartbeat interval (0 disables automatic
	// heartbeats; tests use a short interval).
	Heartbeat time.Duration
	// OnCommand handles an inbound command (desired/forward_delete/...)
	// between the journal's APPLYING and APPLIED/NACKED phases. It returns
	// the durable semantic result or an error that NACKs the operation.
	OnCommand func(ctx context.Context, op Operation) ([]byte, error)
	// OnRecoveredDeletion converges only the ABSENT resources from a command
	// recovered from APPLYING. It is invoked on an exact payload redelivery after
	// localstate has installed the durable deletion fences; PRESENT siblings are
	// never replayed because their external side effects may already have run.
	OnRecoveredDeletion func(ctx context.Context, op Operation) error
	// OnReceipt is called for controller semantic receipts that do not
	// correspond to an agent outbox row (for example the probe receipt ack).
	OnReceipt func(ctx context.Context, operationID string) error
	// Dialer overrides the WebSocket dialer (tests, family fallback).
	Dialer DialFunc
}

// DialFunc dials a WebSocket to the control path on endpoint.
type DialFunc func(ctx context.Context, endpoint string) (*websocket.Conn, error)

// Operation is one inbound command delivered to OnCommand.
type Operation struct {
	OperationID string
	MessageID   string
	MessageType string
	Payload     []byte
}

// Client is one Agent control session loop.
type sessionIdentity struct {
	generation uint64
	conn       *websocket.Conn
	epoch      uint64
	session    string

	// inSeq belongs to this transport, not to Client. A stale frame handler can
	// remain in an application sink after its socket is replaced; keeping the
	// receive sequence on the immutable session identity prevents that old
	// handler from resetting or advancing the new session's sequence.
	inSeqMu sync.Mutex
	inSeq   uint64
}

type sessionWorkers struct {
	mu        sync.Mutex
	remaining int
	done      chan struct{}
}

func newSessionWorkers(count int) *sessionWorkers {
	return &sessionWorkers{remaining: count, done: make(chan struct{})}
}

func (w *sessionWorkers) complete() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.remaining <= 0 {
		return
	}
	w.remaining--
	if w.remaining == 0 {
		close(w.done)
	}
}

func (w *sessionWorkers) wait(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-w.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type Client struct {
	opts ClientOptions

	connectMu sync.Mutex
	mu        sync.Mutex
	conn      *websocket.Conn
	active    *sessionIdentity
	workers   *sessionWorkers
	writeMu   sync.Mutex
	wg        sync.WaitGroup
	// outSeq is the agent's outbound sequence (A2C).
	outSeq uint64
	// epoch/session are the ACTIVE session (persisted before activation).
	epoch   uint64
	session string
	// sessionGeneration changes for every successfully handshaken transport.
	// Transport goroutines retain their generation so an old connection cannot
	// tear down or write through a newer session after reconnect.
	sessionGeneration uint64

	closed        chan struct{}
	once          sync.Once
	sessionCancel context.CancelFunc
}

// NewClient validates the options and builds a client.
func NewClient(opts ClientOptions) (*Client, error) {
	if opts.Endpoint == "" {
		return nil, errors.New("control: client requires endpoint")
	}
	if opts.NodeID == "" {
		return nil, errors.New("control: client requires node id")
	}
	if opts.Store == nil {
		return nil, errors.New("control: client requires store")
	}
	if opts.Key == nil {
		return nil, errors.New("control: client requires node key")
	}
	if opts.Dialer == nil {
		opts.Dialer = defaultDialer
	}
	return &Client{opts: opts, closed: make(chan struct{})}, nil
}

// defaultDialer upgrades the controller endpoint to ws(s) and dials with the
// family-aware transport (A-only / AAAA-only / dual fallback, Story 6).
func defaultDialer(ctx context.Context, endpoint string) (*websocket.Conn, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("control: parse endpoint: %w", err)
	}
	scheme := "ws"
	if u.Scheme == "https" {
		scheme = "wss"
	}
	wsURL := scheme + "://" + u.Host + "/agent/v1/control"
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// The family policy applies to the TCP dial; the address here is
			// host:port from the WS URL.
			conn, _, err := DialEndpoint(ctx, "http://"+addr, net.DefaultResolver, 30*time.Second)
			return conn, err
		},
	}
	conn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPClient: &http.Client{Transport: transport, Timeout: 30 * time.Second},
	})
	if err != nil {
		return nil, fmt.Errorf("control: ws dial %s: %w", wsURL, err)
	}
	return conn, nil
}

// CloseContext terminates only the active transport session and waits for its
// workers, without allowing a stuck application callback to bypass ctx. The
// Client remains reusable for a later Connect; a later caller may retry the
// same close after a deadline.
func (c *Client) CloseContext(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	c.connectMu.Lock()
	c.stopSession(0, nil)
	workers := c.currentWorkers()
	c.connectMu.Unlock()
	if workers == nil {
		return nil
	}
	return workers.wait(ctx)
}

// Close terminates only the active transport session and waits for all of its
// workers to leave. The Client remains reusable for a later Connect.
func (c *Client) Close() {
	_ = c.CloseContext(context.Background())
}

// Shutdown permanently closes the Client and prevents further reconnects.
// App lifecycle teardown uses ShutdownContext so a blocked application callback
// cannot bypass the caller's shutdown deadline. Direct callers retain the
// historical blocking behavior through a background context.
func (c *Client) Shutdown() {
	_ = c.ShutdownContext(context.Background())
}

// ShutdownContext permanently closes the Client and waits for its current
// transport workers without holding up the caller past ctx's deadline. The
// transport is stopped before waiting, but the caller must not close resources
// used by callbacks when this returns a context error; those workers may still
// be running.
func (c *Client) ShutdownContext(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	c.connectMu.Lock()
	c.once.Do(func() {
		close(c.closed)
	})
	c.stopSession(0, nil)
	workers := c.currentWorkers()
	c.connectMu.Unlock()
	if workers == nil {
		return nil
	}
	return workers.wait(ctx)
}

func (c *Client) currentWorkers() *sessionWorkers {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.workers
}

func (c *Client) waitWorkers(ctx context.Context) error {
	if workers := c.currentWorkers(); workers != nil {
		return workers.wait(ctx)
	}
	return nil
}

// stopSession tears down only the current transport. A non-zero generation and
// connection identify a goroutine-owned transport; stale goroutines become
// no-ops once a later handshake has installed a new session.
func (c *Client) stopSession(generation uint64, ownedConn *websocket.Conn) {
	c.mu.Lock()
	if generation != 0 &&
		(c.sessionGeneration != generation || c.conn != ownedConn) {
		c.mu.Unlock()
		return
	}
	conn := c.conn
	c.conn = nil
	c.active = nil
	cancel := c.sessionCancel
	c.sessionCancel = nil
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if conn != nil {
		_ = conn.CloseNow()
	}
}

// Wait waits for all session goroutines started by Connect.
func (c *Client) Wait() { c.wg.Wait() }

// Connected reports whether a transport session is currently established
// (P14 uninstall notice bounded-receipt seam). It is advisory: a session may
// die between this check and the next send, which is exactly why the uninstall
// notice is bounded best-effort.
func (c *Client) Connected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn != nil
}

// SendMessage pushes an agent-initiated A2C message (P10 probe plane: the
// RCT1 probe_ingress_receipt). P08 declares that P10 consumes the control
// channel via interfaces; this is that outbound interface, the mirror of the
// controller-side ProbeSink. The message id is fresh per call and the frame
// is signed like any A2C envelope; callers must not use it for command
// results (those go through the durable outbox journal).
func (c *Client) SendMessage(ctx context.Context, messageType string, payload []byte) error {
	if c.opts.Store == nil {
		return errors.New("control: send message requires a store")
	}
	sum := sha256.Sum256(payload)
	messageID := security.MessageID(hex.EncodeToString(sum[:]), messageType)
	return c.writeEnvelope(ctx, messageID, messageType, payload)
}

// Connect establishes ONE session: dial, mutual-challenge handshake, epoch
// persistence BEFORE socket activation, then starts the inbound frame loop,
// the outbox pump, and heartbeats. It returns once the handshake completes.
func (c *Client) Connect(ctx context.Context) error {
	c.connectMu.Lock()
	defer c.connectMu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-c.closed:
		return errors.New("control: client is closed")
	default:
	}
	c.mu.Lock()
	if c.conn != nil || c.sessionCancel != nil {
		c.mu.Unlock()
		return errors.New("control: session already connected")
	}
	c.mu.Unlock()
	// Load the pinned controller key (the trust anchor from enrollment).
	pins, err := c.opts.Store.ListControllerPins()
	if err != nil {
		return fmt.Errorf("control: load pins: %w", err)
	}
	if len(pins) != 1 {
		return fmt.Errorf("control: expected exactly one pinned controller, found %d (enroll first)", len(pins))
	}
	pin := pins[0]

	conn, err := c.opts.Dialer(ctx, c.opts.Endpoint)
	if err != nil {
		return err
	}
	conn.SetReadLimit(maxEnvelopeBytes)
	epoch, session, err := c.handshake(ctx, conn, pin)
	if err != nil {
		_ = conn.CloseNow()
		return err
	}
	select {
	case <-c.closed:
		_ = conn.CloseNow()
		return errors.New("control: client is closed")
	default:
	}

	// Requeue any un-receipted outbox rows for the new session (semantic
	// resend) and start the pumps. Connect's context bounds only dialing and
	// the handshake; it must not cancel a successfully established session
	// when a caller used a startup timeout. A session context is cancelled on
	// transport failure; the terminal client channel is reserved for Shutdown.
	sessionCtx, sessionCancel := context.WithCancel(context.Background())
	workerCount := 2
	if c.opts.Heartbeat > 0 {
		workerCount++
	}
	workers := newSessionWorkers(workerCount)
	c.mu.Lock()
	c.sessionGeneration++
	generation := c.sessionGeneration
	identity := &sessionIdentity{
		generation: generation,
		conn:       conn,
		epoch:      epoch,
		session:    session,
	}
	// Keep the legacy fields for package-local diagnostics and compatibility;
	// transport workers use the immutable identity above.
	c.epoch = epoch
	c.session = session
	c.active = identity
	c.conn = conn
	c.sessionCancel = sessionCancel
	identity.inSeq = 0
	c.outSeq = 0
	c.mu.Unlock()
	if _, err := c.opts.Store.RequeueOutboxForSession(identity.epoch, identity.session); err != nil {
		c.stopSession(generation, conn)
		return fmt.Errorf("control: requeue outbox: %w", err)
	}
	c.mu.Lock()
	c.workers = workers
	c.mu.Unlock()
	c.wg.Add(workerCount)
	go func() {
		defer c.wg.Done()
		defer workers.complete()
		c.frameLoop(sessionCtx, identity)
	}()
	go func() {
		defer c.wg.Done()
		defer workers.complete()
		c.outboxPump(sessionCtx, identity)
	}()
	if c.opts.Heartbeat > 0 {
		go func() {
			defer c.wg.Done()
			defer workers.complete()
			c.heartbeatLoop(sessionCtx, identity)
		}()
	}
	return nil
}

// handshake runs hello -> welcome -> final. The agent verifies the welcome
// against the PINNED controller key and persists the granted epoch/session
// BEFORE sending the final (v0.8 §6.3: persist before socket activation).
func (c *Client) handshake(ctx context.Context, conn *websocket.Conn, pin localstate.ControllerPin) (uint64, string, error) {
	curEpoch, curSession, err := c.opts.Store.CurrentSession()
	if err != nil {
		return 0, "", fmt.Errorf("control: current session: %w", err)
	}
	instance := [16]byte{}
	if b, err := hex.DecodeString(pin.InstanceID); err == nil && len(b) == 16 {
		copy(instance[:], b)
	}
	var node [16]byte
	copy(node[:], c.opts.NodeID)
	var nonce [security.SessionNonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return 0, "", err
	}
	hello := security.SessionHello{
		ControllerInstanceID: instance,
		NodeID:               node,
		AgentCredentialVer:   c.opts.Key.CredentialVersion(),
		AgentPublicKey:       [32]byte(c.opts.Key.PublicKey()),
		AgentNonce:           nonce,
		AgentMaxEpoch:        curEpoch,
		ProtocolVersions:     "1",
	}
	sig, err := hello.Sign(c.opts.Key.PrivateKey())
	if err != nil {
		return 0, "", err
	}
	if err := conn.Write(ctx, websocket.MessageBinary, append(hello.Canonical(), sig...)); err != nil {
		return 0, "", fmt.Errorf("control: write hello: %w", err)
	}

	_, rawWelcome, err := conn.Read(ctx)
	if err != nil {
		return 0, "", fmt.Errorf("control: read welcome: %w", err)
	}
	welcome, err := security.ParseSessionWelcome(rawWelcome, pin.PublicKey())
	if err != nil {
		return 0, "", fmt.Errorf("control: verify welcome: %w (wrong pinned controller?)", err)
	}
	if welcome.ControllerInstanceID != instance {
		return 0, "", errors.New("control: welcome from a different controller instance")
	}
	if welcome.ControllerKeyID != pin.KeyID {
		return 0, "", errors.New("control: welcome key id does not match the pinned key")
	}
	if welcome.ConnectionEpoch < curEpoch {
		return 0, "", fmt.Errorf("control: welcome epoch %d below accepted %d (downgrade)", welcome.ConnectionEpoch, curEpoch)
	}
	if curSession != "" && welcome.ConnectionEpoch == curEpoch && welcome.SessionID != curSession {
		return 0, "", errors.New("control: same-epoch welcome with a different session (split brain)")
	}

	// PERSIST before activation (v0.8 §6.3).
	if err := c.opts.Store.AdvanceSession(welcome.ConnectionEpoch, welcome.SessionID); err != nil {
		return 0, "", fmt.Errorf("control: persist epoch: %w", err)
	}
	if err := c.opts.Store.RecoverApplyingOperations(welcome.ConnectionEpoch, welcome.SessionID); err != nil {
		return 0, "", fmt.Errorf("control: recover applying operations: %w", err)
	}

	final := security.SessionFinal{
		ControllerInstanceID: welcome.ControllerInstanceID,
		NodeID:               node,
		ServerNonce:          welcome.ServerNonce,
		ConnectionEpoch:      welcome.ConnectionEpoch,
		SessionID:            welcome.SessionID,
	}
	fsig, err := final.Sign(c.opts.Key.PrivateKey())
	if err != nil {
		return 0, "", err
	}
	if err := conn.Write(ctx, websocket.MessageBinary, append(final.Canonical(), fsig...)); err != nil {
		return 0, "", fmt.Errorf("control: write final: %w", err)
	}
	return welcome.ConnectionEpoch, welcome.SessionID, nil
}

// frameLoop reads C2A envelopes until the session dies. Any verification
// failure closes the session (fail closed).
func (c *Client) frameLoop(ctx context.Context, identity *sessionIdentity) {
	for {
		readCtx, cancel := context.WithTimeout(ctx, sessionIdleTimeout)
		_, frame, err := identity.conn.Read(readCtx)
		cancel()
		if err != nil {
			c.stopSession(identity.generation, identity.conn)
			return
		}
		if err := c.handleInboundFrameOnSession(ctx, identity, frame); err != nil {
			c.stopSession(identity.generation, identity.conn)
			return
		}
	}
}

// handleInboundFrame verifies and dispatches one C2A envelope using the
// currently active session. Production workers call the session-bound variant.
func (c *Client) handleInboundFrame(ctx context.Context, frame []byte) error {
	c.mu.Lock()
	identity := c.active
	if identity == nil && (c.epoch != 0 || c.session != "") {
		// Package-local protocol tests may seed the legacy diagnostic fields
		// without installing a socket. Production workers always pass the
		// immutable identity directly.
		identity = &sessionIdentity{epoch: c.epoch, session: c.session}
	}
	c.mu.Unlock()
	if identity == nil {
		return errors.New("control: session is not connected")
	}
	return c.handleInboundFrameOnSession(ctx, identity, frame)
}

func (c *Client) handleInboundFrameOnSession(ctx context.Context, identity *sessionIdentity, frame []byte) error {
	pins, err := c.opts.Store.ListControllerPins()
	if err != nil || len(pins) != 1 {
		return errors.New("control: pinned controller lost")
	}
	env, stage, err := protocol.ParseEnvelope(frame, pins[0].PublicKey())
	if err != nil {
		return fmt.Errorf("control: envelope rejected at %s: %w", stage, err)
	}
	hdr := env.Header
	if hdr.Direction != protocol.DirectionC2A {
		return errors.New("control: wrong direction: expected C2A")
	}
	if hdr.ConnectionEpoch != identity.epoch || hdr.SessionID != identity.session {
		return errors.New("control: stale epoch/session in frame")
	}
	identity.inSeqMu.Lock()
	expectedSeq := identity.inSeq + 1
	if hdr.Sequence != expectedSeq {
		identity.inSeqMu.Unlock()
		return fmt.Errorf("control: sequence %d, want %d", hdr.Sequence, expectedSeq)
	}
	identity.inSeq = hdr.Sequence
	identity.inSeqMu.Unlock()

	switch hdr.MessageType {
	case "desired", "forward_delete", "node_decommission", "probe_arm", "probe_outcome",
		// P14 Story 4/5 lifecycle commands route to the same durable command
		// path (repair-1 H1). Before the fix they hit the default arm below and
		// tore the session down, leaving the Agent-side App.handlers unreachable
		// over the control transport.
		"key_rotation_prepare", "key_rotation_commit", "restore_reconcile", "restore_result":
		return c.handleCommandOnSession(ctx, identity, env)
	case "message_receipt":
		return c.handleReceiptOnSession(ctx, identity, env)
	case "heartbeat", "status":
		return nil
	default:
		return fmt.Errorf("control: unexpected message type %q", hdr.MessageType)
	}
}

// handleCommand journals the command through the inbox FSM and delivers it to
// OnCommand (the P10 reconcile extension point). The semantic result is
// queued to the outbox; a handler error NACKs the operation and queues the
// nack payload so the controller still learns the outcome.
func (c *Client) handleCommand(ctx context.Context, env protocol.Envelope) error {
	c.mu.Lock()
	identity := c.active
	c.mu.Unlock()
	if identity == nil {
		return errors.New("control: session is not connected")
	}
	return c.handleCommandOnSession(ctx, identity, env)
}

func (c *Client) handleCommandOnSession(ctx context.Context, identity *sessionIdentity, env protocol.Envelope) error {
	hdr := env.Header
	msgID := hex.EncodeToString(hdr.MessageID[:])

	// Payload-aware receive: the generic command identity C (msgID) journals
	// the command, while desired/forward_delete payloads additionally persist
	// their deletion classification and the durable pending delete fence in
	// the same transaction. The semantic deletion identity D stays separate -
	// dedicated delete results are queued under D by the reconcile layer, not
	// under C.
	dup, recoveredDeletionPending, err := c.opts.Store.ReceiveCommandWithPayloadStatus(identity.epoch, identity.session, msgID, msgID, hdr.MessageType, env.Payload, hdr.MessageType)
	if err != nil {
		return err
	}
	if dup {
		phase, found, err := c.opts.Store.OperationPhase(msgID)
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("control: duplicate command %q has no operation journal", msgID)
		}
		switch phase {
		case "APPLIED":
			// CompleteOperation atomically records the result and queues it.
			// A missing outbox row means the durable state is inconsistent;
			// fail closed rather than invoking the side effect again.
			if _, present, err := c.opts.Store.OutboxState(msgID); err != nil {
				return err
			} else if !present {
				return fmt.Errorf("control: applied duplicate command %q has no queued result", msgID)
			}
			return nil
		case "NACKED":
			if recoveredDeletionPending {
				if c.opts.OnRecoveredDeletion == nil {
					return fmt.Errorf("control: recovered deletion %q has no convergence handler", msgID)
				}
				if err := c.opts.OnRecoveredDeletion(ctx, Operation{
					OperationID: msgID,
					MessageID:   msgID,
					MessageType: hdr.MessageType,
					Payload:     env.Payload,
				}); err != nil {
					return err
				}
				if err := c.opts.Store.CompleteRecoveredDeletion(identity.epoch, identity.session, msgID); err != nil {
					return err
				}
			}
			return c.opts.Store.QueueNackedResult(identity.epoch, identity.session, msgID)
		case "APPLYING":
			// An APPLYING operation may already have performed an external side
			// effect. Never invoke OnCommand a second time. A legacy deletion row
			// becomes retryable only after exact redelivery atomically backfills its
			// payload and fences; keep C APPLYING until bounded cleanup succeeds.
			if recoveredDeletionPending {
				if c.opts.OnRecoveredDeletion == nil {
					return fmt.Errorf("control: recovered deletion %q has no convergence handler", msgID)
				}
				if err := c.opts.OnRecoveredDeletion(ctx, Operation{
					OperationID: msgID,
					MessageID:   msgID,
					MessageType: hdr.MessageType,
					Payload:     env.Payload,
				}); err != nil {
					return err
				}
				if err := c.opts.Store.CompleteRecoveredDeletion(identity.epoch, identity.session, msgID); err != nil {
					return err
				}
			}
			if err := c.opts.Store.RecoverApplyingOperations(identity.epoch, identity.session); err != nil {
				return err
			}
			return nil
		case "RECEIVED":
			// ReceiveCommand is atomic with the RECEIVED journal. No external
			// side effect is allowed before the next transition, so the replay
			// may safely resume the normal pipeline below.
		case "INTENT_PERSISTED":
			// Intent persistence precedes every external side effect; resume at
			// APPLYING rather than losing the redelivered command.
		default:
			return fmt.Errorf("control: duplicate command %q has unknown phase %q", msgID, phase)
		}
	}
	if phase, found, err := c.opts.Store.OperationPhase(msgID); err != nil {
		return err
	} else if found {
		switch phase {
		case "RECEIVED":
			if err := c.opts.Store.PersistOperationIntent(identity.epoch, identity.session, msgID); err != nil {
				return err
			}
		case "INTENT_PERSISTED":
			// Continue below.
		default:
			return fmt.Errorf("control: command %q is not applyable from phase %q", msgID, phase)
		}
	} else {
		return fmt.Errorf("control: command %q has no operation journal", msgID)
	}
	if err := c.opts.Store.MarkOperationApplying(identity.epoch, identity.session, msgID); err != nil {
		return err
	}

	var result []byte
	var applyErr error
	if c.opts.OnCommand != nil {
		result, applyErr = c.opts.OnCommand(ctx, Operation{
			OperationID: msgID,
			MessageID:   msgID,
			MessageType: hdr.MessageType,
			Payload:     env.Payload,
		})
	}
	if applyErr != nil {
		nackPayload, _ := json.Marshal(map[string]any{"status": "nacked", "reason": applyErr.Error()})
		return c.opts.Store.NackOperationWithResult(identity.epoch, identity.session, msgID, applyErr.Error(), nackPayload)
	}
	if result == nil {
		result = []byte(`{"status":"applied"}`)
	}
	return c.opts.Store.CompleteOperation(identity.epoch, identity.session, msgID, result)
}

// handleReceipt applies the controller's durable receipt using the active
// transport identity. The wrapper is retained for package-local callers.
func (c *Client) handleReceipt(ctx context.Context, env protocol.Envelope) error {
	c.mu.Lock()
	identity := c.active
	c.mu.Unlock()
	if identity == nil {
		return errors.New("control: session is not connected")
	}
	return c.handleReceiptOnSession(ctx, identity, env)
}

// handleReceiptOnSession applies the controller's durable receipt for one of
// the agent's outbox results: the receipt both semantically acks and durably
// receipts the row (the controller persists the result before sending it).
// On reconnect the receipt can beat the agent's own pump, so a PENDING row is
// advanced legally before the ack.
func (c *Client) handleReceiptOnSession(ctx context.Context, identity *sessionIdentity, env protocol.Envelope) error {
	var v struct {
		OperationID string `json:"operation_id"`
	}
	if err := protocol.DecodeStrictJSONInto(env.Payload, &v); err != nil || v.OperationID == "" {
		return errors.New("control: malformed receipt payload")
	}
	op := v.OperationID
	state, present, err := c.opts.Store.OutboxState(op)
	if err != nil {
		return err
	}
	if !present {
		if c.opts.OnReceipt == nil {
			return nil // already GC'd (idempotent redelivery)
		}
		return c.opts.OnReceipt(ctx, op)
	}
	switch state {
	case "PENDING":
		if err := c.opts.Store.ClaimOutbox(identity.epoch, identity.session, op); err != nil {
			if errors.Is(err, localstate.ErrIllegalPhase) {
				return nil
			}
			return err
		}
		if err := c.opts.Store.MarkOutboxSent(identity.epoch, identity.session, op); err != nil {
			return err
		}
	case "CLAIMED":
		if err := c.opts.Store.MarkOutboxSent(identity.epoch, identity.session, op); err != nil {
			return err
		}
	case "SENT", "SEMANTIC_ACKED":
		// already sent; ack below is idempotent for SEMANTIC_ACKED
	default:
		return nil
	}
	if err := c.opts.Store.AcceptSemanticACK(identity.epoch, identity.session, op); err != nil {
		if errors.Is(err, localstate.ErrIllegalPhase) {
			return nil // already receipted/GC'd (idempotent redelivery)
		}
		return err
	}
	if err := c.opts.Store.AcceptReceipt(identity.epoch, identity.session, op); err != nil {
		if errors.Is(err, localstate.ErrAlreadyReceipted) {
			return nil
		}
		return err
	}
	return nil
}

// writeEnvelope signs and writes one A2C envelope with the next sequence.
// Agent-initiated sends use the currently active transport.
func (c *Client) writeEnvelope(ctx context.Context, messageID [16]byte, messageType string, payload []byte) error {
	c.mu.Lock()
	identity := c.active
	if identity == nil || identity.generation == 0 || identity.conn == nil {
		c.mu.Unlock()
		return errors.New("control: session is not connected")
	}
	generation, conn := identity.generation, identity.conn
	c.mu.Unlock()
	return c.writeEnvelopeOnSession(ctx, generation, conn, messageID, messageType, payload)
}

// writeEnvelopeOnSession binds a transport-owned send to its connection
// generation. A stale pump or heartbeat must not write a frame using the
// newer session's epoch/session, nor consume the newer session's sequence.
// Sequence reservation happens only after trust-header lookup and envelope
// construction succeed; failed local preparation therefore cannot create a
// sequence gap in an otherwise-live session.
func (c *Client) writeEnvelopeOnSession(ctx context.Context, generation uint64, ownedConn *websocket.Conn, messageID [16]byte, messageType string, payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	c.mu.Lock()
	if generation != 0 && (c.sessionGeneration != generation || c.conn != ownedConn) {
		c.mu.Unlock()
		return errors.New("control: stale session transport")
	}
	identity := c.active
	if generation != 0 && identity != nil && identity.generation != generation {
		c.mu.Unlock()
		return errors.New("control: stale session transport")
	}
	conn := c.conn
	epoch := c.epoch
	session := c.session
	if identity != nil {
		epoch = identity.epoch
		session = identity.session
	}
	if generation != 0 {
		conn = ownedConn
	}
	if conn == nil {
		c.mu.Unlock()
		return errors.New("control: session is not connected")
	}
	seq := c.outSeq + 1
	c.mu.Unlock()

	pins, err := c.opts.Store.ListControllerPins()
	if err != nil {
		return fmt.Errorf("control: load controller pin for envelope: %w", err)
	}
	if len(pins) != 1 {
		return fmt.Errorf("control: expected exactly one pinned controller, found %d", len(pins))
	}
	var instance [16]byte
	if b, err := hex.DecodeString(pins[0].InstanceID); err != nil || len(b) != 16 {
		return errors.New("control: pinned controller instance id is invalid")
	} else {
		copy(instance[:], b)
	}
	var node [16]byte
	copy(node[:], c.opts.NodeID)
	header := protocol.ProtectedHeader{
		ProtocolDomain:       protocol.ProtocolDomain,
		ControllerInstanceID: instance,
		NodeID:               node,
		ControllerKeyID:      pins[0].KeyID,
		AgentCredentialVer:   c.opts.Key.CredentialVersion(),
		ConnectionEpoch:      epoch,
		SessionID:            session,
		Direction:            protocol.DirectionA2C,
		Sequence:             seq,
		MessageID:            messageID,
		MessageType:          messageType,
		SchemaVersion:        1,
	}
	frame, err := protocol.BuildEnvelope(c.opts.Key.PrivateKey(), header, payload)
	if err != nil {
		return fmt.Errorf("control: build envelope: %w", err)
	}

	// writeMu still excludes every other writer, so reserve exactly this
	// sequence immediately before the owned connection write. A failed socket
	// write tears down this generation; local preparation failures above do not.
	c.mu.Lock()
	if generation != 0 && (c.sessionGeneration != generation || c.conn != ownedConn) {
		c.mu.Unlock()
		return errors.New("control: stale session transport")
	}
	if c.outSeq+1 != seq {
		c.mu.Unlock()
		return errors.New("control: outbound sequence changed during envelope preparation")
	}
	c.outSeq = seq
	c.mu.Unlock()
	return conn.Write(ctx, websocket.MessageBinary, frame)
}

// outboxPump claims queued results and sends them as A2C operation_complete
// envelopes; each result is followed by a message_receipt for the command it
// answers so the controller can GC its outbox row.
func (c *Client) outboxPump(ctx context.Context, identity *sessionIdentity) {
	ticker := time.NewTicker(outboxPumpInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.closed:
			return
		case <-ticker.C:
			if err := c.pumpOnce(ctx, identity); err != nil {
				c.stopSession(identity.generation, identity.conn)
				return
			}
		}
	}
}

func (c *Client) pumpOnce(ctx context.Context, identity *sessionIdentity) error {
	const pageSize = 256
	lastKey := ""
	for {
		ids, err := c.opts.Store.OutboxOperationIDsAfter(lastKey, pageSize)
		if err != nil {
			return err
		}
		if len(ids) == 0 {
			return nil
		}
		for _, op := range ids {
			lastKey = op
			state, present, err := c.opts.Store.OutboxState(op)
			if err != nil || !present {
				continue
			}
			if state != "PENDING" {
				continue
			}
			result, err := c.opts.Store.ResultForOperation(identity.epoch, identity.session, op)
			if err != nil {
				continue // receipted concurrently
			}
			if err := c.opts.Store.ClaimOutbox(identity.epoch, identity.session, op); err != nil {
				if errors.Is(err, localstate.ErrIllegalPhase) {
					continue // racing receipt already advanced/GC'd the row
				}
				return err
			}
			// Result envelope: deterministic message id (resend dedup).
			msgID := security.MessageID(op, "operation_complete")
			if err := c.writeEnvelopeOnSession(ctx, identity.generation, identity.conn, msgID, "operation_complete", result); err != nil {
				return err
			}
			// A racing receipt may have advanced the row (SEMANTIC_ACKED/GC);
			// tolerate the transition loss, but still send the Agent receipt. The
			// controller's receipt proves the semantic result is durable; the Agent
			// receipt is the independent proof that lets the controller GC its row.
			if err := c.opts.Store.MarkOutboxSent(identity.epoch, identity.session, op); err != nil &&
				!errors.Is(err, localstate.ErrIllegalPhase) &&
				!errors.Is(err, localstate.ErrAlreadyReceipted) {
				return err
			}
			// Durable receipt for the answered command so the controller can GC
			// its outbox row (the controller correlates via the receipt's
			// operation_id = the command message id hex).
			receiptID := security.MessageID(op, "message_receipt")
			payload := []byte(fmt.Sprintf(`{"operation_id":%q}`, op))
			if err := c.writeEnvelopeOnSession(ctx, identity.generation, identity.conn, receiptID, "message_receipt", payload); err != nil {
				return err
			}
		}
		if len(ids) < pageSize {
			return nil
		}
	}
}

// heartbeatLoop sends A2C heartbeat envelopes.
func (c *Client) heartbeatLoop(ctx context.Context, identity *sessionIdentity) {
	ticker := time.NewTicker(c.opts.Heartbeat)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.closed:
			return
		case <-ticker.C:
			var msgID [16]byte
			if _, err := rand.Read(msgID[:]); err != nil {
				c.stopSession(identity.generation, identity.conn)
				return
			}
			if err := c.writeEnvelopeOnSession(ctx, identity.generation, identity.conn, msgID, "heartbeat", []byte(`{}`)); err != nil {
				c.stopSession(identity.generation, identity.conn)
				return
			}
		}
	}
}
