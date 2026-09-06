// STUN over TCP framing and persistent client (RFC 8489 §6.2.2). A STUN-only
// TCP connection needs no additional framing: the 20-byte header's length
// field delimits each message, so the frame reader tolerates partial
// header/body reads, rejects oversize declarations, and surfaces disconnect
// and timeout distinctly. There is no STUN-layer retransmission over TCP;
// one request is sent per transaction and the client waits Ti (default
// 39.5 s) for the response. A connection reset or EOF before the response
// fails the transaction and invalidates the mapping candidate (v0.8 §3.5),
// signaled through the Disconnected channel. The connection stays open for
// multiple transactions and pipelined requests are demultiplexed by
// transaction ID.
package stun

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// DefaultTi is the default transaction timeout over TCP (RFC 8489 §6.2.2).
const DefaultTi = 39500 * time.Millisecond

// TCP client sentinel errors.
var (
	ErrDisconnected = errors.New("stun: TCP connection lost before response")
	ErrTCPClosed    = errors.New("stun: TCP client is closed")
)

// TCPClientOptions tunes the persistent TCP client.
type TCPClientOptions struct {
	Timeout        time.Duration // per-transaction deadline Ti; default 39.5 s
	MaxMessageSize int           // frame size bound; default 65535
}

func (o TCPClientOptions) withDefaults() TCPClientOptions {
	if o.Timeout <= 0 {
		o.Timeout = DefaultTi
	}
	if o.MaxMessageSize <= 0 {
		o.MaxMessageSize = MaxMessageSize
	}
	return o
}

// TCPClient is a persistent STUN-over-TCP transport. Exactly one reader
// goroutine demultiplexes frames to waiters; writers are serialized so
// pipelined frames never interleave.
type TCPClient struct {
	conn net.Conn
	opts TCPClientOptions

	writeMu sync.Mutex
	mu      sync.Mutex
	waiters map[TransactionID]*waiter
	// disconnected is closed exactly once when the transport is dead.
	disconnected chan struct{}
	closeOnce    sync.Once
	closed       bool
}

// DialTCP opens a persistent STUN TCP connection.
func DialTCP(ctx context.Context, address string, opts TCPClientOptions) (*TCPClient, error) {
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp4", address)
	if err != nil {
		return nil, err
	}
	client := &TCPClient{
		conn:         conn,
		opts:         opts.withDefaults(),
		waiters:      make(map[TransactionID]*waiter),
		disconnected: make(chan struct{}),
	}
	go client.readerLoop()
	return client, nil
}

// Disconnected is closed when the TCP connection is lost (EOF, reset, or an
// unrecoverable framing error), which invalidates any mapping learned over
// this transport (v0.8 §3.5).
func (c *TCPClient) Disconnected() <-chan struct{} {
	return c.disconnected
}

// Close tears the transport down. Pending waiters fail with ErrDisconnected.
func (c *TCPClient) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		c.conn.Close()
	})
	return nil
}

// Exchange sends one request frame and waits for the matching response with
// deadline Ti. It never retransmits at the STUN layer (RFC 8489 §6.2.2).
// A response is accepted only when its transaction ID matches the request;
// late responses for timed-out transactions are dropped.
func (c *TCPClient) Exchange(ctx context.Context, req *Message) (*Message, error) {
	if req.Type.Class() != ClassRequest {
		return nil, ErrNotARequest
	}
	wire, err := req.Marshal()
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	select {
	case <-c.disconnected:
		c.mu.Unlock()
		return nil, ErrDisconnected
	default:
	}
	if c.closed {
		c.mu.Unlock()
		return nil, ErrTCPClosed
	}
	// TCP demux keys on transaction ID only: the connection itself is the
	// exact server tuple (RFC 8489 §6.2.2).
	w := &waiter{
		method: req.Type.Method(),
		ch:     make(chan *Message, 1),
		done:   make(chan struct{}),
	}
	c.waiters[req.TransactionID] = w
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.waiters, req.TransactionID)
		c.mu.Unlock()
	}()

	if err := c.writeFrame(wire); err != nil {
		return nil, err
	}
	return waitResponse(ctx, w, c.opts.Timeout)
}

// SendIndication writes an indication frame (fire-and-forget, no response,
// no retransmission). Used for TCP keepalive indications.
func (c *TCPClient) SendIndication(indication *Message) error {
	if indication.Type.Class() != ClassIndication {
		return ErrNotARequest
	}
	wire, err := indication.Marshal()
	if err != nil {
		return err
	}
	return c.writeFrame(wire)
}

// writeFrame serializes concurrent writers so frames never interleave on the
// wire. A failed write kills the transport and signals Disconnected.
func (c *TCPClient) writeFrame(wire []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	select {
	case <-c.disconnected:
		return ErrDisconnected
	default:
	}
	if _, err := c.conn.Write(wire); err != nil {
		c.transportDead(err)
		return ErrDisconnected
	}
	return nil
}

// readerLoop reads frames until the connection fails. Each frame is routed
// to the waiter with the matching transaction ID; frames with unknown
// transaction IDs (late responses, unsolicited indications) are dropped.
func (c *TCPClient) readerLoop() {
	for {
		msg, err := readFrame(c.conn, c.opts.MaxMessageSize)
		if err != nil {
			c.transportDead(err)
			return
		}
		class := msg.Type.Class()
		if class != ClassSuccess && class != ClassError {
			continue // not a response; drop (e.g. an unsolicited indication)
		}
		c.mu.Lock()
		w, ok := c.waiters[msg.TransactionID]
		if ok && w.method == msg.Type.Method() {
			select {
			case w.ch <- msg:
			default:
			}
		} else {
		}
		c.mu.Unlock()
	}
}

// transportDead fails every pending waiter with the underlying cause
// (ErrDisconnected for network loss, ErrOversize/ErrMalformed/ErrBadCookie
// for protocol violations) and closes Disconnected exactly once.
func (c *TCPClient) transportDead(cause error) {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		waiters := make([]*waiter, 0, len(c.waiters))
		for _, w := range c.waiters {
			waiters = append(waiters, w)
		}
		c.mu.Unlock()
		failure := cause
		if !errors.Is(failure, ErrOversize) && !errors.Is(failure, ErrMalformed) && !errors.Is(failure, ErrBadCookie) {
			failure = ErrDisconnected
		}
		for _, w := range waiters {
			w.fail(failure)
		}
		close(c.disconnected)
		c.conn.Close()
	})
}

// readFrame reads one STUN message from r: the exact 20-byte header, then
// the length-declared body, tolerating partial reads. Oversize declarations
// (beyond max) and non-multiple-of-4 lengths are rejected before any body
// allocation. Disconnect mid-frame returns ErrDisconnected.
func readFrame(r io.Reader, max int) (*Message, error) {
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, ErrDisconnected
		}
		return nil, err
	}
	if binary.BigEndian.Uint32(header[4:8]) != MagicCookie {
		return nil, ErrBadCookie
	}
	declared := int(binary.BigEndian.Uint16(header[2:4]))
	if declared > max {
		return nil, ErrOversize
	}
	if declared%4 != 0 {
		return nil, ErrMalformed
	}
	frame := make([]byte, HeaderSize+declared)
	copy(frame, header)
	if _, err := io.ReadFull(r, frame[HeaderSize:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, ErrDisconnected
		}
		return nil, err
	}
	return ParseMessage(frame)
}
