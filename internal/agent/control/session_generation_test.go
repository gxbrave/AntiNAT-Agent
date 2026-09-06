package control

import (
	"context"
	"testing"

	"github.com/coder/websocket"
)

func TestWriteEnvelopeCapturesActiveTransportGeneration(t *testing.T) {
	client := &Client{}
	if err := client.writeEnvelope(context.Background(), [16]byte{}, "heartbeat", []byte(`{}`)); err == nil {
		t.Fatal("generic write unexpectedly succeeded without an active session")
	}

	client.active = &sessionIdentity{generation: 9, conn: &websocket.Conn{}}
	client.conn = &websocket.Conn{}
	client.sessionGeneration = 10
	if err := client.writeEnvelope(context.Background(), [16]byte{}, "heartbeat", []byte(`{}`)); err == nil {
		t.Fatal("generic write unexpectedly used a stale captured connection")
	}
	if client.outSeq != 0 {
		t.Fatalf("stale generic write consumed sequence %d", client.outSeq)
	}
}

func TestStopSessionIgnoresStaleTransportGeneration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := &Client{
		conn:              nil,
		sessionCancel:     cancel,
		sessionGeneration: 2,
	}

	client.stopSession(1, nil)
	select {
	case <-ctx.Done():
		t.Fatal("stale transport canceled the current session")
	default:
	}
	if client.sessionCancel == nil {
		t.Fatal("stale transport cleared the current session cancel function")
	}

	if err := client.writeEnvelopeOnSession(
		context.Background(), 1, nil, [16]byte{}, "heartbeat", []byte(`{}`),
	); err == nil {
		t.Fatal("stale transport write unexpectedly succeeded")
	}
	if client.outSeq != 0 {
		t.Fatalf("stale transport consumed current sequence: %d", client.outSeq)
	}
}

func TestStopSessionClearsOwnedTransport(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	client := &Client{
		sessionCancel:     cancel,
		sessionGeneration: 3,
	}
	client.stopSession(3, (*websocket.Conn)(nil))
	select {
	case <-ctx.Done():
	default:
		t.Fatal("owned transport did not cancel its session")
	}
	if client.sessionCancel != nil {
		t.Fatal("owned transport cancel function was retained")
	}
}

func TestStopSessionRejectsSameGenerationDifferentConnection(t *testing.T) {
	oldCtx, oldCancel := context.WithCancel(context.Background())
	newCtx, newCancel := context.WithCancel(context.Background())
	oldConn := &websocket.Conn{}
	newConn := &websocket.Conn{}
	client := &Client{
		conn:              newConn,
		sessionCancel:     newCancel,
		sessionGeneration: 7,
	}

	client.stopSession(7, oldConn)

	select {
	case <-oldCtx.Done():
		t.Fatal("stale transport unexpectedly canceled the old context")
	default:
	}
	select {
	case <-newCtx.Done():
		t.Fatal("same-generation stale connection canceled the active session")
	default:
	}
	if client.conn != newConn {
		t.Fatal("same-generation stale connection replaced the active connection")
	}
	if client.sessionCancel == nil {
		t.Fatal("same-generation stale connection cleared the active cancel function")
	}
	oldCancel()
}
