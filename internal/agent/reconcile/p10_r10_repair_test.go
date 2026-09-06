package reconcile

import (
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
)

func TestRestartRecoversConsumedReplayFencesBeyondOnePage(t *testing.T) {
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Unix(10_000, 0)
	var target protocol.ProbeArm
	for i := 0; i < 513; i++ {
		arm := protocol.ProbeArm{Endpoint: "198.51.100.7:8080", TTLMS: 60_000}
		arm.ProbeID[14] = byte(i >> 8)
		arm.ProbeID[15] = byte(i)
		arm.ExpectedSourceIP = [4]byte{198, 51, 100, byte((i % 254) + 1)}
		if i == 512 {
			arm.ExpectedSourceIP = [4]byte{203, 0, 113, 9}
		}
		if i == 512 {
			target = arm
		}
		if err := st.SaveArmedProbeForForward(arm, "forward-replay", now.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		if err := st.MarkArmedProbeConsumedWithReceipt(arm.ProbeID, []byte("receipt"), "operation-replay", now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}

	m := NewProbeManager(ProbeManagerOptions{
		Store:               st,
		Clock:               func() time.Time { return now },
		MaxActiveOperations: 2,
	})
	if !m.hasArmedBySource(target.ExpectedSourceIP, "forward-replay") {
		t.Fatalf("consumed replay fence %s was not recovered beyond the first page", hex.EncodeToString(target.ExpectedSourceIP[:]))
	}
}

func TestRestartFailsClosedWhenWallClockRollsBackBeforeArm(t *testing.T) {
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	arm := protocol.ProbeArm{Endpoint: "198.51.100.7:8080", TTLMS: 60_000}
	arm.ProbeID[15] = 1
	arm.ExpectedSourceIP = [4]byte{198, 51, 100, 8}
	started := time.Unix(20_000, 0)
	if err := st.SaveArmedProbeForForward(arm, "forward-clock", started.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	m := NewProbeManager(ProbeManagerOptions{
		Store: st,
		Clock: func() time.Time { return started.Add(-time.Second) },
	})
	if m.hasArmedBySource(arm.ExpectedSourceIP, "forward-clock") {
		t.Fatal("clock rollback before persisted arm time revived the probe; restart must fail closed")
	}
}

func TestRestartRecoveryHonorsActiveAndReplayBounds(t *testing.T) {
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Unix(30_000, 0)
	for i := byte(1); i <= 4; i++ {
		arm := protocol.ProbeArm{Endpoint: "198.51.100.7:8080", TTLMS: 60_000}
		arm.ProbeID[15] = i
		arm.ExpectedSourceIP = [4]byte{198, 51, 100, i}
		if err := st.SaveArmedProbeForForward(arm, "forward-active", now.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	for i := byte(11); i <= 14; i++ {
		arm := protocol.ProbeArm{Endpoint: "198.51.100.7:8080", TTLMS: 60_000}
		arm.ProbeID[15] = i
		arm.ExpectedSourceIP = [4]byte{203, 0, 113, i}
		if err := st.SaveArmedProbeForForward(arm, "forward-replay", now.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		if err := st.MarkArmedProbeConsumedWithReceipt(arm.ProbeID, []byte{byte(i)}, "receipt-"+hex.EncodeToString([]byte{i}), now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}

	m := NewProbeManager(ProbeManagerOptions{
		Store:               st,
		Clock:               func() time.Time { return now },
		MaxActiveOperations: 2,
		MaxReplayEntries:    1,
	})
	if got := len(m.ops); got > 2 {
		t.Fatalf("recovered active operations = %d, want at most 2", got)
	}
	if got := len(m.replay); got > 1 {
		t.Fatalf("recovered replay fences = %d, want at most 1", got)
	}
}

func TestTerminalMarkerDoesNotRecoverDurableProbeOperations(t *testing.T) {
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Unix(45_000, 0)
	arm := protocol.ProbeArm{Endpoint: "198.51.100.7:8080", TTLMS: 60_000}
	arm.ProbeID[15] = 6
	arm.ExpectedSourceIP = [4]byte{198, 51, 100, 6}
	if err := st.SaveArmedProbeForForward(arm, "forward-terminal", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	manager := NewProbeManager(ProbeManagerOptions{Store: st, Marker: localstate.MarkerDecommissioning, Clock: func() time.Time { return now }})
	if manager.hasArmedBySource(arm.ExpectedSourceIP, "forward-terminal") {
		t.Fatal("terminal-marker manager recovered an active probe")
	}
	manager.mu.Lock()
	if len(manager.ops) != 0 || len(manager.replay) != 0 {
		t.Fatalf("terminal-marker manager recovered ops=%d replay=%d", len(manager.ops), len(manager.replay))
	}
	manager.mu.Unlock()
}

func TestRestartQuarantinesConsumedFenceAcrossWallClockRollback(t *testing.T) {
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	arm := protocol.ProbeArm{Endpoint: "198.51.100.7:8080", TTLMS: 60_000}
	arm.ProbeID[15] = 7
	arm.ExpectedSourceIP = [4]byte{203, 0, 113, 7}
	started := time.Unix(40_000, 0)
	if err := st.SaveArmedProbeForForward(arm, "forward-quarantine", started.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkArmedProbeConsumedWithReceipt(arm.ProbeID, []byte("receipt"), "receipt-quarantine", started.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	_ = NewProbeManager(ProbeManagerOptions{
		Store: st,
		Clock: func() time.Time { return started.Add(-time.Second) },
	})
	recovered, found, err := st.LoadArmedProbe(arm.ProbeID)
	if err != nil {
		t.Fatal(err)
	}
	if !found || !recovered.Consumed {
		t.Fatalf("consumed fence after clock rollback = found %v record %+v, want durable consumed quarantine", found, recovered)
	}
	if err := st.SaveArmedProbeForForward(arm, "forward-quarantine", started.Add(time.Minute)); !errors.Is(err, localstate.ErrProbeConsumed) {
		t.Fatalf("re-arm after clock rollback = %v, want ErrProbeConsumed", err)
	}
}

func TestRestartRemovesConsumedFenceAfterReplayDeadline(t *testing.T) {
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	arm := protocol.ProbeArm{Endpoint: "198.51.100.7:8080", TTLMS: 60_000}
	arm.ProbeID[15] = 8
	started := time.Unix(50_000, 0)
	if err := st.SaveArmedProbeForForward(arm, "forward-expired", started.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkArmedProbeConsumedWithReceipt(arm.ProbeID, []byte("receipt"), "receipt-expired", started.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	_ = NewProbeManager(ProbeManagerOptions{
		Store: st,
		Clock: func() time.Time { return started.Add(3 * time.Minute) },
	})
	if _, found, err := st.LoadArmedProbe(arm.ProbeID); err != nil || found {
		t.Fatalf("expired consumed fence = found %v err %v, want removed", found, err)
	}
}
