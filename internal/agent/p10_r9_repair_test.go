package agent

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
)

func TestPrepareActivationRecoveryProcessesAllPersistedSnapshots(t *testing.T) {
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	states := protocol.ActivationStates{
		ControlState: "ONLINE", ListenerState: "READY", MappingState: "PUBLIC_CANDIDATE",
		KeepaliveState: "HEALTHY", WanReachabilityState: "OPEN_FROM_VANTAGE",
		ReturnPathState: "VERIFIED", TargetHealthState: "PASS",
		PublicationState: "PUBLISHED_VERIFIED", DataPlaneState: "READY",
	}
	const count = 300
	for i := 0; i < count; i++ {
		if err := st.SaveActivationSnapshot(localstate.ActivationSnapshot{
			ForwardID: "fwd-" + zeroPad(i), Activation: activationHex("fwd-"+zeroPad(i), 1), Generation: 1, States: states,
		}); err != nil {
			t.Fatal(err)
		}
	}
	a := &App{store: st}
	if err := a.prepareActivationRecovery(); err != nil {
		t.Fatal(err)
	}
	last, ok, err := st.LoadActivationSnapshot("fwd-" + zeroPad(count-1))
	if err != nil || !ok {
		t.Fatalf("last snapshot ok=%v err=%v", ok, err)
	}
	if last.States.PublicationState != "PUBLISHED_UNVERIFIED" {
		t.Fatalf("last snapshot remained verified: %+v", last.States)
	}
}

func TestControllerShutdownCanRetryAfterContextDeadline(t *testing.T) {
	dir := t.TempDir()
	st, err := localstate.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	app := &App{store: st, client: &blockingShutdownClient{unblock: make(chan struct{})}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := app.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("first Shutdown error = %v, want context deadline", err)
	}
	client := app.client.(*blockingShutdownClient)
	close(client.unblock)
	if err := app.Shutdown(context.Background()); err != nil {
		t.Fatalf("retry Shutdown: %v", err)
	}
	reopened, err := localstate.Open(dir, localstate.WithLockTimeout(20*time.Millisecond))
	if err != nil {
		t.Fatalf("reopen store after retry Shutdown: %v", err)
	}
	_ = reopened.Close()
}

func activationHex(forwardID string, generation uint64) string {
	id := protocol.ActivationID(forwardID, generation)
	return fmt.Sprintf("%x", id[:])
}

func zeroPad(i int) string {
	return fmt.Sprintf("%03d", i)
}
