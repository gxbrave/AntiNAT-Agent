// P14 repair-2 M-A data-race oracle: the in-memory a.marker is read by the
// background `monitorLiveness` goroutine EVERY tick, and written by
// `handleDecommission` (DECOMMISSIONING at Begin, DECOMMISSIONED at Complete).
// Before the mutex guard (markerMu) the two goroutines accessed the field with
// no lock/atomic/happens-before edge, so a REAL App driving handleDecommission
// while a REAL monitorLiveness loop is running tripped `WARNING: DATA RACE` at
// the app.go:1153/:1170 write sites. The race detector is the oracle: if a
// future change reintroduces a bare `a.marker` read on the monitorLiveness /
// reconnectControl / runDetectionOnce paths, this test fails under -race.
package agent

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/control"
	"github.com/gxbrave/AntiNAT-Agent/internal/agent/localstate"
)

func TestMarkerRaceOracleMonitorLivenessDuringDecommission(t *testing.T) {
	for i := 0; i < 5; i++ {
		a, _, _, _ := p12wRecoveryApp(t)
		a.cfg = Config{
			StateDir:         t.TempDir(),
			NodeID:           "node-marker",
			RouteTable:       p12wRouteTable{},
			LivenessInterval: time.Millisecond,
		}
		a.latch = localstate.NewLatch()
		// Pre-goroutine construction: no lock needed until the goroutines start.
		a.marker = localstate.MarkerActive

		ctx, cancel := context.WithCancel(context.Background())
		go a.monitorLiveness(ctx)
		// Let the reader tick at least once so the loop is live before the write.
		time.Sleep(3 * time.Millisecond)

		opID := fmt.Sprintf("op-marker-%d", i)
		if _, err := a.handleDecommission(ctx, control.Operation{
			MessageType: "node_decommission",
			OperationID: opID,
			Payload:     []byte(fmt.Sprintf(`{"node_id":"node-marker","deletion_operation_id":%q}`, opID)),
		}); err != nil {
			cancel()
			t.Fatalf("iteration %d handleDecommission: %v", i, err)
		}
		cancel()
	}
}
