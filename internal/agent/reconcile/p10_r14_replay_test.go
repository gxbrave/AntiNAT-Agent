package reconcile

import (
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/localstate"
)

// R14 RED: after semantic receipt acknowledgement and process restart, the
// durable consumed source/digest fence must still hydrate into the probe gate
// until ReceiptDeadline; acknowledgement must not reopen the business path.
func TestR14RestartHydratesAcknowledgedConsumedProbeFence(t *testing.T) {
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	now := time.Unix(91_000, 0)
	arm := sampleProbeArm()
	arm.ExpectedSourceIP = [4]byte{198, 51, 100, 44}
	arm.TTLMS = 30_000
	if err := st.SaveArmedProbeForForward(arm, "forward-r14", now.Add(30*time.Second)); err != nil {
		t.Fatalf("save armed probe: %v", err)
	}
	receipt := []byte("r14-restart-receipt")
	operationID := probeReceiptOperationID(receipt)
	if err := st.MarkArmedProbeConsumedWithReceipt(arm.ProbeID, receipt, operationID, now.Add(time.Hour)); err != nil {
		t.Fatalf("mark consumed: %v", err)
	}
	if err := st.AcknowledgeArmedProbeReceipt(operationID); err != nil {
		t.Fatalf("acknowledge receipt: %v", err)
	}

	manager := NewProbeManager(ProbeManagerOptions{
		Store:               st,
		Clock:               func() time.Time { return now },
		MaxActiveOperations: 1,
		MaxReplayEntries:    1,
	})
	if manager.Quarantined() {
		t.Fatal("valid acknowledged replay fence caused recovery quarantine")
	}
	if !manager.hasArmedBySource(arm.ExpectedSourceIP, "forward-r14") {
		t.Fatal("acknowledged consumed source was not retained as a replay fence after restart")
	}
	manager.mu.Lock()
	binding, ok := manager.replaySource[arm.ProbeID]
	manager.mu.Unlock()
	if !ok || binding.source != arm.ExpectedSourceIP || binding.forwardID != "forward-r14" {
		t.Fatalf("recovered replay source binding = %+v (present %v)", binding, ok)
	}
}
