package localstate

import (
	"testing"
	"time"
)

// R14 RED: a semantic Controller acknowledgement only acknowledges receipt
// delivery; it must not remove the consumed probe/source/digest fence before
// ReceiptDeadline, and the fence must be removed once that deadline expires.
func TestR14SemanticAckRetainsProbeFenceUntilReceiptDeadline(t *testing.T) {
	st := openProbeStore(t)
	arm := sampleArm()
	arm.ExpectedSourceIP = [4]byte{203, 0, 113, 44}
	forwardID := "forward-r14"
	now := time.Unix(90_000, 0)
	armDeadline := now.Add(time.Minute)
	receiptDeadline := now.Add(time.Hour)
	if err := st.SaveArmedProbeForForward(arm, forwardID, armDeadline); err != nil {
		t.Fatalf("save armed probe: %v", err)
	}
	receipt := []byte("r14-receipt")
	if err := st.MarkArmedProbeConsumedWithReceipt(arm.ProbeID, receipt, "r14-operation", receiptDeadline); err != nil {
		t.Fatalf("mark consumed: %v", err)
	}
	if err := st.AcknowledgeArmedProbeReceipt("r14-operation"); err != nil {
		t.Fatalf("acknowledge receipt: %v", err)
	}

	recovered, found, err := st.LoadArmedProbe(arm.ProbeID)
	if err != nil || !found {
		t.Fatalf("load acknowledged replay fence: found=%v err=%v", found, err)
	}
	if !recovered.Consumed || recovered.ForwardID != forwardID || recovered.Digest != arm.Digest() ||
		!recovered.ReceiptDeadline.Equal(receiptDeadline) {
		t.Fatalf("acknowledged replay fence lost durable binding: %+v", recovered)
	}
	if err := st.SweepArmedProbeTombstones(now.Add(30 * time.Minute)); err != nil {
		t.Fatalf("sweep before receipt deadline: %v", err)
	}
	if _, found, err := st.LoadArmedProbe(arm.ProbeID); err != nil || !found {
		t.Fatalf("replay fence removed before ReceiptDeadline: found=%v err=%v", found, err)
	}
	if err := st.SweepArmedProbeTombstones(receiptDeadline); err != nil {
		t.Fatalf("sweep at receipt deadline: %v", err)
	}
	if _, found, err := st.LoadArmedProbe(arm.ProbeID); err != nil || found {
		t.Fatalf("replay fence retained after ReceiptDeadline: found=%v err=%v", found, err)
	}
}
