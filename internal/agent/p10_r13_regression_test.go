package agent

import (
	"testing"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/control"
	"github.com/gxbrave/AntiNAT-Agent/internal/agent/reconcile"
	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
)

func r13ProbeOutcomeApp(t *testing.T) *App {
	t.Helper()
	act := reconcile.NewActivation("forward-r13", "activation-r13", 1)
	if err := act.Set(protocol.ActivationStates{
		ControlState: "ONLINE", ListenerState: "READY", MappingState: "PUBLIC_CANDIDATE",
		KeepaliveState: "NOT_REQUIRED", WanReachabilityState: "PROBING",
		ReturnPathState: "NOT_TESTED", TargetHealthState: "UNKNOWN",
		PublicationState: "UNPUBLISHED", DataPlaneState: "READY",
	}); err != nil {
		t.Fatal(err)
	}
	return &App{dp: &dataPlane{}, activations: map[string]*reconcile.Activation{"forward-r13": act}}
}

// R13 RED: probe_outcome is semantic JSON inside an already authenticated
// control envelope. Duplicate or unknown fields must be rejected before the
// activation state machine is mutated.
func TestR13ProbeOutcomeUsesStrictSemanticJSON(t *testing.T) {
	for _, payload := range []string{
		`{"forward_id":"forward-r13","activation":"activation-r13","generation":1,"outcome":"OPEN_FROM_VANTAGE","outcome":"REJECTED"}`,
		`{"forward_id":"forward-r13","activation":"activation-r13","generation":1,"outcome":"REJECTED","unknown":true}`,
		`{"forward_id":"forward-r13","activation":"activation-r13","generation":1e0,"outcome":"REJECTED"}`,
	} {
		a := r13ProbeOutcomeApp(t)
		before := *a.ActivationSnapshot("forward-r13")
		if _, err := a.applyProbeOutcome(control.Operation{MessageType: "probe_outcome", Payload: []byte(payload)}); err == nil {
			t.Fatalf("ambiguous probe outcome accepted: %s", payload)
		}
		after := *a.ActivationSnapshot("forward-r13")
		if after != before {
			t.Fatalf("ambiguous payload mutated activation:\nbefore=%+v\nafter=%+v", before, after)
		}
	}
}
