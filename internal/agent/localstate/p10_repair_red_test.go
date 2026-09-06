package localstate

import (
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
)

func TestArmedProbePreservesForwardBinding(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var id [16]byte
	id[0] = 1
	arm := protocol.ProbeArm{ProbeID: id}
	if err := s.SaveArmedProbeForForward(arm, "forward-a", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.LoadArmedProbe(id)
	if err != nil || !ok {
		t.Fatalf("load: ok=%v err=%v", ok, err)
	}
	if got.ForwardID != "forward-a" {
		t.Fatalf("forward binding = %q, want forward-a", got.ForwardID)
	}
	if err := s.SaveArmedProbeForForward(arm, "forward-b", time.Now().Add(time.Minute)); err != ErrProbeConflict {
		t.Fatalf("cross-forward replay error = %v, want ErrProbeConflict", err)
	}
}
