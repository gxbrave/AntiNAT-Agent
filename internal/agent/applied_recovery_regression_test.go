package agent

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
	"github.com/gxbrave/AntiNAT-Agent/internal/traversal"
)

func recoverySpec(id, target string, revision uint64) protocol.ForwardSpec {
	return protocol.ForwardSpec{
		ForwardID:       id,
		Name:            "recovery",
		Protocol:        protocol.ProtocolTCP,
		Target:          target,
		Strategy:        protocol.StrategyDirectV4,
		DesiredRevision: revision,
		Presence:        protocol.PresencePresent,
	}
}

func recoveryApplied(spec protocol.ForwardSpec, host string, port uint16) protocol.AppliedForwardState {
	return protocol.AppliedForwardState{
		ForwardID:       spec.ForwardID,
		SpecRevision:    spec.DesiredRevision,
		DesiredRevision: spec.DesiredRevision,
		ActualBindHost:  host,
		ActualBindPort:  port,
		Strategy:        string(spec.Strategy),
		LayerVersion:    1,
		AppliedAtUnix:   time.Now().Unix(),
	}
}

func TestDataPlaneRecoveryUsesServingLKGWhenDesiredIsNewer(t *testing.T) {
	routeTable := traversal.HostRouteTable{}
	selection, capability, err := traversal.Assess(routeTable)
	if err != nil || capability != traversal.CapabilityDirectV4Ready {
		t.Skipf("direct-v4 capability unavailable: %v (%s)", err, capability)
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: selection.Source.AsSlice(), Port: 0})
	if err != nil {
		t.Skipf("cannot reserve direct-v4 recovery port on %s: %v", selection.Source, err)
	}
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	_ = listener.Close()

	store, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	id := "fwd-lkg-recovery"
	serving := recoverySpec(id, "127.0.0.1:18081", 1)
	applied := recoveryApplied(serving, selection.Source.String(), port)
	if _, err := store.CommitDesired(protocol.DesiredState{NodeID: "node-recovery", Forwards: []protocol.ForwardSpec{serving}}, []localstate.ForwardApply{{
		ForwardID: id,
		Outcome:   localstate.ApplyApplied,
		Applied:   &applied,
	}}); err != nil {
		t.Fatal(err)
	}

	// Revision 2 is received intent, but its apply failed. The durable applied
	// row remains revision 1 and recovery must reopen target A, not target B.
	newer := recoverySpec(id, "127.0.0.1:18082", 2)
	if _, err := store.CommitDesired(protocol.DesiredState{NodeID: "node-recovery", Forwards: []protocol.ForwardSpec{newer}}, []localstate.ForwardApply{{
		ForwardID: id,
		Outcome:   localstate.ApplyFailed,
		Err:       context.Canceled,
	}}); err != nil {
		t.Fatal(err)
	}

	var gotSpec protocol.ForwardSpec
	d := newDataPlane(dataPlaneConfig{
		Store:      store,
		RouteTable: routeTable,
		Clock:      time.Now,
		OnApplied: func(spec protocol.ForwardSpec, _ protocol.AppliedForwardState) {
			gotSpec = spec
		},
	})
	if _, err := d.recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer d.closeAll(context.Background())

	if gotSpec.Target != serving.Target || gotSpec.DesiredRevision != serving.DesiredRevision {
		t.Fatalf("recovered serving spec = %+v, want target %q revision %d", gotSpec, serving.Target, serving.DesiredRevision)
	}
	actor := d.forwards[id]
	if actor == nil {
		t.Fatal("recovery did not create actor")
	}
	if got := actor.backend.Target(); got != netip.MustParseAddrPort(serving.Target) {
		t.Fatalf("recovered backend target = %v, want %s", got, serving.Target)
	}
	if got, ok, err := store.LoadReceivedDesired(); err != nil || !ok || got.Forwards[0].Target != newer.Target {
		t.Fatalf("received desired = %+v, ok=%v err=%v, want newer retry intent", got, ok, err)
	}
}
