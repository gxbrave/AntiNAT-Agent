// Story 5 RED: connection/FD/pessimistic-buffer budget exhaustion must
// return an explicit reason; release frees capacity; zero limits mean
// unlimited (v0.8 §4.4: worst-case per-connection fallback budget must be
// reserved, never assumed to be pool-controlled).
package forward

import (
	"errors"
	"testing"
)

func TestBudgetConnectionLimitExplicitReason(t *testing.T) {
	budget, err := NewBudget(Limits{MaxConnections: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := budget.Reserve(); err != nil {
		t.Fatalf("first reserve: %v", err)
	}
	err = budget.Reserve()
	if !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("second reserve error = %v, want ErrBudgetExceeded", err)
	}
	var exceeded *BudgetExceededError
	if !errors.As(err, &exceeded) {
		t.Fatalf("second reserve error = %T, want *BudgetExceededError", err)
	}
	if exceeded.Kind != LimitConnections {
		t.Fatalf("kind = %q, want %q", exceeded.Kind, LimitConnections)
	}
	if exceeded.Limit != 1 || exceeded.Current != 1 {
		t.Fatalf("exceeded = %+v, want limit 1 current 1", exceeded)
	}
}

func TestBudgetFDAndBufferLimitsExplicitReason(t *testing.T) {
	t.Run("fds", func(t *testing.T) {
		budget, err := NewBudget(Limits{MaxFDs: 1})
		if err != nil {
			t.Fatal(err)
		}
		if err := budget.Reserve(); err != nil {
			t.Fatal(err)
		}
		var exceeded *BudgetExceededError
		if err := budget.Reserve(); !errors.As(err, &exceeded) || exceeded.Kind != LimitFDs {
			t.Fatalf("second reserve = %v, want LimitFDs exceeded", err)
		}
	})
	t.Run("pessimistic buffer", func(t *testing.T) {
		budget, err := NewBudget(Limits{MaxPessimisticBufferBytes: PessimisticBufferBytesPerConnection})
		if err != nil {
			t.Fatal(err)
		}
		if err := budget.Reserve(); err != nil {
			t.Fatal(err)
		}
		var exceeded *BudgetExceededError
		if err := budget.Reserve(); !errors.As(err, &exceeded) || exceeded.Kind != LimitPessimisticBuffer {
			t.Fatalf("second reserve = %v, want LimitPessimisticBuffer exceeded", err)
		}
	})
}

func TestBudgetReleaseFreesCapacity(t *testing.T) {
	budget, err := NewBudget(Limits{MaxConnections: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := budget.Reserve(); err != nil {
		t.Fatal(err)
	}
	budget.Release()
	if err := budget.Reserve(); err != nil {
		t.Fatalf("reserve after release: %v", err)
	}
	budget.Release()
	snapshot := budget.Snapshot()
	if snapshot.Connections != 0 || snapshot.FDs != 0 || snapshot.PessimisticBufferBytes != 0 {
		t.Fatalf("snapshot after full release = %+v, want zeros", snapshot)
	}
}

func TestBudgetSnapshotTracksAllAxes(t *testing.T) {
	budget, err := NewBudget(Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if err := budget.Reserve(); err != nil {
		t.Fatal(err)
	}
	snapshot := budget.Snapshot()
	if snapshot.Connections != 1 || snapshot.FDs != 1 || snapshot.PessimisticBufferBytes != PessimisticBufferBytesPerConnection {
		t.Fatalf("snapshot = %+v, want one connection, one fd, %d buffer bytes", snapshot, PessimisticBufferBytesPerConnection)
	}
}

func TestBudgetZeroLimitsMeanUnlimited(t *testing.T) {
	budget, err := NewBudget(Limits{})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1000; i++ {
		if err := budget.Reserve(); err != nil {
			t.Fatalf("reserve %d with zero limits: %v", i, err)
		}
	}
}

func TestBudgetRejectsNegativeLimits(t *testing.T) {
	for _, limits := range []Limits{
		{MaxConnections: -1},
		{MaxFDs: -1},
		{MaxPessimisticBufferBytes: -1},
	} {
		if _, err := NewBudget(limits); err == nil {
			t.Fatalf("NewBudget(%+v) unexpectedly succeeded", limits)
		}
	}
}
