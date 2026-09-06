package forward

import (
	"errors"
	"testing"
	"time"
)

func TestLimiterDirectionalBurstAndRefillWithFakeClock(t *testing.T) {
	now := time.Unix(10, 0)
	l, err := NewLimiterWithClock(RateLimit{RateBPS: 100, BurstBytes: 100}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if !l.Allow(DirectionIngress, 100) || l.Allow(DirectionIngress, 1) {
		t.Fatal("ingress burst was not consumed")
	}
	if !l.Allow(DirectionEgress, 100) {
		t.Fatal("egress bucket incorrectly shared ingress tokens")
	}
	now = now.Add(500 * time.Millisecond)
	if !l.Allow(DirectionIngress, 50) || l.Allow(DirectionIngress, 1) {
		t.Fatal("ingress refill incorrect")
	}
	if wait := l.WaitDuration(DirectionIngress, 50); wait <= 0 {
		t.Fatalf("wait duration=%s, want positive after consuming refill", wait)
	}
}

func TestLimiterUnlimitedAndInvalidDirections(t *testing.T) {
	unlimited, err := NewLimiter(RateLimit{})
	if err != nil || !unlimited.Allow(DirectionIngress, 1<<30) {
		t.Fatalf("unlimited limiter err=%v", err)
	}
	limited, err := NewLimiter(RateLimit{RateBPS: 1, BurstBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	if limited.Allow(Direction(99), 1) {
		t.Fatal("invalid direction allowed")
	}
	if !errors.Is(ErrRateLimited, ErrRateLimited) {
		t.Fatal("rate sentinel changed")
	}
}
