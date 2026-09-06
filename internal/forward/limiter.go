// Package forward provides reusable data-plane limits. This file owns the
// token-bucket limiter used by new Forward sessions; callers snapshot a limiter
// at session start so updates remain NEW_SESSIONS_ONLY.
package forward

import (
	"errors"
	"sync"
	"time"
)

var ErrRateLimited = errors.New("forward: rate limit exceeded")

// Direction identifies one independent byte stream.
type Direction uint8

const (
	DirectionIngress Direction = iota + 1
	DirectionEgress
)

// RateLimit is a token bucket. RateBPS is the refill rate and BurstBytes is
// the maximum token capacity. Zero rate means unlimited.
type RateLimit struct {
	RateBPS    uint64
	BurstBytes uint64
}

type tokenBucket struct {
	tokens float64
	at     time.Time
}

// Limiter is safe for concurrent use by one session's copy loops.
type Limiter struct {
	mu      sync.Mutex
	cfg     RateLimit
	now     func() time.Time
	buckets map[Direction]tokenBucket
}

// NewLimiter validates and constructs a directional limiter. A nonzero rate
// with zero burst uses one second of allowance, making configuration explicit
// while keeping a useful default.
func NewLimiter(cfg RateLimit) (*Limiter, error) {
	return NewLimiterWithClock(cfg, time.Now)
}

func NewLimiterWithClock(cfg RateLimit, now func() time.Time) (*Limiter, error) {
	if now == nil {
		now = time.Now
	}
	if cfg.RateBPS == 0 {
		return &Limiter{cfg: cfg, now: now, buckets: make(map[Direction]tokenBucket)}, nil
	}
	if cfg.BurstBytes == 0 {
		cfg.BurstBytes = cfg.RateBPS
	}
	if cfg.BurstBytes == 0 {
		return nil, errors.New("forward: invalid rate limit")
	}
	initial := float64(cfg.BurstBytes)
	return &Limiter{cfg: cfg, now: now, buckets: map[Direction]tokenBucket{
		DirectionIngress: {tokens: initial, at: now()},
		DirectionEgress:  {tokens: initial, at: now()},
	}}, nil
}

// Allow reports whether n bytes may pass now and consumes tokens when true.
// Requests larger than the burst are denied without partial consumption.
func (l *Limiter) Allow(direction Direction, n int) bool {
	if n < 0 || direction != DirectionIngress && direction != DirectionEgress {
		return false
	}
	if l == nil || l.cfg.RateBPS == 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[direction]
	now := l.now()
	if now.Before(b.at) {
		now = b.at
	}
	elapsed := now.Sub(b.at).Seconds()
	b.tokens += elapsed * float64(l.cfg.RateBPS)
	if b.tokens > float64(l.cfg.BurstBytes) {
		b.tokens = float64(l.cfg.BurstBytes)
	}
	b.at = now
	if float64(n) > b.tokens {
		l.buckets[direction] = b
		return false
	}
	b.tokens -= float64(n)
	l.buckets[direction] = b
	return true
}

// WaitDuration returns the minimum duration until n bytes are available. It
// does not consume tokens and is safe to use for bounded sleeps by callers.
func (l *Limiter) WaitDuration(direction Direction, n int) time.Duration {
	if n <= 0 || l == nil || l.cfg.RateBPS == 0 {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[direction]
	now := l.now()
	if now.Before(b.at) {
		now = b.at
	}
	available := b.tokens + now.Sub(b.at).Seconds()*float64(l.cfg.RateBPS)
	if available >= float64(n) {
		return 0
	}
	return time.Duration((float64(n) - available) / float64(l.cfg.RateBPS) * float64(time.Second))
}

// Config returns the immutable session configuration.
func (l *Limiter) Config() RateLimit {
	if l == nil {
		return RateLimit{}
	}
	return l.cfg
}
