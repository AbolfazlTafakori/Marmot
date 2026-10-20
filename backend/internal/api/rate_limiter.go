package api

import (
	"sync"
	"time"
)

// rateLimiter counts failed logins per key (client IP, username) in a
// sliding window and blocks a key that reaches the limit until its oldest
// failure leaves the window.
type rateLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	fails  map[string][]time.Time
	now    func() time.Time
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{limit: limit, window: window, fails: map[string][]time.Time{}, now: time.Now}
}

// blocked reports whether key may not try now, and for how long.
func (r *rateLimiter) blocked(key string) (bool, time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f := r.prune(key)
	if len(f) < r.limit {
		return false, 0
	}
	return true, f[0].Add(r.window).Sub(r.now())
}

// fail records a failure for key.
func (r *rateLimiter) fail(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fails[key] = append(r.prune(key), r.now())
}

// reset forgets key's failures after a success.
func (r *rateLimiter) reset(key string) {
	r.mu.Lock()
	delete(r.fails, key)
	r.mu.Unlock()
}

// sweep drops keys with no recent failures, so the map cannot grow without
// bound under a spray of addresses.
func (r *rateLimiter) sweep() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k := range r.fails {
		r.prune(k)
	}
}

// prune removes failures older than the window; the caller holds mu.
func (r *rateLimiter) prune(key string) []time.Time {
	f := r.fails[key]
	cut := r.now().Add(-r.window)
	i := 0
	for i < len(f) && !f[i].After(cut) {
		i++
	}
	f = f[i:]
	if len(f) == 0 {
		delete(r.fails, key)
		return nil
	}
	r.fails[key] = f
	return f
}
