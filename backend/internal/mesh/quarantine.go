package mesh

import (
	"sync"
	"time"
)

// Quarantine backoff (ADR-0011): 1 s, doubling per failure, at most 5 min.
const (
	firstBackoff = time.Second
	maxBackoff   = 5 * time.Minute
)

// quarantine remembers routes that failed and when they may be tried again.
type quarantine struct {
	mu    sync.Mutex
	now   func() time.Time
	state map[string]qEntry
}

type qEntry struct {
	failures int
	until    time.Time
}

func newQuarantine(now func() time.Time) *quarantine {
	return &quarantine{now: now, state: map[string]qEntry{}}
}

// fail records a failure and returns how long the route is now held.
func (q *quarantine) fail(key string) time.Duration {
	q.mu.Lock()
	defer q.mu.Unlock()
	e := q.state[key]
	e.failures++
	d := firstBackoff << min(e.failures-1, 20)
	if d > maxBackoff || d <= 0 {
		d = maxBackoff
	}
	e.until = q.now().Add(d)
	q.state[key] = e
	return d
}

// ok clears a route after it worked.
func (q *quarantine) ok(key string) {
	q.mu.Lock()
	delete(q.state, key)
	q.mu.Unlock()
}

// held reports whether key may not be tried yet.
func (q *quarantine) held(key string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	e, ok := q.state[key]
	return ok && q.now().Before(e.until)
}

// earliest returns when the first of keys leaves quarantine (zero if one
// is free now).
func (q *quarantine) earliest(keys []string) time.Time {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := q.now()
	var first time.Time
	for _, k := range keys {
		e, ok := q.state[k]
		if !ok || !now.Before(e.until) {
			return time.Time{}
		}
		if first.IsZero() || e.until.Before(first) {
			first = e.until
		}
	}
	return first
}

// failures returns the failure count of key, for status.
func (q *quarantine) failures(key string) (int, time.Time) {
	q.mu.Lock()
	defer q.mu.Unlock()
	e := q.state[key]
	return e.failures, e.until
}
