package crypto

import (
	"sync"
	"time"
)

// replayCache remembers handshake nonces for a time window so a captured
// first handshake message cannot be replayed.
type replayCache struct {
	mu     sync.Mutex
	window time.Duration
	seen   map[[48]byte]time.Time // static key (32) + nonce (16)
	sweep  time.Time
}

func newReplayCache(window time.Duration) *replayCache {
	return &replayCache{window: window, seen: make(map[[48]byte]time.Time)}
}

// check records (static, nonce) and reports whether it is fresh.
func (c *replayCache) check(static []byte, nonce [16]byte, now time.Time) bool {
	var k [48]byte
	copy(k[:32], static)
	copy(k[32:], nonce[:])

	c.mu.Lock()
	defer c.mu.Unlock()
	if now.Sub(c.sweep) > c.window {
		for key, t := range c.seen {
			if now.Sub(t) > c.window {
				delete(c.seen, key)
			}
		}
		c.sweep = now
	}
	if _, dup := c.seen[k]; dup {
		return false
	}
	c.seen[k] = now
	return true
}
