package node

import (
	"sync"
	"time"
)

// Event types, as in the API's Event schema.
const (
	EventPeerState     = "peer.state"
	EventPathState     = "path.state"
	EventFailover      = "failover"
	EventRotation      = "rotation"
	EventConfigApplied = "config.applied"
)

// Event is something the panel may want to show live.
type Event struct {
	Type string         `json:"type"`
	At   time.Time      `json:"at"`
	Data map[string]any `json:"data,omitempty"`
}

// subscriberBuffer is how many events a slow subscriber may lag before
// events to it are dropped.
const subscriberBuffer = 64

// eventBus fans events out to subscribers without ever blocking the
// publisher.
type eventBus struct {
	mu     sync.Mutex
	subs   map[chan Event]struct{}
	counts map[string]uint64
}

func newEventBus() *eventBus {
	return &eventBus{subs: make(map[chan Event]struct{}), counts: make(map[string]uint64)}
}

func (b *eventBus) publish(typ string, data map[string]any) {
	e := Event{Type: typ, At: time.Now(), Data: data}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.counts[typ]++
	for ch := range b.subs {
		select {
		case ch <- e:
		default:
		}
	}
}

// snapshotCounts returns how many events of each type were published.
func (b *eventBus) snapshotCounts() map[string]uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make(map[string]uint64, len(b.counts))
	for k, v := range b.counts {
		out[k] = v
	}
	return out
}

func (b *eventBus) subscribe() (<-chan Event, func()) {
	ch := make(chan Event, subscriberBuffer)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			b.mu.Lock()
			delete(b.subs, ch)
			b.mu.Unlock()
			close(ch)
		})
	}
}
