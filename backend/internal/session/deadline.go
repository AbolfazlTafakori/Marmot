package session

import (
	"sync"
	"time"
)

// deadline is a read or write deadline of a v2 stream: wait returns a
// channel that is closed while the deadline is in the past. It follows
// the pipeDeadline of package net.
type deadline struct {
	mu     sync.Mutex
	timer  *time.Timer
	cancel chan struct{}
}

func newDeadline() *deadline { return &deadline{cancel: make(chan struct{})} }

// set arms the deadline; the zero time disarms it.
func (d *deadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil && !d.timer.Stop() {
		<-d.cancel // the timer fired; wait for it to close cancel
	}
	d.timer = nil

	closed := isClosed(d.cancel)
	if t.IsZero() {
		if closed {
			d.cancel = make(chan struct{})
		}
		return
	}
	if dur := time.Until(t); dur > 0 {
		if closed {
			d.cancel = make(chan struct{})
		}
		c := d.cancel
		d.timer = time.AfterFunc(dur, func() { close(c) })
		return
	}
	if !closed {
		close(d.cancel)
	}
}

func (d *deadline) wait() chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cancel
}

func isClosed(c chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

// signal wakes one waiter without blocking; a waiter checks its condition
// under the session lock before waiting, so a signal is never lost.
func signal(c chan struct{}) {
	select {
	case c <- struct{}{}:
	default:
	}
}
