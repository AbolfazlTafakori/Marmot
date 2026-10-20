// Package telemetry sets up structured logging, exposes Prometheus
// metrics and applies runtime limits. It knows nothing about the node;
// callers hand it what to report.
package telemetry

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"time"
)

// LogRecord is a log line forwarded to live subscribers (the panel).
type LogRecord struct {
	At      time.Time      `json:"at"`
	Level   string         `json:"level"`
	Message string         `json:"message"`
	Attrs   map[string]any `json:"attrs,omitempty"`
}

// logSubscriberBuffer is how far a slow subscriber may lag before records
// to it are dropped.
const logSubscriberBuffer = 64

// LogHub fans log records at or above a level out to subscribers.
type LogHub struct {
	mu   sync.Mutex
	subs map[chan LogRecord]struct{}
}

// Subscribe returns a channel of records and a function to stop.
func (h *LogHub) Subscribe() (<-chan LogRecord, func()) {
	ch := make(chan LogRecord, logSubscriberBuffer)
	h.mu.Lock()
	if h.subs == nil {
		h.subs = make(map[chan LogRecord]struct{})
	}
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			h.mu.Lock()
			delete(h.subs, ch)
			h.mu.Unlock()
			close(ch)
		})
	}
}

func (h *LogHub) publish(r LogRecord) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- r:
		default:
		}
	}
}

// NewLogger returns a JSON logger writing to w at the level in lv, and a
// hub that receives every record at forwardMin or above.
func NewLogger(w io.Writer, lv *slog.LevelVar, forwardMin slog.Level) (*slog.Logger, *LogHub) {
	hub := &LogHub{}
	base := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: lv})
	return slog.New(&teeHandler{next: base, hub: hub, min: forwardMin}), hub
}

// teeHandler passes records on and copies important ones to a hub.
type teeHandler struct {
	next  slog.Handler
	hub   *LogHub
	min   slog.Level
	attrs []slog.Attr // from WithAttrs, flattened with group prefixes
	group string
}

func (t *teeHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return t.next.Enabled(ctx, l)
}

func (t *teeHandler) Handle(ctx context.Context, r slog.Record) error {
	err := t.next.Handle(ctx, r)
	if r.Level >= t.min {
		rec := LogRecord{At: r.Time, Level: r.Level.String(), Message: r.Message, Attrs: map[string]any{}}
		for _, a := range t.attrs {
			rec.Attrs[a.Key] = a.Value.Resolve().Any()
		}
		r.Attrs(func(a slog.Attr) bool {
			rec.Attrs[t.prefix()+a.Key] = attrValue(a.Value)
			return true
		})
		t.hub.publish(rec)
	}
	return err
}

// attrValue makes values JSON-friendly; errors would otherwise encode as {}.
func attrValue(v slog.Value) any {
	v = v.Resolve()
	if err, ok := v.Any().(error); ok {
		return err.Error()
	}
	if v.Kind() == slog.KindAny {
		if s, ok := v.Any().(interface{ String() string }); ok {
			return s.String()
		}
	}
	return v.Any()
}

func (t *teeHandler) prefix() string {
	if t.group == "" {
		return ""
	}
	return t.group + "."
}

func (t *teeHandler) WithAttrs(as []slog.Attr) slog.Handler {
	c := *t
	c.next = t.next.WithAttrs(as)
	c.attrs = append([]slog.Attr(nil), t.attrs...)
	for _, a := range as {
		c.attrs = append(c.attrs, slog.Any(t.prefix()+a.Key, attrValue(a.Value)))
	}
	return &c
}

func (t *teeHandler) WithGroup(name string) slog.Handler {
	c := *t
	c.next = t.next.WithGroup(name)
	c.group = t.prefix() + name
	return &c
}
