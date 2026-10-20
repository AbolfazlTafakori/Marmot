package api

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"marmot/internal/node"
	"marmot/internal/store"
)

// Traffic is sampled once per sampleStep and kept for retention.
const (
	sampleStep = time.Minute
	retention  = 31 * 24 * time.Hour
	purgeEvery = time.Hour
)

// trafficRanges maps the API's range parameter to its span and bucket.
var trafficRanges = map[string]struct{ span, step time.Duration }{
	"1h":  {time.Hour, time.Minute},
	"24h": {24 * time.Hour, 15 * time.Minute},
	"7d":  {7 * 24 * time.Hour, 2 * time.Hour},
	"30d": {30 * 24 * time.Hour, 6 * time.Hour},
}

// trafficSampler turns the node's cumulative byte counters into per-step
// deltas in the store. Counters restart from zero when a port is rebound
// or the process restarts; a counter that went down is taken as restarted.
type trafficSampler struct {
	node  *node.Node
	store *store.Store
	log   *slog.Logger
	last  map[string][2]int64 // scope -> (in, out) at the previous sample
}

func newTrafficSampler(n *node.Node, st *store.Store, log *slog.Logger) *trafficSampler {
	return &trafficSampler{node: n, store: st, log: log, last: map[string][2]int64{}}
}

func (t *trafficSampler) run(ctx context.Context) {
	t.sample(ctx, time.Now()) // baseline
	tick := time.NewTicker(sampleStep)
	defer tick.Stop()
	purge := time.NewTicker(purgeEvery)
	defer purge.Stop()
	for {
		select {
		case <-ctx.Done():
			// One last sample so a shutdown loses at most nothing.
			t.sample(context.Background(), time.Now())
			return
		case now := <-tick.C:
			t.sample(ctx, now)
		case now := <-purge.C:
			if err := t.store.PurgeTraffic(ctx, now.Add(-retention)); err != nil && ctx.Err() == nil {
				t.log.Warn("purge traffic", "err", err)
			}
		}
	}
}

// counters reads the cumulative counters of every scope.
func counters(st node.Status) map[string][2]int64 {
	m := map[string][2]int64{}
	var nodeIn, nodeOut int64
	for _, p := range st.Peers {
		in, out := int64(p.BytesRecv), int64(p.BytesSent)
		m[store.ScopePeer(string(p.ID))] = [2]int64{in, out}
		nodeIn += in
		nodeOut += out
	}
	m[store.ScopeNode] = [2]int64{nodeIn, nodeOut}
	for _, p := range st.Ports {
		m[store.ScopePort(int(p.Rule.Port))] = [2]int64{p.BytesIn, p.BytesOut}
	}
	return m
}

func (t *trafficSampler) sample(ctx context.Context, now time.Time) {
	cur := counters(t.node.Snapshot())
	var samples []store.TrafficSample
	first := len(t.last) == 0
	for scope, c := range cur {
		prev, seen := t.last[scope]
		t.last[scope] = c
		if first || !seen {
			continue
		}
		d := [2]int64{delta(prev[0], c[0]), delta(prev[1], c[1])}
		if d[0] != 0 || d[1] != 0 {
			samples = append(samples, store.TrafficSample{Scope: scope, BytesIn: d[0], BytesOut: d[1]})
		}
	}
	for scope := range t.last {
		if _, ok := cur[scope]; !ok {
			delete(t.last, scope)
		}
	}
	if len(samples) == 0 {
		return
	}
	if err := t.store.AddTraffic(ctx, now.Truncate(sampleStep), samples); err != nil {
		t.log.Warn("record traffic", "err", err)
	}
}

func delta(prev, cur int64) int64 {
	if cur < prev {
		return cur // counter restarted
	}
	return cur - prev
}

func (s *Server) handleTraffic(w http.ResponseWriter, r *http.Request, a *authCtx) {
	q := r.URL.Query()
	name := q.Get("range")
	if name == "" {
		name = "24h"
	}
	rg, ok := trafficRanges[name]
	if !ok {
		writeError(w, http.StatusBadRequest, "bad_request", "range must be 1h, 24h, 7d or 30d")
		return
	}
	scope := store.ScopeNode
	if p := q.Get("port"); p != "" {
		port, err := strconv.Atoi(p)
		if err != nil || port < 1 || port > 65535 {
			writeError(w, http.StatusBadRequest, "bad_request", "invalid port")
			return
		}
		scope = store.ScopePort(port)
	} else if peer := q.Get("peer"); peer != "" {
		scope = store.ScopePeer(peer)
	}
	now := s.now()
	to := now.Truncate(rg.step).Add(rg.step)
	pts, err := s.cfg.Store.QueryTraffic(r.Context(), scope, to.Add(-rg.span), to, rg.step)
	if err != nil {
		s.internal(w, err)
		return
	}
	out := trafficSeriesView{StepSec: int64(rg.step.Seconds()), Points: make([]trafficPointView, 0, len(pts))}
	for _, p := range pts {
		out.Points = append(out.Points, trafficPointView{T: p.T, BytesIn: p.BytesIn, BytesOut: p.BytesOut})
	}
	writeJSON(w, http.StatusOK, out)
}
