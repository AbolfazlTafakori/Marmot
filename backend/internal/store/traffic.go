package store

import (
	"context"
	"database/sql"
	"strconv"
	"time"
)

// Traffic scopes: the whole node, one peer, or one user-facing port.
const (
	ScopeNode = "node"
)

// ScopePeer is the scope of one peer's traffic.
func ScopePeer(id string) string { return "peer:" + id }

// ScopePort is the scope of one user-facing port's traffic.
func ScopePort(port int) string { return "port:" + strconv.Itoa(port) }

// TrafficSample is the bytes moved in one scope during one sampling step.
type TrafficSample struct {
	Scope    string
	BytesIn  int64
	BytesOut int64
}

// TrafficPoint is one bucket of a time series.
type TrafficPoint struct {
	T        time.Time
	BytesIn  int64
	BytesOut int64
}

// AddTraffic records samples for the step starting at t. Adding to the same
// scope and step again accumulates.
func (s *Store) AddTraffic(ctx context.Context, t time.Time, samples []TrafficSample) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		for _, x := range samples {
			_, err := tx.ExecContext(ctx, `INSERT INTO traffic (scope, t, bytes_in, bytes_out) VALUES (?, ?, ?, ?)
				ON CONFLICT (scope, t) DO UPDATE SET bytes_in = bytes_in + excluded.bytes_in, bytes_out = bytes_out + excluded.bytes_out`,
				x.Scope, ms(t), x.BytesIn, x.BytesOut)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// QueryTraffic sums a scope's samples in [from, to) into buckets of step.
// Buckets without traffic are returned as zeros, so a chart has no gaps.
func (s *Store) QueryTraffic(ctx context.Context, scope string, from, to time.Time, step time.Duration) ([]TrafficPoint, error) {
	stepMs := step.Milliseconds()
	start := ms(from) - ms(from)%stepMs
	rows, err := s.db.QueryContext(ctx, `SELECT (t - ?) / ? AS b, sum(bytes_in), sum(bytes_out) FROM traffic
		WHERE scope = ? AND t >= ? AND t < ? GROUP BY b ORDER BY b`, start, stepMs, scope, start, ms(to))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	n := int((ms(to) - start + stepMs - 1) / stepMs)
	out := make([]TrafficPoint, n)
	for i := range out {
		out[i].T = fromMs(start + int64(i)*stepMs)
	}
	for rows.Next() {
		var b, in, outB int64
		if err := rows.Scan(&b, &in, &outB); err != nil {
			return nil, err
		}
		if b >= 0 && int(b) < n {
			out[b].BytesIn, out[b].BytesOut = in, outB
		}
	}
	return out, rows.Err()
}

// PurgeTraffic deletes samples older than before.
func (s *Store) PurgeTraffic(ctx context.Context, before time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM traffic WHERE t < ?`, ms(before))
	return err
}
