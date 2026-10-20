// Package steering binds the user-facing ports Marmot is told to carry and
// hands every connection or UDP flow to a peer stream. Ports that are not
// listed are never bound, so they keep reaching whatever listens on them:
// bypass is implicit and cannot lock the server out.
package steering

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"sync"
	"time"

	"marmot/internal/core"
	"marmot/internal/frame"
	"marmot/internal/session"
)

// openTimeout bounds how long a new user connection waits for a stream.
const openTimeout = 10 * time.Second

// Rule is the policy of one user-facing port.
type Rule struct {
	Port       uint16
	Class      core.Class
	Protos     []core.Proto
	TargetPort uint16
	Peers      []core.NodeID // empty = any peer
}

func (r Rule) has(p core.Proto) bool { return slices.Contains(r.Protos, p) }

// Opener opens a stream toward the peer that should carry rule's traffic.
// The node implements it; in Phase 2 the scheduler does.
type Opener interface {
	Open(ctx context.Context, rule Rule, h frame.StreamHeader) (session.Stream, error)
}

// Config configures Steering.
type Config struct {
	Opener         Opener
	UDPIdleTimeout time.Duration
	Logger         *slog.Logger
}

// Steering owns the user-facing listeners.
type Steering struct {
	cfg Config
	log *slog.Logger

	mu    sync.Mutex
	ports map[uint16]*port
}

// New creates a Steering with no ports; call Update to bind them.
func New(cfg Config) (*Steering, error) {
	if cfg.Opener == nil {
		return nil, errors.New("steering: opener required")
	}
	if cfg.UDPIdleTimeout <= 0 {
		return nil, errors.New("steering: udp idle timeout must be positive")
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Steering{cfg: cfg, log: log, ports: make(map[uint16]*port)}, nil
}

// Update applies a new rule set. Ports whose protocols did not change keep
// their listeners and connections and only pick up the new rule; removed
// ports are closed; new ports are bound. Every port that could not be
// bound is reported in the error; the others are applied regardless.
func (s *Steering) Update(rules []Rule) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	want := make(map[uint16]Rule, len(rules))
	for _, r := range rules {
		want[r.Port] = r
	}
	for p, cur := range s.ports {
		r, keep := want[p]
		if keep && slices.Equal(r.Protos, cur.rule().Protos) {
			cur.setRule(r)
			delete(want, p)
			continue
		}
		cur.close()
		delete(s.ports, p)
	}
	var errs []error
	for _, r := range sortedRules(want) {
		p, err := s.bind(r)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		s.ports[r.Port] = p
	}
	return errors.Join(errs...)
}

func protoNames(ps []core.Proto) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return out
}

func sortedRules(m map[uint16]Rule) []Rule {
	out := make([]Rule, 0, len(m))
	for _, r := range m {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}

func (s *Steering) bind(r Rule) (*port, error) {
	p, err := listen(s, r)
	if err == nil {
		s.log.Info("port bound", "port", r.Port, "class", r.Class.String(), "protos", protoNames(r.Protos), "target_port", r.TargetPort)
		return p, nil
	}
	if owner := portOwner(r.Port); owner != "" {
		return nil, fmt.Errorf("port %d is already used by %s: %w", r.Port, owner, err)
	}
	return nil, fmt.Errorf("port %d: %w", r.Port, err)
}

// PortStatus describes one bound port. Byte counts are cumulative since
// the port was bound: In is from users into the tunnel, Out back to users.
type PortStatus struct {
	Rule      Rule
	ActiveTCP int
	ActiveUDP int
	BytesIn   int64
	BytesOut  int64
}

// Ports returns the bound ports, sorted.
func (s *Steering) Ports() []PortStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]PortStatus, 0, len(s.ports))
	for _, p := range s.ports {
		tcp, udp := p.active()
		out = append(out, PortStatus{Rule: p.rule(), ActiveTCP: tcp, ActiveUDP: udp,
			BytesIn: p.bytesIn.Load(), BytesOut: p.bytesOut.Load()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Rule.Port < out[j].Rule.Port })
	return out
}

// Close unbinds every port and ends every connection through it.
func (s *Steering) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, p := range s.ports {
		p.close()
		delete(s.ports, k)
	}
	return nil
}
