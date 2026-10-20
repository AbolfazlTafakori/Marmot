// Package node wires the data plane together and is the only object the
// control plane talks to: Start, Stop, Reload, Snapshot, Subscribe.
package node

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"marmot/internal/config"
	"marmot/internal/core"
	"marmot/internal/crypto"
	"marmot/internal/forwarder"
	"marmot/internal/scheduler"
	"marmot/internal/session"
	"marmot/internal/socks5"
	"marmot/internal/steering"
)

// Errors returned by Node.
var (
	ErrNotRunning      = errors.New("node: not running")
	ErrAlreadyRunning  = errors.New("node: already running")
	ErrRestartRequired = errors.New("node: node id or identity changed; restart required")
)

// Options are fixed for the life of a Node.
type Options struct {
	Version string
	Logger  *slog.Logger

	// exitDestinations overrides the exit destination rule; only this
	// package's tests set it, since every address on a test host is local.
	exitDestinations func(netip.Addr) bool
}

// Node is one running Marmot instance.
type Node struct {
	identity *crypto.Identity
	version  string
	// exitDestinations: see Options; nil means the ADR-0010 rule.
	exitDestinations func(netip.Addr) bool
	log              *slog.Logger
	events           *eventBus

	lifecycle sync.Mutex // serialises Start, Reload and Stop

	mu        sync.RWMutex // guards the fields below
	cfg       *config.Config
	running   bool
	started   time.Time
	links     map[core.NodeID]*peerLink
	weights   map[core.NodeID]int
	listeners map[string]*interListener
	acceptor  *session.Acceptor
	forwarder *forwarder.Forwarder
	steering  *steering.Steering
	socks     *socks5.Server // exit-mode inbound; nil when disabled
	picker    *scheduler.Picker

	ctx    context.Context // cancelled by Stop; parent of stream serving
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Bytes of sessions that have ended, per peer, so peer totals keep
	// growing across reconnects. Guarded by totalsMu.
	totalsMu sync.Mutex
	closed   map[core.NodeID]byteTotals

	transit      atomic.Int64  // relayed paths passing through this node now
	transitBytes atomic.Uint64 // bytes of ended relayed paths
}

// byteTotals are bytes sent to and received from a peer.
type byteTotals struct{ sent, recv uint64 }

// New creates a stopped node. cfg must be validated.
func New(cfg *config.Config, identity *crypto.Identity, opts Options) (*Node, error) {
	if cfg == nil || identity == nil {
		return nil, errors.New("node: config and identity required")
	}
	log := opts.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Node{identity: identity, version: opts.Version, log: log, events: newEventBus(), cfg: cfg,
		exitDestinations: opts.exitDestinations, picker: scheduler.New(),
		closed: map[core.NodeID]byteTotals{}}, nil
}

// PublicKey returns this node's identity key.
func (n *Node) PublicKey() ed25519.PublicKey { return n.identity.PublicKey() }

// Sign signs msg with this node's identity key (used for join tokens).
func (n *Node) Sign(msg []byte) []byte { return n.identity.Sign(msg) }

// Config returns the configuration in effect. Callers must not modify it.
func (n *Node) Config() *config.Config {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.cfg
}

// Subscribe returns a channel of live events and a function to stop.
func (n *Node) Subscribe() (<-chan Event, func()) { return n.events.subscribe() }

// Start binds every listener and starts dialing peers. If anything cannot
// be bound, it stops what it started and returns the reason.
func (n *Node) Start() error {
	n.lifecycle.Lock()
	defer n.lifecycle.Unlock()
	n.mu.Lock()
	if n.running {
		n.mu.Unlock()
		return ErrAlreadyRunning
	}
	cfg := n.cfg
	n.mu.Unlock()

	keys, err := peerKeys(cfg)
	if err != nil {
		return err
	}
	fwd, err := forwarder.New(n.forwarderPolicy(cfg), n.log.With("component", "forwarder"))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	acc, err := session.NewAcceptor(session.AcceptorConfig{
		Local: n.identity, Peers: keys, Caps: localCaps(cfg),
		Conn:      connConfig(cfg, n.log.With("component", "session")),
		OnSession: n.onInbound,
		Logger:    n.log.With("component", "acceptor"),
	})
	if err != nil {
		cancel()
		return err
	}
	st, err := steering.New(steering.Config{Opener: n, UDPIdleTimeout: cfg.Session.UDPIdleTimeout.D(),
		Logger: n.log.With("component", "steering")})
	if err != nil {
		cancel()
		return err
	}

	n.mu.Lock()
	n.ctx, n.cancel = ctx, cancel
	n.forwarder, n.acceptor, n.steering = fwd, acc, st
	n.links, n.listeners = map[core.NodeID]*peerLink{}, map[string]*interListener{}
	n.weights = peerWeights(cfg)
	n.running, n.started = true, time.Now()
	n.mu.Unlock()

	errs := []error{n.applyListeners(cfg)}
	n.applyLinks(nil, cfg)
	if err := st.Update(steeringRules(cfg)); err != nil {
		errs = append(errs, err)
	}
	if err := n.applySOCKS5(nil, cfg); err != nil {
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		n.stopLocked()
		return fmt.Errorf("node start: %w", err)
	}
	n.log.Info("node started", "node", cfg.Node.ID, "role", cfg.Node.Role, "peers", len(cfg.Peers))
	return nil
}

// Stop closes every listener, session and user connection and waits for
// all goroutines.
func (n *Node) Stop() error {
	n.lifecycle.Lock()
	defer n.lifecycle.Unlock()
	n.mu.RLock()
	running := n.running
	n.mu.RUnlock()
	if !running {
		return ErrNotRunning
	}
	n.stopLocked()
	n.log.Info("node stopped")
	return nil
}

// stopLocked tears everything down; the caller holds lifecycle.
func (n *Node) stopLocked() {
	n.mu.Lock()
	n.running = false
	links, listeners := n.links, n.listeners
	n.links, n.listeners = nil, nil
	n.mu.Unlock()

	_ = n.steering.Close()
	n.mu.Lock()
	socks := n.socks
	n.socks = nil
	n.mu.Unlock()
	if socks != nil {
		_ = socks.Close()
	}
	for _, l := range listeners {
		l.close()
	}
	for _, l := range links {
		l.stop()
	}
	_ = n.acceptor.Close()
	n.cancel()
	n.wg.Wait()
}

// onInbound starts serving a session a peer dialed to us.
func (n *Node) onInbound(s *session.MuxSession) {
	n.events.publish(EventPeerState, map[string]any{"peer": s.Peer(), "state": "up", "direction": "inbound"})
	n.serveSession(s)
}

// serveSession accepts the peer's streams on s and delivers them locally
// until s ends.
func (n *Node) serveSession(s *session.MuxSession) {
	n.mu.RLock()
	ctx, fwd := n.ctx, n.forwarder
	for _, l := range n.links {
		l.kick() // a new session may be the relay another peer waits for
	}
	n.mu.RUnlock()
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		defer n.foldSession(s)
		for {
			st, h, err := s.AcceptStream(ctx)
			if err != nil {
				return
			}
			n.wg.Add(1)
			go func() {
				defer n.wg.Done()
				if h.Path {
					n.servePath(ctx, s, st, h)
					return
				}
				fwd.Serve(ctx, st, h)
			}()
		}
	}()
}

// foldSession adds an ended session's bytes to its peer's totals. The
// stream accept loop ends exactly when the session does, so each session
// is folded once.
func (n *Node) foldSession(s *session.MuxSession) {
	<-s.Done()
	st := s.Stats()
	n.totalsMu.Lock()
	t := n.closed[s.Peer()]
	t.sent += st.SentOff
	t.recv += st.RecvOff
	n.closed[s.Peer()] = t
	n.totalsMu.Unlock()
}

// EventCounts returns how many events of each type have occurred, for
// metrics such as the failover count.
func (n *Node) EventCounts() map[string]uint64 { return n.events.snapshotCounts() }

func peerWeights(c *config.Config) map[core.NodeID]int {
	m := make(map[core.NodeID]int, len(c.Peers))
	for i := range c.Peers {
		m[core.NodeID(c.Peers[i].ID)] = c.Peers[i].Weight
	}
	return m
}
