package node

import (
	"errors"
	"net/netip"
	"reflect"

	"marmot/internal/config"
	"marmot/internal/core"
	"marmot/internal/transport"
)

// Reload applies a new validated configuration without a restart:
//   - removed or re-keyed peers lose their sessions at once (revocation);
//   - unchanged peers, ports and listeners keep their connections;
//   - changed ones are restarted individually.
//
// Session tuning applies to outbound sessions as their links restart and
// to inbound sessions after a restart. Changing the node id or identity
// file needs a restart. Ports or listeners that cannot be bound are
// reported in the error; everything else is applied.
func (n *Node) Reload(next *config.Config) error {
	n.lifecycle.Lock()
	defer n.lifecycle.Unlock()
	n.mu.RLock()
	running, prev := n.running, n.cfg
	n.mu.RUnlock()
	if !running {
		return ErrNotRunning
	}
	if next.Node.ID != prev.Node.ID || next.Node.IdentityKeyFile != prev.Node.IdentityKeyFile {
		return ErrRestartRequired
	}
	keys, err := peerKeys(next)
	if err != nil {
		return err
	}

	n.acceptor.SetPeers(keys)
	if err := n.forwarder.SetPolicy(n.forwarderPolicy(next)); err != nil {
		return err
	}
	n.mu.Lock()
	n.cfg = next
	n.weights = peerWeights(next)
	n.mu.Unlock()

	errs := []error{n.applyListeners(next)}
	n.applyLinks(prev, next)
	errs = append(errs, n.steering.Update(steeringRules(next)), n.applySOCKS5(prev, next))

	err = errors.Join(errs...)
	data := map[string]any{"ok": err == nil}
	if err != nil {
		data["error"] = err.Error()
	}
	n.events.publish(EventConfigApplied, data)
	n.log.Info("config reloaded", "err", err)
	return err
}

// applyLinks starts, keeps or restarts one link per peer. prev is nil on
// start.
func (n *Node) applyLinks(prev, next *config.Config) {
	depsChanged := prev == nil ||
		!reflect.DeepEqual(prev.Session, next.Session) ||
		!reflect.DeepEqual(prev.Local, next.Local) ||
		prev.Relay != next.Relay
	deps := n.linkDeps(next)

	n.mu.Lock()
	current := n.links
	fresh := make(map[core.NodeID]*peerLink, len(next.Peers))
	var stale []*peerLink
	keys, _ := peerKeys(next) // validated by the caller
	for i := range next.Peers {
		p := next.Peers[i]
		id := core.NodeID(p.ID)
		if l := current[id]; l != nil && !depsChanged && reflect.DeepEqual(l.cfg, p) {
			fresh[id] = l
			delete(current, id)
			continue
		}
		key, _ := keys.KeyOf(id)
		cands, skipped := candidates(p, localV4(next), transportKnown)
		for _, t := range skipped {
			n.log.Warn("transport not available in this build; endpoint skipped", "peer", p.ID, "transport", t)
		}
		fresh[id] = startLink(deps, p, key, cands)
	}
	for _, l := range current {
		stale = append(stale, l)
	}
	n.links = fresh
	n.mu.Unlock()

	// Restarted peers have their replacement in place before the old link
	// goes, so streams fail over to inbound sessions or the new link.
	for _, l := range stale {
		l.stop()
	}
}

func (n *Node) linkDeps(c *config.Config) linkDeps {
	return linkDeps{
		local:          n.identity,
		localID:        core.NodeID(c.Node.ID),
		caps:           localCaps(c),
		conn:           connConfig(c, n.log),
		standby:        c.Session.StandbyPaths,
		rotateBytes:    uint64(c.Session.RotateBytes),
		rotateInterval: c.Session.RotateInterval.D(),
		events:         n.events,
		serve:          n.serveSession,
		log:            n.log.With("component", "link"),
	}
}

func localV4(c *config.Config) []netip.Addr {
	out := make([]netip.Addr, 0, len(c.Local.IPv4Pool))
	for _, s := range c.Local.IPv4Pool {
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, a)
		}
	}
	return out
}

func transportKnown(name string) bool {
	_, err := transport.Get(name)
	return err == nil
}
