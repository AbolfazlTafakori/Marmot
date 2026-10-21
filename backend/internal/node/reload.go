package node

import (
	"errors"
	"net/netip"
	"reflect"

	"marmot/internal/config"
	"marmot/internal/core"
	"marmot/internal/mesh"
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
		routes, skipped := routesFor(next, p)
		for _, t := range skipped {
			n.log.Warn("transport not available in this build; endpoint skipped", "peer", p.ID, "transport", t)
		}
		fresh[id] = startLink(deps, p, key, routes)
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
		relayVias:      n.relayVias,
		dialRelay:      n.dialRelay,
		reportDial:     n.dials.add,
		log:            n.log.With("component", "link"),
	}
}

// baseLocals are the configured source addresses, before rotation.
func baseLocals(c *config.Config) mesh.Locals {
	return mesh.Locals{V4: parseAddrs(c.Local.IPv4Pool), V6: parseAddrs(c.Local.IPv6Pool)}
}

// peerSpec translates a peer's addresses and endpoints for mesh. The IPv6
// /64 is not dialed before Phase 4 (ADR-0011).
func peerSpec(p *config.Peer) mesh.PeerSpec {
	spec := mesh.PeerSpec{Addrs: append(parseAddrs(p.IPv4Pool), parseAddrs(p.IPv6Pool)...)}
	for i := range p.Endpoints {
		e := &p.Endpoints[i]
		if !e.Dialed() {
			continue // the peer dials us here (ADR-0017)
		}
		spec.Endpoints = append(spec.Endpoints, mesh.Endpoint{
			Transport: e.Transport, Ports: e.Ports, PortRange: [2]uint16{e.PortRange.Lo, e.PortRange.Hi}, Hop: e.HopInterval.D(),
			Family: mesh.ParseFamily(e.Family), Options: e.Options,
		})
	}
	return spec
}

func parseAddrs(ss []string) []netip.Addr {
	out := make([]netip.Addr, 0, len(ss))
	for _, s := range ss {
		if a, err := netip.ParseAddr(s); err == nil { // validated already
			out = append(out, a.Unmap())
		}
	}
	return out
}

func transportKnown(name string) bool {
	_, err := transport.Get(name)
	return err == nil
}
