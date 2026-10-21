package node

import (
	"crypto/ed25519"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"time"

	"marmot/internal/config"
	"marmot/internal/core"
	"marmot/internal/crypto"
	"marmot/internal/forwarder"
	"marmot/internal/session"
	"marmot/internal/steering"
)

// The data plane never imports config (ARCHITECTURE §4); these functions
// translate a validated Config into each package's own types.

func steeringRules(c *config.Config) []steering.Rule {
	prs := c.Steering.PortRules()
	out := make([]steering.Rule, 0, len(prs))
	for _, pr := range prs {
		r := steering.Rule{Port: pr.Port, Class: pr.Class, Protos: pr.Protos, TargetPort: pr.TargetPort}
		for _, p := range pr.Peers {
			r.Peers = append(r.Peers, core.NodeID(p))
		}
		out = append(out, r)
	}
	return out
}

func (n *Node) forwarderPolicy(c *config.Config) forwarder.Policy {
	p := forwarder.Policy{
		AllowDestination: n.exitDestinations,
		TargetHost:       c.PanelIntegration.TargetHost,
		ProxyV2:          c.PanelIntegration.PreserveClientIP == "proxy_v2",
		DeniedPorts:      map[uint16]bool{},
		AllowUDP:         true,
		AllowExit:        c.Node.Role == "exit" || c.Node.Role == "hybrid",
		UDPIdleTimeout:   c.Session.UDPIdleTimeout.D(),
	}
	if len(c.PanelIntegration.ProxyV2Ports) > 0 {
		p.ProxyV2Ports = map[uint16]bool{}
		for _, port := range c.PanelIntegration.ProxyV2Ports {
			p.ProxyV2Ports[port] = true
		}
	}
	// A peer may never reach SSH or this node's own management ports.
	for _, port := range c.Steering.ProtectedPorts {
		p.DeniedPorts[port] = true
	}
	for _, addr := range []string{c.API.Listen, c.Telemetry.MetricsListen} {
		if port, ok := listenPort(addr); ok {
			p.DeniedPorts[port] = true
		}
	}
	return p
}

func listenPort(addr string) (uint16, bool) {
	_, ps, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, false
	}
	p, err := strconv.ParseUint(ps, 10, 16)
	return uint16(p), err == nil && p != 0
}

// minDeadAfter keeps a path from being dropped for a short stall when the
// probe interval is small.
const minDeadAfter = 3 * time.Second

func connConfig(c *config.Config, log *slog.Logger) session.ConnConfig {
	probe := c.Session.ProbeInterval.D()
	data, parity := fecStart(c)
	return session.ConnConfig{
		SendBuffer:    int(c.Session.SendBuffer),
		ProbeInterval: probe,
		DeadAfter:     max(4*probe, minDeadAfter),
		ResumeTimeout: c.Session.ResumeTimeout.D(),
		FECData:       data,
		FECParity:     parity,
		Logger:        log,
	}
}

// fecStart is the FEC group a v2 session starts with: fixed mode sends
// its parity from the first packet; adaptive waits for the controller.
func fecStart(c *config.Config) (data, parity int) {
	switch c.FEC.Mode {
	case "fixed":
		return c.FEC.DataShards, c.FEC.MaxParityShards
	case "adaptive":
		return c.FEC.DataShards, 0
	}
	return 0, 0
}

func peerKeys(c *config.Config) (*session.PeerKeys, error) {
	m := make(map[core.NodeID]ed25519.PublicKey, len(c.Peers))
	for i := range c.Peers {
		p := &c.Peers[i]
		pub, err := config.ParsePublicKey(p.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("peer %s: %w", p.ID, err)
		}
		m[core.NodeID(p.ID)] = pub
	}
	return session.NewPeerKeys(m)
}

// localCaps are the capabilities this node offers, dialing and accepting.
// Offering CapMultipath selects session v2 with a peer that offers it too.
func localCaps(c *config.Config) uint32 {
	caps := crypto.CapUDP
	if c.Relay.AllowTransit {
		caps |= crypto.CapRelay
	}
	if c.Session.Version == 2 {
		caps |= crypto.CapMultipath | crypto.CapDatagrams
	}
	return caps
}
