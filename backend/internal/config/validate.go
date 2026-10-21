package config

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"marmot/internal/core"
)

// Validate checks the whole configuration and returns every issue found.
// Call ApplyDefaults first.
func (c *Config) Validate() []Issue {
	var is issues
	c.validateNode(&is)
	user := c.validateSteering(&is)
	c.validatePanel(&is)
	c.validateLocal(&is)
	c.validateSession(&is)
	c.validateTransportListen(&is, user)
	c.validatePeers(&is)
	c.validateControlPlane(&is, user)
	return is
}

func (c *Config) validateNode(is *issues) {
	if _, err := core.ParseNodeID(c.Node.ID); err != nil {
		is.errf("node.id", "%v", err)
	}
	if !oneOf(c.Node.Role, "relay", "exit", "hybrid") {
		is.errf("node.role", "must be relay, exit or hybrid")
	}
	if c.Node.IdentityKeyFile == "" {
		is.errf("node.identity_key_file", "required")
	}
}

// validateSteering returns the set of user-facing ports.
func (c *Config) validateSteering(is *issues) map[uint16]bool {
	s := &c.Steering
	user := make(map[uint16]bool)
	protected := make(map[uint16]bool)
	for _, p := range s.ProtectedPorts {
		protected[p] = true
	}
	check := func(field string, ports []uint16) {
		for i, p := range ports {
			path := fmt.Sprintf("steering.%s[%d]", field, i)
			switch {
			case p == 0:
				is.errf(path, "port 0 is not allowed")
			case user[p]:
				is.errf(path, "port %d is listed more than once", p)
			case protected[p]:
				is.errf(path, "port %d is protected (SSH or management) and can never be tunneled", p)
			}
			user[p] = true
		}
	}
	check("tunneled_ports", s.TunneledPorts)
	check("vip_control_ports", s.VIPControlPorts)
	if len(user) == 0 {
		is.warnf("steering", "no ports are tunneled; the node will only relay")
	}
	validateProtocols(is, "steering.protocols", s.Protocols)

	for k, target := range s.PortMap {
		path := "steering.port_map." + k
		validatePortKey(is, path, k, user)
		if target == 0 {
			is.errf(path, "target port 0 is not allowed")
		}
	}
	for k, protos := range s.PortProtocols {
		path := "steering.port_protocols." + k
		validatePortKey(is, path, k, user)
		validateProtocols(is, path, protos)
	}
	peerIDs := make(map[string]bool, len(c.Peers))
	for i := range c.Peers {
		peerIDs[c.Peers[i].ID] = true
	}
	for k, ids := range s.PortPeers {
		path := "steering.port_peers." + k
		validatePortKey(is, path, k, user)
		for _, id := range ids {
			if !peerIDs[id] {
				is.errf(path, "unknown peer %q", id)
			}
		}
	}
	return user
}

func validatePortKey(is *issues, path, key string, user map[uint16]bool) {
	p, err := strconv.ParseUint(key, 10, 16)
	if err != nil || p == 0 {
		is.errf(path, "key must be a port number")
		return
	}
	if !user[uint16(p)] {
		is.errf(path, "port %d is not a tunneled or vip port", p)
	}
}

func validateProtocols(is *issues, path string, protos []string) {
	if len(protos) == 0 {
		is.errf(path, "at least one protocol is required")
	}
	seen := map[string]bool{}
	for _, p := range protos {
		if _, err := core.ParseProto(p); err != nil {
			is.errf(path, "%v", err)
		}
		if seen[p] {
			is.errf(path, "protocol %q listed twice", p)
		}
		seen[p] = true
	}
}

func (c *Config) validatePanel(is *issues) {
	p := &c.PanelIntegration
	if !oneOf(p.PreserveClientIP, "none", "proxy_v2") {
		is.errf("panel_integration.preserve_client_ip", "must be none or proxy_v2")
	}
	if !validHost(p.TargetHost) {
		is.errf("panel_integration.target_host", "invalid host %q", p.TargetHost)
	}
	if c.SOCKS5.Enabled {
		ap, err := netip.ParseAddrPort(c.SOCKS5.Listen)
		switch {
		case err != nil:
			is.errf("socks5.listen", "%v", err)
		case !ap.Addr().IsLoopback():
			is.warnf("socks5.listen", "not a loopback address: anyone who can reach %s can send traffic out through the exit; keep it on a private network", ap)
		}
	}
	if c.Node.Role == "exit" && !c.SOCKS5.Enabled {
		is.warnf("socks5.enabled", "role is exit but the SOCKS5 inbound is disabled")
	}
}

func (c *Config) validateLocal(is *issues) {
	validatePool(is, "local.ipv4_pool", c.Local.IPv4Pool)
	validatePool6(is, "local.ipv6_pool", c.Local.IPv6Pool)
	validateSubnet(is, "local.ipv6_subnet", c.Local.IPv6Subnet)
	r := c.Local.IPv6Rotation
	if r.Enabled {
		if c.Local.IPv6Subnet == "" {
			is.errf("local.ipv6_rotation", "requires local.ipv6_subnet")
		}
		if r.Active < 1 || r.Active > 64 {
			is.errf("local.ipv6_rotation.active", "must be 1..64")
		}
		if r.Epoch.D().Seconds() < 10 {
			is.errf("local.ipv6_rotation.epoch", "must be at least 10s")
		}
	}
}

func (c *Config) validateSession(is *issues) {
	s := &c.Session
	if s.Version != 1 && s.Version != 2 {
		is.errf("session.version", "must be 1 or 2")
	}
	if s.StandbyPaths < 0 || s.StandbyPaths > 8 {
		is.errf("session.standby_paths", "must be 0..8")
	}
	if s.SendBuffer < 64<<10 || s.SendBuffer > 256<<20 {
		is.errf("session.send_buffer", "must be between 64KiB and 256MiB")
	}
	if s.RotateBytes < 1<<20 {
		is.errf("session.rotate_bytes", "must be at least 1MiB")
	}
	if s.RotateInterval.D().Seconds() < 30 {
		is.errf("session.rotate_interval", "must be at least 30s")
	}
	if s.ProbeInterval.D().Milliseconds() < 100 {
		is.errf("session.probe_interval", "must be at least 100ms")
	}
	if s.ResumeTimeout.D().Seconds() < 1 {
		is.errf("session.resume_timeout", "must be at least 1s")
	}
	if !oneOf(c.FEC.Mode, "off", "fixed", "adaptive") {
		is.errf("fec.mode", "must be off, fixed or adaptive")
	}
	if c.FEC.DataShards < 1 || c.FEC.DataShards > 32 {
		is.errf("fec.data_shards", "must be 1..32")
	}
	if c.FEC.MaxParityShards < 0 || c.FEC.MaxParityShards > 16 {
		is.errf("fec.max_parity_shards", "must be 0..16")
	}
	if c.Relay.MaxHops < 0 || c.Relay.MaxHops > 4 {
		is.errf("relay.max_hops", "must be 0..4")
	}
}

// MaxListenPorts bounds a port_range listener: the node binds every port
// of it (ADR-0014 §3).
const MaxListenPorts = 256

func (c *Config) validateTransportListen(is *issues, user map[uint16]bool) {
	used := make(map[uint16]string)
	for i, l := range c.TransportListen {
		path := fmt.Sprintf("transport_listen[%d]", i)
		if l.Transport == "" {
			is.errf(path+".transport", "required")
		}
		if (l.Port == 0) == l.PortRange.IsZero() {
			is.errf(path, "set exactly one of port or port_range")
			continue
		}
		lo, hi := l.Port, l.Port
		if !l.PortRange.IsZero() {
			lo, hi = l.PortRange.Lo, l.PortRange.Hi
			if int(hi)-int(lo)+1 > MaxListenPorts {
				is.errf(path+".port_range", "spans more than %d ports; the node binds each one", MaxListenPorts)
				continue
			}
		}
		for p := uint32(lo); p <= uint32(hi); p++ {
			port := uint16(p)
			if user[port] {
				is.errf(path, "port %d collides with a user-facing port", port)
			}
			if prev, ok := used[port]; ok {
				is.errf(path, "port %d already used by %s", port, prev)
			}
			used[port] = path
		}
	}
}

func (c *Config) validatePeers(is *issues) {
	seen := make(map[string]bool)
	for i := range c.Peers {
		p := &c.Peers[i]
		path := fmt.Sprintf("peers[%d]", i)
		if _, err := core.ParseNodeID(p.ID); err != nil {
			is.errf(path+".id", "%v", err)
		}
		if p.ID == c.Node.ID {
			is.errf(path+".id", "peer id equals this node's id")
		}
		if seen[p.ID] {
			is.errf(path+".id", "duplicate peer id %q", p.ID)
		}
		seen[p.ID] = true
		if err := ValidatePublicKey(p.PublicKey); err != nil {
			is.errf(path+".public_key", "%v", err)
		}
		if p.Weight < 1 || p.Weight > 100 {
			is.errf(path+".weight", "must be 1..100")
		}
		validatePool(is, path+".ipv4_pool", p.IPv4Pool)
		validatePool6(is, path+".ipv6_pool", p.IPv6Pool)
		validateSubnet(is, path+".ipv6_subnet", p.IPv6Subnet)
		if len(p.Endpoints) > 0 && len(p.IPv4Pool) == 0 && len(p.IPv6Pool) == 0 && p.IPv6Subnet == "" {
			is.errf(path, "endpoints need ipv4_pool, ipv6_pool or ipv6_subnet")
		}
		for j, e := range p.Endpoints {
			validateEndpoint(is, fmt.Sprintf("%s.endpoints[%d]", path, j), e)
		}
	}
	if len(c.Peers) == 0 {
		is.warnf("peers", "no peers configured")
	}
}

func validateEndpoint(is *issues, path string, e Endpoint) {
	if e.Transport == "" {
		is.errf(path+".transport", "required")
	}
	if (len(e.Ports) == 0) == e.PortRange.IsZero() {
		is.errf(path, "set exactly one of ports or port_range")
	}
	for _, p := range e.Ports {
		if p == 0 {
			is.errf(path+".ports", "port 0 is not allowed")
		}
	}
	if !oneOf(e.Family, "any", "ipv4", "ipv6") {
		is.errf(path+".family", "must be any, ipv4 or ipv6")
	}
	if !oneOf(e.Direction, "outbound", "inbound", "both") {
		is.errf(path+".direction", "must be outbound, inbound or both")
	}
	if e.HopInterval != 0 {
		if e.PortRange.IsZero() {
			is.errf(path+".hop_interval", "needs port_range")
		}
		if e.HopInterval.D().Seconds() < 10 {
			is.errf(path+".hop_interval", "must be at least 10s")
		}
	}
}

// Dialed reports whether this node dials the endpoint (ADR-0017).
func (e *Endpoint) Dialed() bool { return e.Direction != "inbound" }

func (c *Config) validateControlPlane(is *issues, user map[uint16]bool) {
	checkListen := func(path, addr string) {
		_, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			is.errf(path, "%v", err)
			return
		}
		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			is.errf(path, "invalid port %q", portStr)
			return
		}
		if user[uint16(port)] {
			is.errf(path, "port %d is a tunneled port; the management port must stay reachable", port)
		}
	}
	checkListen("api.listen", c.API.Listen)
	if c.Telemetry.MetricsListen != "" {
		checkListen("telemetry.metrics_listen", c.Telemetry.MetricsListen)
	}
	if (c.API.TLSCert == "") != (c.API.TLSKey == "") {
		is.errf("api", "set both tls_cert and tls_key, or neither")
	}
	if c.API.TLSCert == "" {
		is.warnf("api", "panel is served without TLS; put it behind HTTPS")
	}
	for i, a := range c.API.AllowIPs {
		if _, err := netip.ParsePrefix(a); err != nil {
			if _, err2 := netip.ParseAddr(a); err2 != nil {
				is.errf(fmt.Sprintf("api.allow_ips[%d]", i), "not an IP or CIDR: %q", a)
			}
		}
	}
	if !oneOf(c.Telemetry.LogLevel, "debug", "info", "warn", "error") {
		is.errf("telemetry.log_level", "must be debug, info, warn or error")
	}
}

func validatePool(is *issues, path string, pool []string) {
	for i, s := range pool {
		a, err := netip.ParseAddr(s)
		if err != nil || !a.Is4() {
			is.errf(fmt.Sprintf("%s[%d]", path, i), "not an IPv4 address: %q", s)
		}
	}
}

func validatePool6(is *issues, path string, pool []string) {
	seen := map[netip.Addr]bool{}
	for i, s := range pool {
		a, err := netip.ParseAddr(s)
		if err != nil || !a.Is6() || a.Is4In6() || a.Zone() != "" {
			is.errf(fmt.Sprintf("%s[%d]", path, i), "not an IPv6 address: %q", s)
			continue
		}
		if seen[a] {
			is.errf(fmt.Sprintf("%s[%d]", path, i), "address %s listed twice", a)
		}
		seen[a] = true
	}
}

func validateSubnet(is *issues, path, s string) {
	if s == "" {
		return
	}
	p, err := netip.ParsePrefix(s)
	if err != nil || !p.Addr().Is6() || p.Addr().Is4In6() {
		is.errf(path, "not an IPv6 prefix: %q", s)
		return
	}
	if p.Bits() > 64 {
		is.errf(path, "prefix must be /64 or larger")
	}
}

func validHost(h string) bool {
	if _, err := netip.ParseAddr(h); err == nil {
		return true
	}
	if len(h) == 0 || len(h) > 253 {
		return false
	}
	for i := 0; i < len(h); i++ {
		if !hostChar(h[i]) {
			return false
		}
	}
	return true
}

func hostChar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	default:
		return c == '-' || c == '.'
	}
}

func oneOf(v string, opts ...string) bool {
	for _, o := range opts {
		if v == o {
			return true
		}
	}
	return false
}
