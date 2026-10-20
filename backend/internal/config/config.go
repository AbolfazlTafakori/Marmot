// Package config defines the marmot.toml schema, loads it strictly, applies
// defaults and validates it. A Config that passes Validate is safe to apply.
package config

// Config is the complete node configuration (marmot.toml).
type Config struct {
	Node             Node              `toml:"node,omitempty"`
	Steering         Steering          `toml:"steering,omitempty"`
	PanelIntegration PanelIntegration  `toml:"panel_integration,omitempty"`
	SOCKS5           SOCKS5            `toml:"socks5,omitempty"`
	Local            Local             `toml:"local,omitempty"`
	Session          Session           `toml:"session,omitempty"`
	FEC              FEC               `toml:"fec,omitempty"`
	Relay            Relay             `toml:"relay,omitempty"`
	TransportListen  []TransportListen `toml:"transport_listen,omitempty"`
	Peers            []Peer            `toml:"peers,omitempty"`
	API              API               `toml:"api,omitempty"`
	Telemetry        Telemetry         `toml:"telemetry,omitempty"`
}

// Node describes this node.
type Node struct {
	ID              string `toml:"id,omitempty"`
	Role            string `toml:"role,omitempty"` // relay | exit | hybrid
	IdentityKeyFile string `toml:"identity_key_file,omitempty"`
}

// Steering selects which user-facing ports Marmot binds. Ports that are not
// listed are never touched (implicit bypass).
type Steering struct {
	TunneledPorts   []uint16 `toml:"tunneled_ports,omitempty"`
	VIPControlPorts []uint16 `toml:"vip_control_ports,omitempty"`
	Protocols       []string `toml:"protocols,omitempty"`
	// ProtectedPorts can never be tunneled (SSH by default).
	ProtectedPorts []uint16 `toml:"protected_ports,omitempty"`
	// PortMap maps a user port to the target port on the receiving node.
	PortMap map[string]uint16 `toml:"port_map,omitempty"`
	// PortProtocols overrides Protocols for individual ports.
	PortProtocols map[string][]string `toml:"port_protocols,omitempty"`
	// PortPeers restricts which peers may carry a port (default: all).
	PortPeers map[string][]string `toml:"port_peers,omitempty"`
}

// PanelIntegration controls delivery on the receiving node.
type PanelIntegration struct {
	PreserveClientIP     string `toml:"preserve_client_ip,omitempty"` // none | proxy_v2
	SkipDoubleEncryption bool   `toml:"skip_double_encryption,omitempty"`
	TargetHost           string `toml:"target_host,omitempty"`
	// ProxyV2Ports limits PROXY v2 to these target ports (default: all).
	ProxyV2Ports []uint16 `toml:"proxy_v2_ports,omitempty"`
}

// SOCKS5 is the local inbound used in exit mode.
type SOCKS5 struct {
	Enabled bool   `toml:"enabled,omitempty"`
	Listen  string `toml:"listen,omitempty"`
}

// Local lists addresses this node may originate paths from.
type Local struct {
	IPv4Pool     []string     `toml:"ipv4_pool,omitempty"`
	IPv6Subnet   string       `toml:"ipv6_subnet,omitempty"`
	IPv6Rotation IPv6Rotation `toml:"ipv6_rotation,omitempty"`
}

// IPv6Rotation derives a rotating set of source addresses from a /64.
type IPv6Rotation struct {
	Enabled bool     `toml:"enabled,omitempty"`
	Epoch   Duration `toml:"epoch,omitempty"`
	Active  int      `toml:"active,omitempty"`
}

// Session tunes the session layer.
type Session struct {
	RotateBytes    ByteSize `toml:"rotate_bytes,omitempty"`
	RotateInterval Duration `toml:"rotate_interval,omitempty"`
	StandbyPaths   int      `toml:"standby_paths,omitempty"`
	ResumeTimeout  Duration `toml:"resume_timeout,omitempty"`
	SendBuffer     ByteSize `toml:"send_buffer,omitempty"`
	ProbeInterval  Duration `toml:"probe_interval,omitempty"`
	UDPIdleTimeout Duration `toml:"udp_idle_timeout,omitempty"`
}

// FEC configures forward error correction on datagram paths.
type FEC struct {
	Mode            string `toml:"mode,omitempty"` // off | fixed | adaptive
	DataShards      int    `toml:"data_shards,omitempty"`
	MaxParityShards int    `toml:"max_parity_shards,omitempty"`
}

// Relay controls transit through this node.
type Relay struct {
	AllowTransit bool `toml:"allow_transit,omitempty"`
	MaxHops      int  `toml:"max_hops,omitempty"`
}

// TransportListen is an inter-node listener on this node.
type TransportListen struct {
	Transport string         `toml:"transport,omitempty"`
	Port      uint16         `toml:"port,omitempty"`
	PortRange PortRange      `toml:"port_range,omitempty"`
	Options   map[string]any `toml:"options,omitempty"`
}

// Peer is another node this node talks to.
type Peer struct {
	ID         string     `toml:"id,omitempty"`
	PublicKey  string     `toml:"public_key,omitempty"`
	Weight     int        `toml:"weight,omitempty"`
	IPv4Pool   []string   `toml:"ipv4_pool,omitempty"`
	IPv6Subnet string     `toml:"ipv6_subnet,omitempty"`
	Endpoints  []Endpoint `toml:"endpoints,omitempty"`
}

// Endpoint is one way to dial a peer. A peer without endpoints is
// inbound-only: it dials us (reverse connection).
type Endpoint struct {
	Transport   string         `toml:"transport,omitempty"`
	Ports       []uint16       `toml:"ports,omitempty"`
	PortRange   PortRange      `toml:"port_range,omitempty"`
	HopInterval Duration       `toml:"hop_interval,omitempty"`
	Family      string         `toml:"family,omitempty"` // any | ipv4 | ipv6
	Options     map[string]any `toml:"options,omitempty"`
}

// API is the panel / control-plane listener.
type API struct {
	Listen   string   `toml:"listen,omitempty"`
	TLSCert  string   `toml:"tls_cert,omitempty"`
	TLSKey   string   `toml:"tls_key,omitempty"`
	AllowIPs []string `toml:"allow_ips,omitempty"`
	DataDir  string   `toml:"data_dir,omitempty"`
	WebRoot  string   `toml:"web_root,omitempty"`
}

// Telemetry configures logs and metrics.
type Telemetry struct {
	LogLevel      string `toml:"log_level,omitempty"`
	MetricsListen string `toml:"metrics_listen,omitempty"`
}
