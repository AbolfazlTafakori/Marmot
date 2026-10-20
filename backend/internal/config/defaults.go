package config

import "time"

// Default values applied by ApplyDefaults to fields left empty.
const (
	DefaultRole           = "hybrid"
	DefaultTargetHost     = "127.0.0.1"
	DefaultSOCKS5Listen   = "127.0.0.1:1080"
	DefaultAPIListen      = "0.0.0.0:7443"
	DefaultDataDir        = "/var/lib/marmot"
	DefaultLogLevel       = "info"
	DefaultStandbyPaths   = 2
	DefaultRelayMaxHops   = 2
	DefaultPeerWeight     = 1
	DefaultFECDataShards  = 4
	DefaultFECMaxParity   = 3
	DefaultIPv6Active     = 4
	DefaultSendBuffer     = 4 << 20
	DefaultRotateBytes    = 256 << 20
	DefaultRotateInterval = 10 * time.Minute
	DefaultResumeTimeout  = 30 * time.Second
	DefaultProbeInterval  = time.Second
	DefaultUDPIdleTimeout = 60 * time.Second
	DefaultIPv6Epoch      = 5 * time.Minute
)

// DefaultProtectedPorts are never allowed as tunneled ports.
var DefaultProtectedPorts = []uint16{22}

// ApplyDefaults fills unset fields in place.
func (c *Config) ApplyDefaults() {
	setStr(&c.Node.Role, DefaultRole)
	if len(c.Steering.Protocols) == 0 {
		c.Steering.Protocols = []string{"tcp"}
	}
	if c.Steering.ProtectedPorts == nil {
		c.Steering.ProtectedPorts = append([]uint16(nil), DefaultProtectedPorts...)
	}
	setStr(&c.PanelIntegration.PreserveClientIP, "none")
	setStr(&c.PanelIntegration.TargetHost, DefaultTargetHost)
	setStr(&c.SOCKS5.Listen, DefaultSOCKS5Listen)

	if c.Local.IPv6Rotation.Epoch == 0 {
		c.Local.IPv6Rotation.Epoch = Duration(DefaultIPv6Epoch)
	}
	setInt(&c.Local.IPv6Rotation.Active, DefaultIPv6Active)

	s := &c.Session
	setSize(&s.RotateBytes, DefaultRotateBytes)
	setDur(&s.RotateInterval, DefaultRotateInterval)
	setInt(&s.StandbyPaths, DefaultStandbyPaths)
	setDur(&s.ResumeTimeout, DefaultResumeTimeout)
	setSize(&s.SendBuffer, DefaultSendBuffer)
	setDur(&s.ProbeInterval, DefaultProbeInterval)
	setDur(&s.UDPIdleTimeout, DefaultUDPIdleTimeout)

	setStr(&c.FEC.Mode, "adaptive")
	setInt(&c.FEC.DataShards, DefaultFECDataShards)
	setInt(&c.FEC.MaxParityShards, DefaultFECMaxParity)
	setInt(&c.Relay.MaxHops, DefaultRelayMaxHops)

	for i := range c.Peers {
		setInt(&c.Peers[i].Weight, DefaultPeerWeight)
		for j := range c.Peers[i].Endpoints {
			setStr(&c.Peers[i].Endpoints[j].Family, "any")
		}
	}

	setStr(&c.API.Listen, DefaultAPIListen)
	setStr(&c.API.DataDir, DefaultDataDir)
	setStr(&c.Telemetry.LogLevel, DefaultLogLevel)
}

func setStr(p *string, v string) {
	if *p == "" {
		*p = v
	}
}

func setInt(p *int, v int) {
	if *p == 0 {
		*p = v
	}
}

func setDur(p *Duration, v time.Duration) {
	if *p == 0 {
		*p = Duration(v)
	}
}

func setSize(p *ByteSize, v int64) {
	if *p == 0 {
		*p = ByteSize(v)
	}
}
