// Package mesh decides how to reach peers: it turns a peer's addresses,
// ports and transports into candidate paths, picks diverse standbys, and
// keeps failing routes in quarantine (ADR-0011). It dials transport
// connections but knows nothing about sessions; node builds those.
package mesh

import (
	"math/rand/v2"
	"net/netip"

	"marmot/internal/core"
)

// Family is an address family filter of an endpoint.
type Family uint8

// Address family filters.
const (
	FamilyAny Family = iota
	FamilyIPv4
	FamilyIPv6
)

// ParseFamily converts the config spelling ("any", "ipv4", "ipv6").
func ParseFamily(s string) Family {
	switch s {
	case "ipv4":
		return FamilyIPv4
	case "ipv6":
		return FamilyIPv6
	default:
		return FamilyAny
	}
}

func (f Family) allows(a netip.Addr) bool {
	switch f {
	case FamilyIPv4:
		return a.Is4()
	case FamilyIPv6:
		return a.Is6()
	default:
		return true
	}
}

// Endpoint is one way to reach a peer: a transport on a set of ports.
type Endpoint struct {
	Transport string
	Ports     []uint16
	PortRange [2]uint16 // inclusive; zero = unset
	Family    Family
	Options   map[string]any
}

// PeerSpec is what mesh needs to know about a peer.
type PeerSpec struct {
	Addrs     []netip.Addr // the peer's IPv4 and IPv6 addresses
	Endpoints []Endpoint
}

// Locals are this node's source addresses; an empty family means the
// operating system chooses the source for that family.
type Locals struct {
	V4 []netip.Addr
	V6 []netip.Addr
}

// Candidate is one concrete path to try.
type Candidate struct {
	Transport string
	Local     netip.Addr // invalid = OS chooses
	Remote    netip.AddrPort
	Options   map[string]any
	Via       core.NodeID // relay node of a relayed candidate
}

// Key identifies a candidate's route for quarantine.
func (c Candidate) Key() string {
	if c.Via != "" {
		return TransportRelay + "|" + string(c.Via)
	}
	local := "any"
	if c.Local.IsValid() {
		local = c.Local.String()
	}
	return c.Transport + "|" + local + "|" + c.Remote.String()
}

// rangeSample is how many ports of a port range are tried per address, so a
// 10 000-port range does not produce 10 000 candidates.
const rangeSample = 4

// Expand lists a peer's candidates: local × remote address × port ×
// transport, within one address family and the endpoint's family filter.
// Transports for which known reports false are skipped and returned by name.
func Expand(p PeerSpec, locals Locals, known func(string) bool) ([]Candidate, []string) {
	var out []Candidate
	var skipped []string
	for _, e := range p.Endpoints {
		if !known(e.Transport) {
			skipped = append(skipped, e.Transport)
			continue
		}
		ports := e.Ports
		if len(ports) == 0 {
			ports = samplePorts(e.PortRange, rangeSample)
		}
		for _, addr := range p.Addrs {
			addr = addr.Unmap()
			if !e.Family.allows(addr) {
				continue
			}
			srcs := locals.V4
			if addr.Is6() {
				srcs = locals.V6
			}
			if len(srcs) == 0 {
				srcs = []netip.Addr{{}}
			}
			for _, port := range ports {
				for _, l := range srcs {
					out = append(out, Candidate{Transport: e.Transport, Local: l,
						Remote: netip.AddrPortFrom(addr, port), Options: e.Options})
				}
			}
		}
	}
	return out, skipped
}

func samplePorts(r [2]uint16, n int) []uint16 {
	if r[0] == 0 {
		return nil
	}
	span := int(r[1]) - int(r[0]) + 1
	if span <= n {
		out := make([]uint16, 0, span)
		for p := int(r[0]); p <= int(r[1]); p++ {
			out = append(out, uint16(p))
		}
		return out
	}
	seen := map[uint16]bool{}
	out := make([]uint16, 0, n)
	for len(out) < n {
		p := r[0] + uint16(rand.IntN(span)) //nolint:gosec // spreading ports, not a secret
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}
