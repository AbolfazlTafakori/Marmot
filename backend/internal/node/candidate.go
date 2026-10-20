package node

import (
	"math/rand/v2"
	"net/netip"

	"marmot/internal/config"
)

// rangeSample is how many ports of an endpoint port_range are tried per
// address, so a 10 000-port range does not produce 10 000 candidates.
const rangeSample = 4

// candidate is one way to dial a peer: transport × remote address × port,
// from one local address.
type candidate struct {
	transport string
	remote    netip.AddrPort
	local     netip.Addr // invalid = let the OS choose
	options   map[string]any
}

func (c candidate) key() string {
	return c.transport + "|" + c.local.String() + "|" + c.remote.String()
}

// candidates expands a peer's endpoints. Transports for which known
// reports false (not compiled in, or a later phase) are skipped and
// returned by name so the caller can warn once.
//
// Only IPv4 pools are expanded in Phase 1; the peer's IPv6 /64 needs the
// derivation of Phase 4.
func candidates(p config.Peer, localV4 []netip.Addr, known func(string) bool) ([]candidate, []string) {
	var out []candidate
	var skipped []string
	locals := localV4
	if len(locals) == 0 {
		locals = []netip.Addr{{}}
	}
	for _, e := range p.Endpoints {
		if !known(e.Transport) {
			skipped = append(skipped, e.Transport)
			continue
		}
		if e.Family == "ipv6" {
			continue
		}
		ports := e.Ports
		if len(ports) == 0 {
			ports = samplePorts(e.PortRange, rangeSample)
		}
		for _, s := range p.IPv4Pool {
			addr, err := netip.ParseAddr(s)
			if err != nil {
				continue // validated already
			}
			for _, port := range ports {
				for _, l := range locals {
					out = append(out, candidate{transport: e.Transport,
						remote: netip.AddrPortFrom(addr, port), local: l, options: e.Options})
				}
			}
		}
	}
	return out, skipped
}

func samplePorts(r config.PortRange, n int) []uint16 {
	if r.IsZero() {
		return nil
	}
	span := int(r.Hi) - int(r.Lo) + 1
	if span <= n {
		out := make([]uint16, 0, span)
		for p := int(r.Lo); p <= int(r.Hi); p++ {
			out = append(out, uint16(p))
		}
		return out
	}
	seen := map[uint16]bool{}
	out := make([]uint16, 0, n)
	for len(out) < n {
		p := r.Lo + uint16(rand.IntN(span)) //nolint:gosec // spreading ports, not a secret
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}
