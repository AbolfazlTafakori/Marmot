package config

import (
	"sort"
	"strconv"

	"marmot/internal/core"
)

// PortRule is the resolved steering policy for one user-facing port.
type PortRule struct {
	Port       uint16
	Class      core.Class
	Protos     []core.Proto
	TargetPort uint16
	Peers      []string // empty = any peer
}

// HasProto reports whether the rule covers p.
func (r PortRule) HasProto(p core.Proto) bool {
	for _, x := range r.Protos {
		if x == p {
			return true
		}
	}
	return false
}

// PortRules resolves steering into one rule per port, sorted by port.
// It assumes the configuration has been validated.
func (s Steering) PortRules() []PortRule {
	rules := make([]PortRule, 0, len(s.TunneledPorts)+len(s.VIPControlPorts))
	add := func(ports []uint16, class core.Class) {
		for _, p := range ports {
			key := strconv.Itoa(int(p))
			r := PortRule{Port: p, Class: class, TargetPort: p, Peers: s.PortPeers[key]}
			if t, ok := s.PortMap[key]; ok {
				r.TargetPort = t
			}
			protos := s.Protocols
			if o, ok := s.PortProtocols[key]; ok {
				protos = o
			}
			for _, name := range protos {
				if pr, err := core.ParseProto(name); err == nil {
					r.Protos = append(r.Protos, pr)
				}
			}
			rules = append(rules, r)
		}
	}
	add(s.TunneledPorts, core.ClassTunneled)
	add(s.VIPControlPorts, core.ClassVIP)
	sort.Slice(rules, func(i, j int) bool { return rules[i].Port < rules[j].Port })
	return rules
}
