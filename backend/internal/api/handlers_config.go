package api

import (
	"net/http"
	"sort"
	"strconv"

	"marmot/internal/config"
	"marmot/internal/core"
)

func (s *Server) handleConfigGet(w http.ResponseWriter, r *http.Request, a *authCtx) {
	data, version, err := s.readConfigFile()
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, configDocument{TOML: string(data), Version: version})
}

// handleConfigPut replaces the file with the text as sent (comments kept),
// if nobody changed the file since the client read it.
func (s *Server) handleConfigPut(w http.ResponseWriter, r *http.Request, a *authCtx) {
	var doc configDocument
	if !decodeJSON(w, r, &doc) {
		return
	}
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	_, version, err := s.readConfigFile()
	if err != nil {
		s.internal(w, err)
		return
	}
	if doc.Version != version {
		writeError(w, http.StatusConflict, "conflict", "the configuration changed since you loaded it; reload and try again")
		return
	}
	loaded, warnings, err := s.applyConfig([]byte(doc.TOML))
	if err != nil {
		s.writeConfigError(w, err)
		return
	}
	s.audit(r, a, "config.update", "marmot.toml")
	writeJSON(w, http.StatusOK, configDocument{TOML: doc.TOML, Version: loaded.Version, Warnings: warnings})
}

func (s *Server) handleConfigValidate(w http.ResponseWriter, r *http.Request, a *authCtx) {
	var doc configDocument
	if !decodeJSON(w, r, &doc) {
		return
	}
	loaded, err := config.Parse([]byte(doc.TOML))
	if err != nil {
		writeJSON(w, http.StatusOK, resultFrom(err))
		return
	}
	res := validationResult{Valid: true, Issues: []issueView{}}
	for _, is := range loaded.Warnings {
		res.Issues = append(res.Issues, issueView{Severity: string(is.Severity), Path: is.Path, Message: is.Message})
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleReload(w http.ResponseWriter, r *http.Request, a *authCtx) {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	data, _, err := s.readConfigFile()
	if err != nil {
		s.internal(w, err)
		return
	}
	loaded, err := config.Parse(data)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, resultFrom(err))
		return
	}
	if err := s.cfg.Node.Reload(loaded.Config); err != nil {
		var res validationResult
		res.Issues = []issueView{{Severity: "error", Path: "", Message: err.Error()}}
		writeJSON(w, http.StatusUnprocessableEntity, res)
		return
	}
	s.audit(r, a, "node.reload", "marmot.toml")
	w.WriteHeader(http.StatusNoContent)
}

const bypassNote = "Ports not listed here are never bound by Marmot; their traffic goes straight to whatever listens on them."

func steeringFrom(c *config.Config) steeringView {
	v := steeringView{Ports: []portRuleView{}, BypassNote: bypassNote}
	for _, pr := range c.Steering.PortRules() {
		pv := portRuleView{Port: int(pr.Port), Class: pr.Class.String(), TargetPort: int(pr.TargetPort)}
		for _, p := range pr.Protos {
			pv.Protocols = append(pv.Protocols, p.String())
		}
		v.Ports = append(v.Ports, pv)
	}
	return v
}

func (s *Server) handleSteeringGet(w http.ResponseWriter, r *http.Request, a *authCtx) {
	writeJSON(w, http.StatusOK, steeringFrom(s.cfg.Node.Config()))
}

func (s *Server) handleSteeringPut(w http.ResponseWriter, r *http.Request, a *authCtx) {
	var req steeringView
	if !decodeJSON(w, r, &req) {
		return
	}
	loaded, warnings, err := s.mutateConfig(func(c *config.Config) error { return applySteering(c, req.Ports) })
	if err != nil {
		s.writeConfigError(w, err)
		return
	}
	s.audit(r, a, "steering.update", strconv.Itoa(len(req.Ports))+" ports")
	v := steeringFrom(loaded.Config)
	v.Warnings = warnings
	writeJSON(w, http.StatusOK, v)
}

// applySteering rewrites the steering section from API rules. Per-port
// protocol lists and target ports are written only where they differ
// from the defaults; port_peers of ports that remain are kept.
func applySteering(c *config.Config, rules []portRuleView) error {
	st := &c.Steering
	defaults := map[string]bool{}
	for _, p := range st.Protocols {
		defaults[p] = true
	}
	st.TunneledPorts, st.VIPControlPorts = nil, nil
	st.PortMap, st.PortProtocols = nil, nil
	keepPeers := st.PortPeers
	st.PortPeers = nil
	for i, r := range rules {
		path := "ports[" + strconv.Itoa(i) + "]"
		if r.Port < 1 || r.Port > 65535 {
			return invalidField(path+".port", "must be 1..65535")
		}
		port := uint16(r.Port)
		key := strconv.Itoa(r.Port)
		switch r.Class {
		case core.ClassTunneled.String():
			st.TunneledPorts = append(st.TunneledPorts, port)
		case core.ClassVIP.String():
			st.VIPControlPorts = append(st.VIPControlPorts, port)
		default:
			return invalidField(path+".class", "must be tunneled or vip")
		}
		if len(r.Protocols) == 0 {
			return invalidField(path+".protocols", "at least one protocol is required")
		}
		protos := append([]string(nil), r.Protocols...)
		sort.Strings(protos)
		if !sameSet(protos, defaults) {
			if st.PortProtocols == nil {
				st.PortProtocols = map[string][]string{}
			}
			st.PortProtocols[key] = protos
		}
		if r.TargetPort != 0 && r.TargetPort != r.Port {
			if r.TargetPort < 1 || r.TargetPort > 65535 {
				return invalidField(path+".targetPort", "must be 1..65535")
			}
			if st.PortMap == nil {
				st.PortMap = map[string]uint16{}
			}
			st.PortMap[key] = uint16(r.TargetPort)
		}
		if peers, ok := keepPeers[key]; ok {
			if st.PortPeers == nil {
				st.PortPeers = map[string][]string{}
			}
			st.PortPeers[key] = peers
		}
	}
	return nil
}

func sameSet(list []string, set map[string]bool) bool {
	if len(list) != len(set) {
		return false
	}
	for _, x := range list {
		if !set[x] {
			return false
		}
	}
	return true
}

func invalidField(path, msg string) error {
	return &invalidConfig{validationResult{Valid: false, Issues: []issueView{{Severity: "error", Path: path, Message: msg}}}}
}
