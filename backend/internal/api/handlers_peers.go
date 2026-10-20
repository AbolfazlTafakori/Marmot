package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"marmot/internal/config"
	"marmot/internal/core"
	"marmot/internal/node"
	"marmot/internal/session"
)

// sessionPath is the status type of one path, named here for brevity.
type sessionPath = session.PathInfo

func peerViewOf(p config.Peer, health map[string]node.PeerStatus) peerView {
	v := peerView{ID: p.ID, PublicKey: p.PublicKey, Weight: p.Weight, IPv4Pool: p.IPv4Pool,
		IPv6Subnet: p.IPv6Subnet, Endpoints: []endpointView{}}
	for _, e := range p.Endpoints {
		ev := endpointView{Transport: e.Transport, Direction: "outbound", Family: e.Family, Options: e.Options}
		for _, port := range e.Ports {
			ev.Ports = append(ev.Ports, int(port))
		}
		if !e.PortRange.IsZero() {
			ev.PortRange = fmt.Sprintf("%d-%d", e.PortRange.Lo, e.PortRange.Hi)
		}
		v.Endpoints = append(v.Endpoints, ev)
	}
	if st, ok := health[p.ID]; ok {
		h := healthOf(st)
		v.Health = &h
	}
	return v
}

func (s *Server) healthByPeer() map[string]node.PeerStatus {
	m := map[string]node.PeerStatus{}
	for _, p := range s.cfg.Node.Snapshot().Peers {
		m[string(p.ID)] = p
	}
	return m
}

func (s *Server) handlePeersList(w http.ResponseWriter, r *http.Request, a *authCtx) {
	health := s.healthByPeer()
	out := []peerView{}
	for _, p := range s.cfg.Node.Config().Peers {
		out = append(out, peerViewOf(p, health))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handlePeerGet(w http.ResponseWriter, r *http.Request, a *authCtx) {
	id := r.PathValue("peerId")
	for _, p := range s.cfg.Node.Config().Peers {
		if p.ID == id {
			writeJSON(w, http.StatusOK, peerViewOf(p, s.healthByPeer()))
			return
		}
	}
	writeError(w, http.StatusNotFound, "not_found", "no such peer")
}

// peerFromView converts an API peer to config, rejecting what Phase 1
// cannot do (ADR-0009).
func peerFromView(v peerView) (config.Peer, error) {
	p := config.Peer{ID: v.ID, PublicKey: v.PublicKey, Weight: v.Weight, IPv4Pool: v.IPv4Pool, IPv6Subnet: v.IPv6Subnet}
	for i, e := range v.Endpoints {
		path := fmt.Sprintf("endpoints[%d]", i)
		if e.Direction != "" && e.Direction != "outbound" {
			return p, invalidField(path+".direction", "only outbound is supported until reverse transports (Phase 4)")
		}
		ce := config.Endpoint{Transport: e.Transport, Family: e.Family, Options: e.Options}
		for _, port := range e.Ports {
			if port < 1 || port > 65535 {
				return p, invalidField(path+".ports", "ports must be 1..65535")
			}
			ce.Ports = append(ce.Ports, uint16(port))
		}
		if e.PortRange != "" {
			if err := ce.PortRange.UnmarshalText([]byte(e.PortRange)); err != nil {
				return p, invalidField(path+".portRange", err.Error())
			}
		}
		p.Endpoints = append(p.Endpoints, ce)
	}
	return p, nil
}

// handlePeerCreate adds a peer given directly or as a join token.
func (s *Server) handlePeerCreate(w http.ResponseWriter, r *http.Request, a *authCtx) {
	raw := json.RawMessage{}
	if !decodeJSON(w, r, &raw) {
		return
	}
	var peer config.Peer
	var probe struct {
		JoinToken string `json:"joinToken"`
	}
	_ = json.Unmarshal(raw, &probe)
	if probe.JoinToken != "" {
		var jr joinRequest
		_ = json.Unmarshal(raw, &jr)
		p, err := parseJoinToken(jr.JoinToken, jr.Weight)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_token", err.Error())
			return
		}
		peer = p
	} else {
		var v peerView
		dec := json.NewDecoder(bytes.NewReader(raw))
		if err := dec.Decode(&v); err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", err.Error())
			return
		}
		p, err := peerFromView(v)
		if err != nil {
			s.writeConfigError(w, err)
			return
		}
		peer = p
	}
	loaded, warnings, err := s.mutateConfig(func(c *config.Config) error {
		for _, p := range c.Peers {
			if p.ID == peer.ID {
				return &apiError{http.StatusConflict, "conflict", "a peer with this id already exists"}
			}
			if p.PublicKey == peer.PublicKey {
				return &apiError{http.StatusConflict, "conflict", "peer " + p.ID + " already uses this public key"}
			}
		}
		c.Peers = append(c.Peers, peer)
		return nil
	})
	if err != nil {
		s.writeConfigError(w, err)
		return
	}
	s.audit(r, a, "peer.add", peer.ID)
	s.writePeer(w, http.StatusCreated, loaded.Config, peer.ID, warnings)
}

func (s *Server) writePeer(w http.ResponseWriter, status int, c *config.Config, id string, warnings []string) {
	for _, p := range c.Peers {
		if p.ID == id {
			v := peerViewOf(p, s.healthByPeer())
			v.Warnings = warnings
			writeJSON(w, status, v)
			return
		}
	}
	writeError(w, http.StatusNotFound, "not_found", "no such peer")
}

func (s *Server) handlePeerUpdate(w http.ResponseWriter, r *http.Request, a *authCtx) {
	id := r.PathValue("peerId")
	var v peerView
	if !decodeJSON(w, r, &v) {
		return
	}
	if v.ID == "" {
		v.ID = id
	}
	if v.ID != id {
		writeError(w, http.StatusBadRequest, "bad_request", "the id in the body differs from the URL; delete and re-add to rename")
		return
	}
	peer, err := peerFromView(v)
	if err != nil {
		s.writeConfigError(w, err)
		return
	}
	loaded, warnings, err := s.mutateConfig(func(c *config.Config) error {
		for i := range c.Peers {
			if c.Peers[i].ID == id {
				c.Peers[i] = peer
				return nil
			}
		}
		return &apiError{http.StatusNotFound, "not_found", "no such peer"}
	})
	if err != nil {
		s.writeConfigError(w, err)
		return
	}
	s.audit(r, a, "peer.update", id)
	s.writePeer(w, http.StatusOK, loaded.Config, id, warnings)
}

// handlePeerDelete removes a peer; the reload closes its sessions at once.
// A peer still named in steering.port_peers is refused by validation, so
// a restricted port never silently opens to every peer.
func (s *Server) handlePeerDelete(w http.ResponseWriter, r *http.Request, a *authCtx) {
	id := r.PathValue("peerId")
	if _, err := core.ParseNodeID(id); err != nil {
		writeError(w, http.StatusNotFound, "not_found", "no such peer")
		return
	}
	_, _, err := s.mutateConfig(func(c *config.Config) error {
		for i := range c.Peers {
			if c.Peers[i].ID == id {
				c.Peers = append(c.Peers[:i], c.Peers[i+1:]...)
				return nil
			}
		}
		return &apiError{http.StatusNotFound, "not_found", "no such peer"}
	})
	if err != nil {
		s.writeConfigError(w, err)
		return
	}
	s.audit(r, a, "peer.delete", strings.ToLower(id))
	w.WriteHeader(http.StatusNoContent)
}
