package api

import (
	"fmt"
	"net/http"
	"time"

	"marmot/internal/config"
	"marmot/internal/node"
)

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if !s.cfg.Node.Snapshot().Running {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("node not running\n"))
		return
	}
	_, _ = w.Write([]byte("ready\n"))
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request, a *authCtx) {
	writeJSON(w, http.StatusOK, statusView(s.cfg.Node.Snapshot(), s.now()))
}

func statusView(st node.Status, now time.Time) nodeStatusView {
	v := nodeStatusView{NodeID: st.NodeID, Role: st.Role, Version: st.Version, Peers: []peerHealthView{}}
	if st.Running {
		v.UptimeSec = int64(now.Sub(st.Started).Seconds())
	}
	for _, p := range st.Peers {
		v.BytesIn += p.BytesRecv
		v.BytesOut += p.BytesSent
		for _, ss := range p.Sessions {
			v.Sessions++
			v.Streams += ss.Streams
		}
		v.Peers = append(v.Peers, healthOf(p))
	}
	return v
}

// healthOf summarises a peer: its state, its active paths and the RTT of
// the active path of its first ready session.
func healthOf(p node.PeerStatus) peerHealthView {
	h := peerHealthView{ID: string(p.ID), State: p.State}
	for _, ss := range p.Sessions {
		for i := range ss.Paths {
			pi := &ss.Paths[i]
			if !pi.Active {
				continue
			}
			h.ActivePaths++
			if h.RTTMs == 0 && ss.Ready {
				h.RTTMs = float64(pi.RTT.Microseconds()) / 1000
			}
		}
	}
	return h
}

func (s *Server) handleIdentity(w http.ResponseWriter, r *http.Request, a *authCtx) {
	c := s.cfg.Node.Config()
	tok, err := makeJoinToken(c, s.cfg.Node.PublicKey(), s.cfg.Node.Sign, s.now())
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, identityView{NodeID: c.Node.ID,
		PublicKey: config.FormatPublicKey(s.cfg.Node.PublicKey()), JoinToken: tok})
}

func (s *Server) handlePeerPaths(w http.ResponseWriter, r *http.Request, a *authCtx) {
	id := r.PathValue("peerId")
	st := s.cfg.Node.Snapshot()
	for _, p := range st.Peers {
		if string(p.ID) != id {
			continue
		}
		out := []pathView{}
		for _, ss := range p.Sessions {
			for i := range ss.Paths {
				out = append(out, pathViewOf(ss.ID, &ss.Paths[i], s.now()))
			}
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	writeError(w, http.StatusNotFound, "not_found", "no such peer")
}

// pathViewOf reports one path. Score and throughput are Phase 1
// stand-ins until the adaptive controller (ADR-0009).
func pathViewOf(sessionID string, pi *sessionPath, now time.Time) pathView {
	rttMs := float64(pi.RTT.Microseconds()) / 1000
	v := pathView{
		ID: fmt.Sprintf("%s/%d", sessionID, pi.ID), Local: pi.Meta.Local, Remote: pi.Meta.Remote,
		Transport: pi.Meta.Transport, Role: "standby", RTTMs: rttMs,
	}
	if age := now.Sub(pi.Registered).Seconds(); age > 0 {
		v.ThroughputBps = int64(float64(pi.BytesSent+pi.BytesRecv) * 8 / age)
	}
	switch {
	case pi.Active:
		v.Role, v.Score = "active", 1
	case rttMs > 0:
		v.Score = 1 / (1 + rttMs/100)
	}
	return v
}
