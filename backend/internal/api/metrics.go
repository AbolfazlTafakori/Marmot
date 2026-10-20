package api

import (
	"runtime"
	"strconv"

	"marmot/internal/node"
	"marmot/internal/telemetry"
)

// logRecord is the telemetry log record, named here for the WebSocket.
type logRecord = telemetry.LogRecord

// Metrics returns the node's Prometheus metrics (ARCHITECTURE §13.3):
// paths, loss, FEC, sessions, streams, bytes, failovers and rotations.
func Metrics(n *node.Node) []telemetry.Metric {
	st := n.Snapshot()
	up := 0.0
	if st.Running {
		up = 1
	}
	peerUp := telemetry.Metric{Name: "marmot_peer_up", Help: "1 if the peer has a ready session.", Type: telemetry.Gauge}
	peerRelayed := telemetry.Metric{Name: "marmot_peer_relayed", Help: "1 if the peer is reached only through a relay node.", Type: telemetry.Gauge}
	sessions := telemetry.Metric{Name: "marmot_sessions", Help: "Open sessions per peer.", Type: telemetry.Gauge}
	paths := telemetry.Metric{Name: "marmot_paths", Help: "Live paths per peer and role.", Type: telemetry.Gauge}
	rtt := telemetry.Metric{Name: "marmot_path_rtt_seconds", Help: "Smoothed RTT of the active path.", Type: telemetry.Gauge}
	streams := telemetry.Metric{Name: "marmot_streams", Help: "Open streams per peer.", Type: telemetry.Gauge}
	bytes := telemetry.Metric{Name: "marmot_peer_bytes_total", Help: "Bytes exchanged with a peer since start.", Type: telemetry.Counter}
	loss := telemetry.Metric{Name: "marmot_path_loss_ratio", Help: "Smoothed fraction of packets lost on a path (session v2).", Type: telemetry.Gauge}
	fecParity := telemetry.Metric{Name: "marmot_fec_parity", Help: "FEC parity symbols per group on a session's datagram paths.", Type: telemetry.Gauge}
	recovered := telemetry.Metric{Name: "marmot_fec_recovered_packets", Help: "Packets rebuilt by FEC on the live sessions of a peer.", Type: telemetry.Gauge}
	for _, p := range st.Peers {
		id := string(p.ID)
		v, relayed := 0.0, 0.0
		if p.State == node.PeerUp || p.State == node.PeerRelayed {
			v = 1
		}
		if p.State == node.PeerRelayed {
			relayed = 1
		}
		peerUp.Samples = append(peerUp.Samples, telemetry.Sample{Labels: map[string]string{"peer": id}, Value: v})
		peerRelayed.Samples = append(peerRelayed.Samples, telemetry.Sample{Labels: map[string]string{"peer": id}, Value: relayed})
		var active, standby, nstreams int
		var rebuilt uint64
		for j := range p.Sessions {
			ss := &p.Sessions[j]
			nstreams += ss.Streams
			if ss.Version == 2 {
				fecParity.Samples = append(fecParity.Samples, telemetry.Sample{
					Labels: map[string]string{"peer": id, "session": ss.ID}, Value: float64(ss.FECParity)})
			}
			for i := range ss.Paths {
				pi := &ss.Paths[i]
				rebuilt += pi.Recovered
				if pi.Scored {
					loss.Samples = append(loss.Samples, telemetry.Sample{
						Labels: map[string]string{"peer": id, "transport": pi.Meta.Transport, "remote": pi.Meta.Remote},
						Value:  pi.Loss})
				}
				if pi.Active {
					active++
					rtt.Samples = append(rtt.Samples, telemetry.Sample{
						Labels: map[string]string{"peer": id, "transport": pi.Meta.Transport, "remote": pi.Meta.Remote},
						Value:  pi.RTT.Seconds()})
				} else {
					standby++
				}
			}
		}
		sessions.Samples = append(sessions.Samples, telemetry.Sample{Labels: map[string]string{"peer": id}, Value: float64(len(p.Sessions))})
		paths.Samples = append(paths.Samples,
			telemetry.Sample{Labels: map[string]string{"peer": id, "role": "active"}, Value: float64(active)},
			telemetry.Sample{Labels: map[string]string{"peer": id, "role": "standby"}, Value: float64(standby)})
		streams.Samples = append(streams.Samples, telemetry.Sample{Labels: map[string]string{"peer": id}, Value: float64(nstreams)})
		recovered.Samples = append(recovered.Samples, telemetry.Sample{Labels: map[string]string{"peer": id}, Value: float64(rebuilt)})
		bytes.Samples = append(bytes.Samples,
			telemetry.Sample{Labels: map[string]string{"peer": id, "direction": "sent"}, Value: float64(p.BytesSent)},
			telemetry.Sample{Labels: map[string]string{"peer": id, "direction": "received"}, Value: float64(p.BytesRecv)})
	}
	portBytes := telemetry.Metric{Name: "marmot_port_bytes_total", Help: "Bytes through a user-facing port since it was bound.", Type: telemetry.Counter}
	portConns := telemetry.Metric{Name: "marmot_port_connections", Help: "Open user connections and UDP flows per port.", Type: telemetry.Gauge}
	for _, p := range st.Ports {
		port := strconv.Itoa(int(p.Rule.Port))
		portBytes.Samples = append(portBytes.Samples,
			telemetry.Sample{Labels: map[string]string{"port": port, "direction": "in"}, Value: float64(p.BytesIn)},
			telemetry.Sample{Labels: map[string]string{"port": port, "direction": "out"}, Value: float64(p.BytesOut)})
		portConns.Samples = append(portConns.Samples,
			telemetry.Sample{Labels: map[string]string{"port": port, "proto": "tcp"}, Value: float64(p.ActiveTCP)},
			telemetry.Sample{Labels: map[string]string{"port": port, "proto": "udp"}, Value: float64(p.ActiveUDP)})
	}
	counts := n.EventCounts()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return []telemetry.Metric{
		{Name: "marmot_go_goroutines", Help: "Goroutines in the process.", Type: telemetry.Gauge,
			Samples: []telemetry.Sample{{Value: float64(runtime.NumGoroutine())}}},
		{Name: "marmot_go_heap_inuse_bytes", Help: "Heap bytes in use.", Type: telemetry.Gauge,
			Samples: []telemetry.Sample{{Value: float64(ms.HeapInuse)}}},
		{Name: "marmot_go_sys_bytes", Help: "Bytes obtained from the OS.", Type: telemetry.Gauge,
			Samples: []telemetry.Sample{{Value: float64(ms.Sys)}}},
		{Name: "marmot_up", Help: "1 if the node is running.", Type: telemetry.Gauge, Samples: []telemetry.Sample{{Value: up}}},
		peerUp, peerRelayed, sessions, paths, rtt, loss, fecParity, recovered, streams, bytes, portBytes, portConns,
		{Name: "marmot_failovers_total", Help: "Active path failures that caused a failover.", Type: telemetry.Counter,
			Samples: []telemetry.Sample{{Value: float64(counts[node.EventFailover])}}},
		{Name: "marmot_rotations_total", Help: "Make-before-break path rotations.", Type: telemetry.Counter,
			Samples: []telemetry.Sample{{Value: float64(counts[node.EventRotation])}}},
		{Name: "marmot_forwarded_streams_total", Help: "Streams delivered to local targets.", Type: telemetry.Counter,
			Samples: []telemetry.Sample{{Value: float64(st.Forwarder.Streams)}}},
		{Name: "marmot_refused_streams_total", Help: "Streams refused (target down or policy).", Type: telemetry.Counter,
			Samples: []telemetry.Sample{{Value: float64(st.Forwarder.Refused)}}},
		{Name: "marmot_relay_transit_paths", Help: "Relayed paths of other nodes passing through this node.", Type: telemetry.Gauge,
			Samples: []telemetry.Sample{{Value: float64(st.Transit.Active)}}},
		{Name: "marmot_relay_transit_bytes_total", Help: "Bytes of ended relayed paths that passed through this node.", Type: telemetry.Counter,
			Samples: []telemetry.Sample{{Value: float64(st.Transit.Bytes)}}},
	}
}
