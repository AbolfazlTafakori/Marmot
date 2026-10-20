# ADR-0014: QUIC transport, datagram paths and FEC

Status: Accepted

## Context
ARCHITECTURE §6 lists `quic` among the transports, and §8 puts
Reed-Solomon FEC on datagram paths only: on a TCP-based path a lost segment
is retransmitted by TCP and FEC cannot help. Marmot has no datagram path
yet. Spec §4.2 already reserves a datagram record format with an explicit
nonce and a replay window.

## Decision
1. **Transport `quic`** uses `quic-go` (MIT). A path is one QUIC connection.
   Its first bidirectional stream carries the Noise handshake (spec §3) and,
   for a v1 session, the records. TLS inside QUIC uses an ephemeral
   self-signed certificate and is not trusted for authentication; Noise
   authenticates the peer, as on every other transport. ALPN defaults to
   `h3`, so the connection looks like HTTP/3; options: `sni`, `alpn`,
   `datagrams` (default true).
2. **Datagram paths.** When the session is v2 and both QUIC endpoints
   negotiated RFC 9221 datagrams, every record after the handshake travels
   in a QUIC DATAGRAM frame using the datagram record format (spec §4.2):
   `nonce:u64 | ciphertext`, nonce counting up from 0, a 1024-entry replay
   window on receipt. Both sides know whether a path is a datagram path
   from the same facts (session version, negotiated datagram support), so
   there is no extra signalling. Records on a datagram path are kept under
   the datagram size QUIC reports (about 1,200 bytes).
3. **Port ranges.** A `quic` listener may use `port_range` (at most 256
   ports); the node binds every port of it. Changing ports during a session
   (`hop_interval`) stays in Phase 4.
4. **FEC on datagram paths.** Package `fec` wraps `klauspost/reedsolomon`
   (MIT). The sender groups up to `k` (`fec.data_shards`) packets sent on
   datagram paths and adds `m` parity packets, spreading a group's packets
   over the session's datagram paths in turn, so the loss of a whole path
   can be repaired. A source symbol is the packet's path id, packet number
   and frames; the receiver rebuilds a missing packet from any `k` symbols
   and processes it as if it had arrived on its own path, so it is
   acknowledged there and not resent. A group is closed early after 10 ms or
   a quarter of the smoothed RTT, whichever is shorter, so a slow trickle
   is still protected. A packet that cannot be rebuilt is lost and resent
   by the session.
5. **How much parity.** `fec.mode = off` sends none; `fixed` always sends
   `max_parity_shards`; `adaptive` lets the controller pick `m` from the
   measured loss of the session's datagram paths (ADR-0015).

## Consequences
- `transport.Conn` gains an optional `transport.Datagrammer` interface; a
  stream transport does not implement it and is unaffected.
- On a QUIC path, a v1 session uses the stream; only v2 uses datagrams.
- FEC adds overhead only on lossy datagram paths in adaptive mode.
- `quic-go` runs its own congestion control (Cubic) under our datagrams
  and offers no way to replace it, so random loss still lowers a QUIC
  path's rate even when FEC repairs every loss. Several QUIC paths in one
  session add their windows up; a plain UDP transport with Marmot's own
  congestion control would avoid the limit and is left to Phase 4.
