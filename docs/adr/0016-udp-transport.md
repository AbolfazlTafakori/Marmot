# ADR-0016: A plain UDP transport with Marmot's own pacing

Status: Accepted

## Context
QUIC paths carry session v2 datagrams under quic-go's Cubic congestion
control, which cannot be replaced. Random loss, common on Iranian routes,
makes Cubic shrink its window even when FEC repairs every loss (ADR-0014
§Consequences); the Phase 3 chaos run showed 0.5–1.2 s stalls on a lossy
QUIC path against under 100 ms on TCP paths.

## Decision
1. **Transport `udp`** sends session v2 records directly in UDP datagrams.
   The dialer has its own socket; the listener has one socket and tells
   connections apart by the peer's address and port.
2. **Wire.** Each datagram starts with one kind byte: `1` handshake, `2`
   record (spec §4.2), `3` close. Handshake datagrams carry `seq:u8 | msg`.
3. **Handshake.** Noise needs one request and one reply. Each side keeps
   its last handshake datagram and sends it again every 250 ms until a
   newer one arrives from the peer; a repeated one from the peer makes it
   send its own again. The listener reports a connection once its first
   handshake datagram arrived; one that stays silent for 10 s is dropped.
4. **Session v2 only.** A udp path cannot carry v1's byte stream: a v1
   session over udp is refused.
5. **Pacing.** The transport reports that it needs pacing; session v2 then
   paces the path's packets at 1.25 × window / smoothed RTT with a burst
   of 10 packets, and its delivery-rate window (ADR-0013 §6) is the only
   congestion control. FEC-repaired loss does not shrink it.
6. **Limits.** Datagrams up to 1,200 bytes, as for QUIC; at most 1,024
   connections per listener; an idle connection (no datagram for 60 s) is
   dropped.

## Consequences
- A udp path looks like random bytes after a one-byte kind, which a
  censor can match; obfuscating it is future work. QUIC stays for routes
  where looking like HTTP/3 matters more than throughput under loss.
- `port_range` and `hop_interval` work for udp as for quic.
