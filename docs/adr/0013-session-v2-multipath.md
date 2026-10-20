# ADR-0013: Session v2 is a multipath packet session with its own stream layer

Status: Accepted

## Context
Session v1 (ADR-0003) runs smux over one active path. A failover waits for
the watchdog (`max(4 × probe_interval, 3 s)`), then a resend round trip, and
a dial timeout when the next route has to be dialed first; the Phase 2 chaos
run measured an 18 s stall when the last direct path died before a relay was
up. v1 also cannot duplicate VIP streams or use FEC, because smux interleaves
every stream into one byte stream and loses track of which bytes belong to
which stream.

ARCHITECTURE §9.1 asks for v2: per-session sequencing, selective ACK,
reordering, retransmission on a different path, FEC, per-path congestion
control, behind the unchanged `Session` interface.

## Decision
1. **Negotiation.** The initiator offers `CapMultipath` (spec §8) when
   `session.version = 2` (the default). The session is v2 when the
   responder's Welcome keeps the bit, else v1 on the same path. Every later
   path of the session joins with the session's version. Phase 2 nodes keep
   working with Phase 3 nodes over v1.
2. **Own stream layer, not smux.** v2 replaces smux. A stream is identified
   by a `u32` id (initiator odd, responder even) and carries the same stream
   header and reply byte as v1 (spec §6). Stream bytes travel in `STREAM`
   frames with an explicit offset, so the receiver reassembles each stream
   on its own and a duplicate or late copy is simply dropped.
3. **Packets per path.** Every path has its own packet number space and is
   acknowledged on itself with `ACK` frames carrying ranges (selective ACK).
   A path is identified on both sides by a 64-bit id taken from the Noise
   handshake hash, so no signalling is needed (FEC refers to it, §4 of
   ADR-0014). Loss detection follows RFC 9002 (packet threshold 3, time
   threshold 9/8 RTT, probe timeout). The frames of a lost packet are
   queued again and preferably sent on a *different* path.
4. **All healthy paths are used.** Each side schedules on its own; there is
   no ACTIVATE. A packet goes on the best-ranked path that has room in its
   congestion window; a lower-ranked path takes data only when the ones
   above it are full (min-RTT scheduling). The controller ranks paths with
   hysteresis (ADR-0015); without its input paths are ranked by smoothed RTT,
   direct before relayed.
5. **Fast failover.** When a path's probe timeout fires, its unacknowledged
   frames are copied to other paths at once and the path stops taking new
   data until it is acknowledged again ("suspect"). A blackholed path
   therefore costs about one probe timeout (RTT + 4 × RTT variance + ACK
   delay), not the watchdog. A path is removed when it has made no progress
   (nothing received, or nothing acknowledged while data is outstanding)
   for `DeadAfter`.
6. **Per-path congestion control.** Each path has an in-flight limit derived
   from its measured delivery rate and minimum RTT (BBR-like: 2 × rate ×
   min RTT plus headroom, between 256 KiB and 32 MiB), cut multiplicatively
   when a datagram path loses packets that FEC did not recover. The
   transport's own congestion control (TCP, QUIC) paces the wire; the limit
   keeps queues short so a dying path holds little data.
7. **VIP duplication.** Stream data of a `vip` stream is sent on the best
   path and again on the best path to a different peer address or address
   family. Whichever copy arrives first is used.
8. **Flow control.** Per stream (2 MiB) and per session (16 MiB) receive
   windows, credited with `MAX_STREAM_DATA` and `MAX_DATA` as the reader
   consumes, as in v1's smux configuration.
9. **Close.** `Close` sends `FIN` after the data already written and `STOP`
   for the other direction; buffered data is still delivered. This matches
   v1, where the end of one direction of a pipe ends the connection.
10. **Rotation.** `Join(rotate=true)` adds the new path and drains the
    path ranked first: it takes no new data, and once its packets are
    acknowledged (or after 2 s) it is closed with `CLOSE(rotate complete)`.
11. **Invariant kept from v1.** A path's reader never writes to the path.
    Each path has one writer goroutine; readers only change state and wake
    writers.

## Consequences
- `node` works with a `session.PeerSession` interface that both versions
  implement; v1 stays for interoperability and as a fallback
  (`session.version = 1`).
- `skip_double_encryption` stays ignored: v2 packs frames of several
  streams into one encrypted packet. Doing it safely needs per-stream
  records and is moved to Phase 4 hardening.
- UDP flows still ride reliable streams (spec §6.1); unreliable datagram
  streams are a later extension.
- The wire format is in spec §11.
