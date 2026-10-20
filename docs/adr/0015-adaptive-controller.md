# ADR-0015: Adaptive controller

Status: Accepted

## Context
ARCHITECTURE §11 describes a component that observes path metrics and
decides, never touching sockets, as pure logic that can be tested with
recorded scenarios. Phase 2 ordered candidate routes by fixed diversity
weights only (ADR-0011) and left measured scores to Phase 3.

## Decision
1. **Package `controller`** is pure: `(*Controller).Decide(Input) Output`.
   The controller keeps only its own memory (smoothed values, hysteresis
   state, dial history). The node calls it once a second with a snapshot
   and applies the output.
2. **Inputs.** For every path of every live session: transport, peer
   address, relayed or direct, smoothed RTT and variance, packets sent and
   lost since the last tick, FEC recoveries, and whether it is a datagram
   path. For the mesh: every dial and handshake attempt since the last tick
   (transport, peer address, success).
3. **Loss** of a path is smoothed per tick from the larger of two rates:
   sent packets lost and not rebuilt by FEC, and the raw loss of the
   incoming direction (packet numbers that never arrived from the wire,
   before FEC). The sender cannot see its own losses that the peer's FEC
   repaired, since those are acknowledged; sizing FEC on them alone would
   make it oscillate. Using the incoming direction assumes loss is about
   the same both ways.
4. **Path score** = smoothed RTT × (1 + 8 × loss) + 2 × RTT variance, plus
   a fixed penalty for relayed paths and for paths that keep losing. A new
   best path replaces the current first rank only when it is at least 20 %
   better for 3 ticks in a row (hysteresis), so ranks do not flap.
5. **Outputs.**
   - path ranks per session (session v2 schedules on them, ADR-0013);
   - FEC parity `m` per session in adaptive mode: raised at once when loss
     crosses a threshold (0.5 %, 2 %, 5 %, 10 % → 1..4 parity, capped by
     `max_parity_shards`), lowered only after 10 s below it;
   - paths to replace: a path losing more than 25 % for 5 ticks is
     reported, and its peer link rotates it away;
   - transport demotion: a transport whose dials failed at least 3 times on
     at least 2 peer addresses within 60 s, spread over at least 5 s, with
     no success, is demoted for 5 minutes (a burst at one moment is peers
     still starting, not a block). The mesh planner then tries it after every other transport
     of equal diversity; it is never dropped completely;
   - a health factor per peer (0.1–1, from its best path's loss and from
     whether it is only relayed) that scales the peer's weight for tunneled
     streams in the scheduler.
6. **What stays elsewhere.** Quarantine backoff stays in `mesh`, rotation
   by bytes and time in the peer link, and relay fallback in the peer link
   (ADR-0011, ADR-0012); the controller only adds measured signals.

## Consequences
- The planner orders candidates by diversity first, then by measured route
  score and demotion; the interface of ADR-0011 is unchanged.
- Every decision is unit-tested from recorded inputs.
- Status shows path scores, loss and FEC level.
