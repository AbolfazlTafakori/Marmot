# ADR-0012: Relay routing carries session paths, not user streams

Status: Accepted

## Context
ARCHITECTURE §7.4 asks for relay routing when no direct path to a peer is
healthy, with the user payload kept end to end so the relay cannot read
it. The Phase 0 spec (§7) sketched per-stream relaying: a user stream's
header names the remaining hops and each relay opens the next stream. That
decrypts the user bytes at every relay (each hop is its own session), and
every user connection would pay a relay round trip to open.

## Decision
1. **A relayed path is a path of the end-to-end session.** The origin opens
   a *path stream* to a relay over its session with that relay. The relay
   opens a path stream to the next hop and pipes bytes. The last node hands
   the stream to its session acceptor as if it came from a listener. The
   origin then runs the normal Noise handshake to the target over it, as a
   new session or as a join of an existing one. The relay sees only Noise
   ciphertext, and failover between direct and relayed paths is ordinary
   session v1 failover.
2. **Wire format.** A path stream starts with stream header version 3:
   `version=3 | route_len | route`. The route lists the hops after the
   receiving node; empty means "hand to your acceptor". Each hop answers
   with the usual reply byte after its own next hop has answered, so the
   origin learns the outcome before the handshake. User streams never carry
   a route; one that does is refused.
3. **Transit policy.** A node relays only with `relay.allow_transit = true`,
   only to a peer it has a session with, never back to the sender or to
   itself, never along a route that repeats a node, and only if the route
   plus the hop it arrived on is at most `relay.max_hops`. Anything else is
   answered `3` (denied) or `2` (unreachable).
4. **No nesting.** Origin and relays carry path streams only on sessions
   whose active path is direct, so a relayed path never runs inside another
   relayed path.
5. **Choosing relays.** Every other configured peer with a direct session
   is a relay candidate. Whether it allows transit is learned by trying: a
   refusal quarantines that relay like a failed route (ADR-0011). Relayed
   candidates are diverse from every direct one. While no direct path is
   up, direct and relayed routes are tried in turn (a blackholed direct
   route costs a full dial timeout per try). While a session runs on a
   relay, every maintenance tick tries a free direct route and, when it
   works, moves the session onto it make-before-break.
6. **Phase 2 routes have one relay** (origin → relay → target). The header
   and the transit rules already allow longer routes; picking them needs
   topology knowledge, which comes with the controller.

## Consequences
- Spec §7 is replaced by this design; stream header version 3 is added.
- A peer reached only through relays has state `relayed`; `/metrics` gains
  `marmot_peer_relayed`, `marmot_relay_transit_paths` and
  `marmot_relay_transit_bytes_total`.
- The capability bit "relay transit allowed" is still sent, but the
  handshake intersects capabilities, so it cannot tell the dialer whether
  the other side relays; trying is authoritative.
- A relay spends bandwidth on others' traffic, so relays are used only
  while no direct path is up.
