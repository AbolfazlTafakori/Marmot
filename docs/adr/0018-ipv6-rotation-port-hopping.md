# ADR-0018: IPv6 /64 rotation and port hopping

Status: Accepted

## Context
A censor that blocks addresses or ports one at a time is slowed by paths
that keep moving. ARCHITECTURE §7.5 asks for rotating source and
destination addresses inside an IPv6 /64, and the config already has
`local.ipv6_rotation` and `peers.ipv6_subnet` (ADR-0011 left them unused),
and `hop_interval` on endpoints (ADR-0014 left it for Phase 4).

## Decision
1. **Rotating addresses.** For each rotation epoch (`local.ipv6_rotation.
   epoch`) the node derives `active` addresses of a /64: the prefix and 64
   bits of SHA-256(subnet, node id, epoch, index). Derivation is local; no
   agreement with the peer is needed, because a listener on `[::]` accepts
   every address of a /64 routed to the host as local (operators add
   `ip -6 route add local <subnet> dev lo`).
   - **Source:** with rotation enabled, IPv6 paths are dialed from the
     current epoch's addresses of `local.ipv6_subnet` (instead of
     `ipv6_pool`). Sockets use `IPV6_FREEBIND`, so the address needs no
     configuration on an interface (Linux).
   - **Destination:** a peer's `ipv6_subnet` adds the current epoch's
     derived addresses of that /64 (with the peer's id) to its addresses.
2. **Epoch change.** The link rebuilds its candidates at every epoch.
   Paths on addresses of an earlier epoch are replaced make-before-break,
   one per pass, so traffic never stops.
3. **Port hopping.** A path dialed on an endpoint with `port_range` and
   `hop_interval` is replaced after `hop_interval` by one on another
   random port of the range, make-before-break.
4. Replacements count as rotations (events, metrics) and keep the
   quarantine of every route.

## Consequences
- Rotation needs Linux and a routed /64; elsewhere `ipv6_rotation` is
  rejected at start with a clear error.
- A rotation epoch shorter than a path's life costs one extra handshake
  per path per epoch.
