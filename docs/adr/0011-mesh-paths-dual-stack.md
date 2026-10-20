# ADR-0011: Mesh paths, dual stack and quarantine

Status: Accepted

## Context
Phase 2 makes a peer reachable over every combination of its addresses,
ports and transports, from every local address, over IPv4 and IPv6. The
Phase 1 config can name IPv4 addresses (`ipv4_pool`) but for IPv6 only a
`/64` (`ipv6_subnet`), which is meant for the rotating addresses of
Phase 4 and does not say which address a peer actually listens on.

## Decision
1. **`ipv6_pool`** is added to `[local]` and to `[[peers]]`: plain IPv6
   addresses, used exactly like `ipv4_pool`. `ipv6_subnet` keeps its
   Phase 4 meaning and is not dialed in Phase 2. A peer with endpoints
   needs at least one of `ipv4_pool`, `ipv6_pool`, `ipv6_subnet`.
2. **Candidates.** A peer's paths are the product of local addresses ×
   peer addresses × endpoint ports × transport, within one address family
   (IPv4 to IPv4, IPv6 to IPv6) and filtered by the endpoint's `family`.
   With no local addresses of a family, the system picks the source.
3. **Diversity.** A standby path is chosen to differ as much as possible
   from the paths already up, in this order of weight: address family,
   peer address, local address, transport, port. The aim is that one
   failure (an address family down, an IP blocked, a transport blocked)
   does not take the standby with it.
4. **Quarantine.** A candidate that fails to dial or handshake is not
   retried until its backoff passes: 1 s, doubling per failure, capped at
   5 minutes; a success clears it. This replaces the Phase 1 round robin,
   which retried dead routes at full rate.
5. **Layers.** `mesh` holds this logic and dials transport connections; it
   does not import `session`. `node` builds sessions on the paths `mesh`
   hands it.

## Consequences
- The API `Peer` gains `ipv6Pool`, join tokens carry the local
  `ipv6_pool`, and the panel's peer form gains the field.
- Phase 3's controller replaces the fixed diversity weights with measured
  path scores; the interface stays.
