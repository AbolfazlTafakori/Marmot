# ADR-0017: Endpoint direction

Status: Accepted

## Context
ARCHITECTURE §7.3 lets the reachable side dial out: if Iran→Foreign is
blocked but Foreign→Iran works, the foreign node dials and the session is
the same. Sessions are already symmetric: a node routes streams over
inbound sessions as well as its own (ADR-0009), and session v2 lets either
side use every path. Until now the API accepted only `direction:
outbound`, and a peer without endpoints was inbound-only.

## Decision
1. `[[peers.endpoints]] direction` is `outbound` (default), `inbound` or
   `both`.
   - `outbound`: this node dials the endpoint.
   - `inbound`: this node never dials it; the peer dials us. The endpoint
     stays in the config to document the route and to keep join tokens
     symmetric.
   - `both`: this node dials it, and the peer is expected to dial us too.
2. A peer whose endpoints are all `inbound` has no outbound link, as a
   peer without endpoints.
3. Only the dialing side adds, rotates and replaces paths (ADR-0013); a
   node relies on the peer's link for an inbound-only peer.

## Consequences
- Reverse connections need no new protocol: they are the peer's ordinary
  outbound link.
- The panel offers the three values.
