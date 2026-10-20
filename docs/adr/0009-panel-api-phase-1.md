# ADR-0009: Panel API adjustments for Phase 1

Status: Accepted

## Context
The Phase 0 API contract (`backend/api/openapi.yaml`) was written before the
config schema and the session layer existed. Implementing it in Phase 1
showed places where the contract promises something the schema cannot hold
yet, or where a field belongs to a different node.

## Decision
1. **Endpoint direction.** The config schema has no `direction`; reverse
   connections arrive in Phase 4. Until then the API accepts only
   `direction: outbound`. A peer with **no endpoints** is inbound-only (it
   dials us), so `Peer.endpoints` may be empty. Views report `outbound`.
2. **`PortRule.preserveClientIp` is removed.** PROXY v2 is written by the
   node that delivers to the panel, not the node that owns the user port.
   It is configured there through `panel_integration` (`PUT /config`).
3. **Health numbers that need the adaptive controller (Phase 3):**
   `lossPct` and `jitterMs` are `0`; `PathView.score` is a heuristic
   (`1` for the active path, `1/(1+rtt/100ms)` for standbys);
   `throughputBps` is the path's average since it was established.
4. **Partial apply.** `PUT /config`, `/steering` and `/peers*` validate
   first and never write an invalid file. If the file is valid but part of
   it cannot be applied (a port is held by another process), the file is
   kept, everything else is applied, and the response carries `warnings`.
5. **Changing `node.id` or `node.identity_key_file`** through the API is
   rejected with 422: it needs a restart.
6. **Comments.** Edits made through the panel re-encode `marmot.toml`;
   comments in the file are not kept. Editing the raw TOML with
   `PUT /config` keeps the text exactly as sent.
7. **Readiness and metrics.** `GET /readyz` (no auth) is added next to
   `/healthz`. Prometheus metrics are served at `/metrics` on
   `telemetry.metrics_listen`, a separate listener, never on the panel port.
8. **Runtime tuning.** `GOMEMLIMIT` is derived from the container's cgroup
   limit unless set; `GOGC` is taken from the environment, as the Go
   runtime does. Neither is in `marmot.toml`.
9. **Join token** format: `mt1.<base64url(JSON payload)>.<base64url(Ed25519
   signature)>`, signed by the node's identity key. The payload holds the
   node id, public key, `local.ipv4_pool`, `local.ipv6_subnet` and the
   inter-node listeners (transport, port, and only the `sni` option; file
   paths are never exported). A token without addresses imports as an
   inbound-only peer.

## Consequences
- The frontend is generated from the updated contract and never shows a
  setting that has no effect.
- Points 1 and 3 are revisited in Phase 3 and 4; the fields stay in the
  contract so clients do not change shape.
