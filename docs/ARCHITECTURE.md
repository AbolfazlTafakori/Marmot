# Marmot — System Architecture

Status: **v0.3** — Phase 1 implemented (see §18). Changes made while implementing it are recorded in [ADR-0009](adr/0009-panel-api-phase-1.md).
Audience: the agents and engineers implementing Marmot. Decisions with lasting impact are recorded as ADRs in [`docs/adr/`](adr/).

---

## 1. Purpose and scope

Marmot is a **transport layer** between servers. It carries the traffic of selected ports from one server to another over a resilient, multi-path, self-healing mesh, so that proxy panels (3x-ui, x-ui, W-UI, Pasargad/Marzban, Hiddify, or any panel of this style) keep working when individual IPs, routes, or protocols degrade or are blocked.

### Goals
1. **Resilience** — a connection survives the loss of any single IP, path, transport, or address family (IPv4/IPv6).
2. **Low latency, stable p99** — the user should not feel path switches.
3. **Self-management** — paths are measured continuously; traffic moves to healthy paths automatically.
4. **Extensibility** — a new transport is one new package behind one interface; nothing else changes.
5. **Operability** — web panel, hot reload, metrics, no lock-out of the server.

### Non-goals
- Marmot **never** creates proxy users, accounts, or subscription links. Panels do that; Marmot is panel-agnostic and needs no integration with a specific panel beyond optional PROXY v2.
- Marmot does **not** forge source addresses that belong to third parties (see [ADR-0005](adr/0005-no-third-party-ip-spoofing.md)).
- Marmot does **not** modify global firewall rules. It only binds the ports it is told to.

### Port model in one picture
```
User config (from the panel):  vless://…@iran-ip:2052
                                          │
             ┌────────────────────────────┴─────────────────────────────┐
  port 2052 is in tunneled_ports                 port 2022 is NOT listed
             │                                              │
  Marmot owns it: carries the bytes over        Marmot never binds it: the connection
  whatever transports/ports/IPs are healthy     goes straight to whatever service on
  between servers (443/tls, 2083/ws, QUIC        that server listens on 2022 (or to the
  40000-50000, relay, …) and delivers them      address in the user's config). Untouched.
  to the panel inbound on the other side.
```
The **user-facing port** never changes; the **inter-node transports and ports** behind it change freely and are invisible to the user (§6.1).

---

## 2. Glossary

| Term | Meaning |
|---|---|
| **Node** | One running Marmot instance on one server. Identified by `node.id` and an Ed25519 identity key. |
| **Peer** | Another node this node is configured to talk to. |
| **Endpoint** | One reachable address of a peer: `(ip, port, transport)`. A peer has many. |
| **Path** | A live link from one local address to one peer endpoint over one transport. The unit of health measurement. |
| **Session** | An authenticated, encrypted association between two nodes, carried over one or more paths. |
| **Stream** | One end-user connection (TCP) or flow (UDP) multiplexed inside a session. |
| **Traffic class** | `tunneled` or `vip`. Decides scheduling policy. Unlisted ports are not touched at all (bypass). |
| **Transport** | A pluggable wire protocol (TCP, TLS, WebSocket, gRPC, QUIC, …) that yields a byte stream or datagram channel. |

---

## 3. Deployment topologies

### 3.1 Relay mode (panel abroad)
```
user ──► [Iran node :443] ══ Marmot mesh ══► [Foreign node] ──PROXY v2──► panel inbound :443
```
The Iran node accepts user connections on `tunneled_ports`, carries them to the foreign node, which connects to the local panel inbound and prepends a **PROXY protocol v2** header with the user's real IP, so panel IP-limits keep working.

### 3.2 Exit mode (panel in Iran)
```
user ──► panel (Iran) ──outbound──► [Iran node SOCKS5 127.0.0.1:1080] ══ mesh ══► [Foreign node] ──► Internet
```
The panel's outbound is pointed at Marmot's local SOCKS5. The foreign node is only an exit; no panel is installed there.

### 3.3 Mesh (N-to-M)
Any node can have many peers. Any node may act as a **relay** for another (§7.4), which is how traffic survives a direct Iran↔Foreign block.

---

## 4. Layered architecture

```
┌──────────────────────────── Control plane ─────────────────────────────┐
│  config (TOML, validate, hot reload)   api (REST+WS, auth)   metrics    │
└─────────────────────────────────────────────────────────────────────────┘
┌──────────────────────────── Data plane ────────────────────────────────┐
│ L5 Ingress / Egress   steering · proxyproto · socks5 · forwarder        │
│ L4 Session            stream mux · flow control · make-before-break     │
│ L3 Scheduler          path selection · VIP duplication · reordering     │
│ L2 Reliability        FEC (adaptive, datagram paths only)               │
│ L1 Path / Mesh        peers · endpoints · paths · probing · relay route │
│ L0 Transport          tcp · tls · ws · grpc · quic · …  (plug-ins)      │
└─────────────────────────────────────────────────────────────────────────┘
              ▲ metrics                      │ decisions
              └──────── Adaptive Controller ─┘
```

**Dependency rule:** a layer may import only layers below it, plus `internal/core` shared types. The control plane talks to the data plane only through the `Node` facade (§10). The data plane never imports `api`.

---

## 5. Data flow

### 5.1 Relay mode, one TCP connection
1. `steering.Listener` accepts on `:443`, classifies it (`tunneled` or `vip`), records the client `addr`.
2. `session.Manager` picks the session for the target peer (via `mesh.Router`) and opens a **Stream** with an `OPEN` frame carrying `{class, dst_port, client_addr}`.
3. Bytes are copied client↔stream using pooled buffers.
4. On the foreign node, the stream acceptor dials `127.0.0.1:<dst_port>` (the panel), writes a PROXY v2 header with `client_addr`, then copies bytes.
5. Close on either side propagates as `FIN`/`RST` frames; buffers return to the pool.

### 5.2 UDP
UDP flows (e.g. QUIC/Hysteria inbounds) are keyed by `(client_addr, dst_port)`, carried as datagram streams with an idle timeout. No reliability is added beyond FEC; the inner protocol handles it.

---

## 6. L0 — Transport plug-ins

### 6.1 Protocol agnosticism and the two port spaces
Marmot tunnels **raw TCP bytes and UDP datagrams**. It never parses the user's proxy protocol, so every protocol a panel can serve works unchanged: VLESS, VMess, Trojan, Shadowsocks, Reality, XHTTP, gRPC/WS/HTTPUpgrade inbounds, Hysteria2, TUIC, WireGuard, SSH, and any future one. UDP-based protocols require `protocols` to include `udp` for that port.

There are two independent port spaces, and config validation keeps them apart:

| Space | Configured in | Seen by user? | Example |
|---|---|---|---|
| **User ports** | `[steering]` | Yes — it is in their config | 443, 8443, 2052, 2057 |
| **Inter-node ports** | `[[peers.endpoints]]` + `[transport_listen]` | No | 443/tls, 2083/ws, 40000-50000/quic |

- A user port maps to a target port on the receiving node (`port_map`, default = same port), so the panel inbound may listen anywhere.
- If a user port and an inter-node listen port collide on the same node and protocol, the config is **rejected**, unless that listener is marked `shared = true`, in which case the listener demultiplexes Marmot handshakes from user traffic (Phase 4).

```go
// package transport
type Kind uint8 // Stream or Datagram

type Transport interface {
    Name() string
    Kind() Kind
    Dial(ctx context.Context, ep Endpoint, local netip.Addr) (Conn, error)
    Listen(ctx context.Context, cfg ListenConfig) (Listener, error)
}

type Conn interface {        // Stream kind: reliable ordered bytes
    io.ReadWriteCloser
    LocalAddr() net.Addr
    RemoteAddr() net.Addr
}

type PacketConn interface {  // Datagram kind: unreliable messages
    ReadPacket(b []byte) (int, error)
    WritePacket(b []byte) error
    Close() error
}
```

- Each transport lives in `internal/transport/<name>/` and registers itself in `init()` with `transport.Register`. Inclusion is controlled with Go **build tags** (`marmot_quic`, …), so unused transports are not compiled in.
- A transport knows nothing about sessions, peers, or FEC. It only moves bytes.
- Initial set (Phase 1–4): `tcp`, `tls` (uTLS fingerprints), `ws` (incl. reverse), `grpc`, `quic`.
- **Reverse** transports: the side that is reachable dials out; the logical direction of the session is independent of who dialed (§7.3).

---

## 7. L1 — Mesh, paths, routing

### 7.1 Path
`Path = (local addr, peer endpoint, transport)`. The path manager builds the **cartesian product** of local addresses × peer endpoints × enabled transports, filtered by address family, and keeps a configurable number of them warm.

### 7.2 Probing
Every path carries `PING/PONG` frames (default every 1 s, jittered). Per path we keep EWMA RTT, RTT variance, loss rate, throughput, and consecutive-failure count. These feed the Adaptive Controller (§11).

### 7.3 Connection direction
Each endpoint has `direction = outbound | inbound | both`. If Iran→Foreign is blocked but Foreign→Iran works, the foreign node dials and the session is established the same way. The session layer does not care who dialed.

### 7.4 Relay routing
When no direct path to a peer is healthy, `mesh.Router` looks for a route through another node (max 2 hops by default). Relay is **source-routed**: the `OPEN` frame carries the hop list; intermediate nodes forward the stream without decrypting the end-to-end payload (inner session keys are end-to-end, see §12).

### 7.5 IPv6 /64 rotation and multi-IP
Local and remote address pools are first-class. For an IPv6 `/64`, the path manager derives addresses deterministically per rotation epoch (both sides compute the same set from the shared session secret), so the set of active addresses changes over time without signalling. Requires the subnet to be routed to the host (documented in ops guide).

---

## 8. L2 — FEC

- Reed-Solomon (`klauspost/reedsolomon`, SIMD) over **datagram paths only**. On stream transports (TCP-based) FEC is pointless and disabled.
- Packets are grouped into blocks of `k` data + `m` parity shards; shards of one block are **spread across different paths**, so losing an entire path can be recovered.
- `k`/`m` are **adaptive**: the controller sets `m` from measured loss (e.g. `m = 0` under 0.5 % loss), so bandwidth is not wasted on clean networks.
- Receiver reconstructs as soon as any `k` shards arrive; a block that cannot be reconstructed within its deadline falls back to retransmission by the session layer.

---

## 9. L3/L4 — Scheduler and Session

### 9.1 Session protocol evolution (see [ADR-0003](adr/0003-session-layer-evolution.md))
- **v1 (Phase 1–2):** a stream multiplexer (`smux`) over a **resumable conn** ([spec §5](spec/frame.md)) that runs on the **best** path, with **hot-standby** paths already handshaken. Failover = activate a standby path and resend from the last acknowledged byte offset; no stream is reset. Make-before-break rotation reconnects a new path before closing the old one.
- **v2 (Phase 3):** a true multipath datagram session: per-session sequence numbers, selective ACK, reordering buffer, retransmission on a *different* path, FEC from §8, per-path congestion control. The `Session` interface stays the same, so L5 does not change.

```go
// package session
type Session interface {
    OpenStream(ctx context.Context, h StreamHeader) (Stream, error)
    AcceptStream(ctx context.Context) (Stream, StreamHeader, error)
    Close() error
}
```

### 9.2 Scheduling policy
| Class | Policy |
|---|---|
| `tunneled` | Weighted by path score; bulk flows prefer high-throughput paths. |
| `vip` | **Duplicated** over the two best paths on different address families/IPs; receiver de-duplicates by sequence. Small traffic, so the cost is negligible. |

### 9.3 Make-before-break rotation
A session is rotated (new path + fresh keys) after `rotate_bytes` or `rotate_interval`, whichever first. The new path is fully established and verified before streams migrate; the old one drains and closes. Users see no interruption.

---

## 10. L5 — Ingress / Egress and the Node facade

- **`steering`**: binds only `tunneled_ports` and `vip_control_ports` (TCP and/or UDP per port). Everything else is untouched → *bypass is implicit and cannot lock the server out*: an unlisted port (e.g. 2022) keeps reaching whatever listens on that server directly. Startup **refuses** a config that lists the SSH port or the panel/API port as tunneled. If a tunneled port is already bound by another process, startup reports which process owns it.
- **`proxyproto`**: PROXY v2 encoder/decoder (TCP4/TCP6/UDP), strict parsing, fuzz-tested.
- **`socks5`**: local SOCKS5 server (CONNECT + UDP ASSOCIATE) for exit mode, bound to loopback by default.
- **`forwarder`**: on the receiving node, dials the local target and pipes bytes (uses `splice` via `io.Copy` on `*net.TCPConn` where possible).

`node.Node` is the only object the control plane sees: `Start`, `Stop`, `Reload(cfg)`, `Snapshot() Status`, `Subscribe() <-chan Event`.

---

## 11. Adaptive Controller

A separate component that **observes** and **decides**; it never touches sockets.

- Inputs: per-path metrics (§7.2), per-transport success/failure history, FEC recovery rate.
- Path **score** = f(RTT, jitter, loss, throughput, recent failures), with hysteresis to avoid flapping.
- Decisions: active/standby path set per peer, scheduler weights, FEC `m`, when to rotate, when to try relay routes, when to retry a quarantined path (exponential backoff).
- Detects **blocking patterns** (e.g. a transport that fails on all IPs at once) and demotes that transport globally for a cool-down period.
- Pure, deterministic logic: `Decide(state, metrics) → actions`. This makes it fully unit-testable with recorded scenarios.

---

## 12. Security model ([ADR-0004](adr/0004-per-node-identity-keys.md))

- Each node has an **Ed25519 identity key**; peers are pinned by public key in config. No shared mesh-wide secret.
- Session handshake: **Noise IK** (`flynn/noise`, X25519 + ChaCha20-Poly1305 + BLAKE2s). Forward secrecy; keys rotated on every make-before-break.
- `skip_double_encryption`: for streams whose inner protocol is already TLS/Reality, payload is not re-encrypted, but frame headers stay authenticated. Control frames are always encrypted.
- Revocation: removing a peer key from config + hot reload terminates its sessions immediately.
- Replay protection on handshake (timestamp + nonce cache).
- Panel/API: argon2id password hashes, TOTP 2FA, HttpOnly SameSite session cookie, CSRF token, optional IP allow-list, rate-limited login. API port is always bypassed and refused as a tunneled port.

---

## 13. Control plane

### 13.1 Config
- **Source of truth:** `marmot.toml` ([ADR-0006](adr/0006-config-file-source-of-truth.md)). The panel edits it through the API: validate → write atomically (temp file + rename) → `Node.Reload`. A bad config is rejected; the running config stays.
- Panel users and audit log live in a small embedded SQLite (`modernc.org/sqlite`, pure Go, no CGO).
- Revised schema: [`docs/config.example.toml`](config.example.toml).

### 13.2 API
- REST under `/api/v1`, JSON. Live status and events over WebSocket `/api/v1/ws`.
- OpenAPI spec in `backend/api/openapi.yaml` is the contract between backend and frontend; frontend types are generated from it.

### 13.3 Observability
- Structured logs (`log/slog`, JSON). No user payloads or full client IPs at info level.
- Prometheus metrics at `/metrics` (paths, sessions, streams, bytes, FEC recoveries, failovers).
- `/healthz` and `/readyz` for Docker; the image's HEALTHCHECK runs `marmot health`.
- Prometheus metrics are on their own listener (`telemetry.metrics_listen`), never on the panel port.

---

## 14. Repository layout

```
Marmot/
├── backend/
│   ├── cmd/marmot/            # main: flags, wiring, signal handling
│   ├── internal/
│   │   ├── core/              # shared types: NodeID, Class, errors, buffer pool
│   │   ├── config/            # schema, load, defaults, validate
│   │   ├── node/              # Node facade, lifecycle, reload
│   │   ├── steering/          # port listeners + classifier
│   │   ├── proxyproto/        # PROXY v2
│   │   ├── socks5/            # exit-mode inbound
│   │   ├── forwarder/         # receiving-side dialer + pipe
│   │   ├── session/           # Session/Stream interfaces, v1 mux, v2 later
│   │   ├── frame/             # wire format codec
│   │   ├── scheduler/         # path selection, VIP duplication
│   │   ├── fec/               # Reed-Solomon blocks
│   │   ├── mesh/              # peer, endpoint, path, pathmanager, router
│   │   ├── controller/        # adaptive controller (pure logic)
│   │   ├── crypto/            # identity, noise handshake, rotation
│   │   ├── transport/         # interface + registry
│   │   │   ├── tcp/ tls/ ws/ grpc/ quic/
│   │   ├── api/               # HTTP handlers, auth, ws hub
│   │   ├── store/             # SQLite: users, audit
│   │   └── telemetry/         # slog setup, prometheus
│   ├── api/openapi.yaml
│   ├── test/                  # integration + chaos (docker, netem)
│   ├── Dockerfile
│   └── go.mod
├── frontend/
│   ├── src/
│   │   ├── app/               # routing, providers, layout
│   │   ├── features/          # dashboard, peers, ports, settings, users, logs
│   │   ├── shared/            # ui kit, api client (generated), i18n (fa/en), hooks
│   ├── Dockerfile
│   └── package.json
├── deploy/docker-compose.yml
└── docs/
```

**File rules:** one primary type per file, files named after it (`path_manager.go`, `path_manager_test.go`). Target < 300 lines per file; split by responsibility, not by line count.

---

## 15. Performance rules (from day one)

1. No allocation on the per-packet hot path: buffers from `core.BufPool` (`sync.Pool` of fixed sizes).
2. Bulk copy uses `io.CopyBuffer` with pooled buffers; TCP↔TCP uses kernel `splice` when available.
3. One goroutine per direction per stream; no goroutine per packet.
4. Locks are never held across I/O. Hot read paths use `atomic` snapshots.
5. `GOMEMLIMIT` set from container limit; `GOGC` tunable via config.
6. Every hot-path package ships `Benchmark*` tests; CI fails on > 10 % regression.

---

## 16. Testing strategy

| Level | What | Tooling |
|---|---|---|
| Unit | every package, table-driven | `go test -race` |
| Fuzz | `frame`, `proxyproto`, `config`, `socks5` parsers | `go test -fuzz` |
| Property | FEC: any `k` of `k+m` shards reconstruct | `testing/quick` |
| Integration | 3-node mesh in Docker, real panels optional | `testcontainers-go` |
| **Chaos** | loss, latency, path blackhole, whole IPv4 down, IP blocked mid-transfer → assert no stream breaks | `tc netem`, `iptables` inside test containers |
| Benchmark | throughput, allocs/op, p99 latency | `go test -bench`, `benchstat` |
| Frontend | components + API mocks; e2e on compose stack | Vitest, Playwright |

Merge gate: `gofmt`, `golangci-lint` (strict profile), all tests with `-race`, coverage ≥ 80 % on `internal/` (except `cmd`), no benchmark regression.

---

## 17. Deployment

- `backend/Dockerfile`: multi-stage, static binary, `gcr.io/distroless/static` runtime, non-root, ~20 MB.
- `frontend/Dockerfile`: multi-stage build → static files served by the backend in production (single container, fewer moving parts) or by nginx in dev.
- `deploy/docker-compose.yml`: `network_mode: host` (no Docker NAT on the data path) and `cap_add: [NET_ADMIN, NET_BIND_SERVICE]`; volume for `marmot.toml` and SQLite.

---

## 18. Phases and ownership

| Phase | Deliverable | Packages (one agent each, no overlap) |
|---|---|---|
| 0 | This doc, ADRs, OpenAPI draft, config schema | docs |
| 1 | Relay mode end-to-end over `tcp`/`tls`, one peer, PROXY v2, panel login + status | core, config, frame, session(v1), transport/tcp+tls, steering, proxyproto, forwarder, node, api, store, frontend shell |
| 2 | Multi-peer, multi-IP, dual-stack, failover, relay routing, exit mode | mesh, scheduler, socks5, transport/ws+grpc |
| 3 | Adaptive controller, session v2 multipath, FEC, QUIC | controller, session(v2), fec, transport/quic |
| 4 | More transports, reverse modes, /64 rotation, hardening | transport/*, mesh |

Each phase ends with the chaos suite green before the next begins (`backend/test/chaos/`, run with `make chaos`).

**Phase 1 status: done.** All Phase 1 packages are implemented and tested; the chaos suite passes (a verified 30 s stream survives each route being blackholed in turn). Notes for Phase 2:
- `node` holds a small per-peer link (`peer_link.go`) that dials, keeps hot standbys and rotates paths; `mesh` replaces it.
- `node.Open` picks a peer by weight; the `scheduler` replaces it.
- Session v1 failover stalls for up to `max(4 × probe_interval, 3 s)`, the time to declare a path dead (ADR-0003 accepts this for v1).
- Invariant in `session`: a path's reader never writes to the path; control writes go through its control loop. Breaking it deadlocks two full pipes.

---

## 19. Resolved decisions

| Question | Decision |
|---|---|
| Frontend stack | React + TS + Vite + Tailwind ([ADR-0002](adr/0002-frontend-react.md)) |
| Languages (UI) | Persian (RTL, default) and English |
| Platforms | Ubuntu 20.04–26.04, Debian 11+ (Tier 1); Alma/Rocky 8+ and Docker (Tier 2) ([ADR-0007](adr/0007-platform-support.md)) |
| Licence | Proprietary; strict dependency licence policy ([ADR-0008](adr/0008-license-and-dependency-policy.md)) |
| PROXY v2 certification order | 3x-ui → Marzban/Pasargad → Hiddify → W-UI |

## 20. Phase 0 artefacts
1. Wire format specification: [`docs/spec/frame.md`](spec/frame.md).
2. API contract: [`backend/api/openapi.yaml`](../backend/api/openapi.yaml).
