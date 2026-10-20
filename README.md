# Marmot

Resilient multi-path tunnel mesh for proxy panels (3x-ui, x-ui, W-UI, Pasargad/Marzban, Hiddify, and similar).
Marmot does not issue user configs; it carries selected ports between servers and keeps them alive when IPs, routes or protocols fail.

**Status:** Phase 1 complete — relay mode end to end over `tcp`/`tls` (uTLS), PROXY v2, hot-standby failover and make-before-break rotation, hot reload, panel with login (TOTP), live status and configuration editing. Phase 2 (multi-peer mesh, relay routing, exit mode) is next.
**Platforms:** Ubuntu 20.04–26.04, Debian 11+, AlmaLinux/Rocky 8+, Docker (amd64, arm64).
**Licence:** proprietary — see [`LICENSE`](LICENSE).

| Path | Contents |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | System design |
| [`docs/adr/`](docs/adr/) | Architecture decision records |
| [`docs/spec/frame.md`](docs/spec/frame.md) | Wire protocol v1 |
| [`docs/deploy.md`](docs/deploy.md) | Installing and operating a node (Docker or systemd) |
| [`backend/api/openapi.yaml`](backend/api/openapi.yaml) | Panel API contract |
| [`docs/config.example.toml`](docs/config.example.toml) | Configuration reference |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Rules for engineers and agents |
| `backend/` | Go: tunnel core, panel API, `marmot` command |
| `backend/test/chaos/` | Chaos suite (blackholed routes under load) |
| `frontend/` | React: web panel (Persian RTL and English) |
| `deploy/` | Docker Compose for one node |

## Quick start

```sh
docker build -f backend/Dockerfile -t marmot .
cd deploy && cat ../docs/deploy.md   # first-start steps: config, keygen, first admin
```

## Development

| Task | Command |
|---|---|
| Whole merge gate | `make check` |
| Go tests / race | `make test` / `make race` |
| Strict lint | `make lint` (golangci-lint v2) |
| Licence policy (ADR-0008) | `make licenses` |
| Chaos suite (Docker) | `make chaos` |
| Panel dev server | `cd frontend && npm run dev` (proxies `/api` to `MARMOT_API`, default `127.0.0.1:7443`) |
