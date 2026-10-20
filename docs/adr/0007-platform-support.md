# ADR-0007: Supported platforms

Status: Accepted

## Decision

| Tier | Platform | Meaning |
|---|---|---|
| 1 | Ubuntu 20.04, 22.04, 24.04, 26.04 | Built, tested in CI (incl. chaos suite), supported |
| 1 | Debian 11, 12 | Same as above |
| 2 | AlmaLinux / Rocky Linux 8, 9 | Built and smoke-tested; supported on a best-effort basis |
| 2 | Any Linux with Docker ≥ 20.10 | Runs the official image |
| Dev only | macOS, Windows | Compile and run unit tests; not supported as server nodes |

Architectures: `linux/amd64` and `linux/arm64`.

## Rationale
- Marmot ships as one static Go binary (no CGO), so it runs on any Linux kernel ≥ 4.x; the tiers describe what is *tested*, not what merely runs.
- The minimum kernel in Tier 1 is 5.4 (Ubuntu 20.04). Features used: `splice`, `SO_REUSEPORT`, IPv6 non-local bind (`net.ipv6.ip_nonlocal_bind`) for /64 rotation — all available in 5.4.
- Ubuntu 20.04 is past standard support upstream but is still common on VPS providers, so it stays in Tier 1. It will be dropped in a future major version with notice.
- Windows/macOS servers are not targets: Linux-only socket features are needed, and VPS nodes are Linux.

## Consequences
- Build-tag-gated Linux code (`//go:build linux`) with portable fallbacks, so the project still compiles on macOS/Windows for development.
- An install script (`deploy/install.sh`) supports Tier 1 and Tier 2 distributions: binary + systemd unit, or Docker.
