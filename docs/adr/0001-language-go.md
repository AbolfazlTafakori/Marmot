# ADR-0001: Backend language is Go

Status: Accepted

## Context
Marmot must react quickly to a changing censorship environment: when a protocol or technique is blocked, a new transport must ship in days, not weeks. It must also be fast and have stable latency.

## Decision
Write the backend in Go.

## Rationale
- New circumvention transports usually appear first in the Go ecosystem and can be imported as libraries.
- Seconds-long build/test cycles; simple code that any engineer or agent can read.
- Performance is close to Rust for network I/O; the main bottleneck is the network itself.

## Consequences
- GC pauses are mitigated by the performance rules in ARCHITECTURE §15 (pooled buffers, no hot-path allocation, `GOMEMLIMIT`).
- If profiling ever proves a single component (e.g. FEC) is the bottleneck, that component alone may be reimplemented behind its existing interface. No such work is planned.
