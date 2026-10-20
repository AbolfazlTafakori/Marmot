# ADR-0003: Session layer ships in two versions behind one interface

Status: Accepted

## Context
A true multipath session (sequence numbers, SACK, reordering, per-path congestion control, FEC) is the end goal, but it is the hardest part of the system. Building it first would delay any working tunnel by months.

## Decision
- **v1:** `smux` stream multiplexing over a resumable byte stream (offsets + ACK + RESUME) on the best path, with hot-standby paths and make-before-break failover. Streams survive path changes.
- **v2:** custom multipath datagram session with FEC, introduced in Phase 3.
Both implement `session.Session`; ingress/egress code never changes.

## Consequences
- Phase 1 delivers a working, resilient tunnel quickly.
- v1 failover may cause a short stall (the in-flight window on the failed path is resent); v2 removes it.
- The chaos test suite written for v1 is reused unchanged to validate v2.
