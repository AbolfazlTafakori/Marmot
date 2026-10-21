# ADR-0019: Unreliable datagrams for UDP flows

Status: Accepted

## Context
UDP flows (Hysteria2, TUIC, WireGuard, QUIC-based inbounds) ride reliable
streams (spec §6.1): a lost packet is resent and holds back every later
one, while the inner protocol already recovers loss itself and only wants
its datagrams fast or not at all.

## Decision
1. Capability bit 4 `datagrams` (session v2 only). When both sides keep
   it, a UDP flow still opens a stream (header and reply byte, spec §6),
   but its payloads travel in `DATAGRAM` frames: `0x08 | sid:v | len:v |
   data`.
2. DATAGRAM frames are never resent and bypass flow control. A receiver
   holds at most 256 unread datagrams per stream and drops the rest.
3. A payload that does not fit in one packet of the path that would carry
   it goes on the stream as before (`len:u16 | payload`), so large
   datagrams still arrive. The receiver reads both.
4. Datagrams may arrive out of order, as UDP does.

## Consequences
- Loss of a UDP flow's packet costs that packet only, not a stall.
- Peers without the bit keep stream framing; nothing else changes.
