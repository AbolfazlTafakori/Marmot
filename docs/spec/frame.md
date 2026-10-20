# Marmot Wire Protocol — v1

Status: Draft (Phase 0). Byte order is big-endian. Sizes are in bytes.
Implemented by: `internal/crypto` (handshake), `internal/frame` (records, codec), `internal/session` (resumable conn, mux).

The protocol is independent of any proxy panel and of the user's proxy protocol: user traffic is opaque bytes/datagrams.

---

## 1. Layering

```
 user TCP bytes / UDP datagrams
            │
 ┌──────────┴───────────┐
 │ Stream header (§6)    │  first bytes of every mux stream
 │ smux (v1)             │  stream multiplexing           ← replaced in v2
 │ Resumable conn (§5)   │  byte offsets, ACK, RESUME → survives path changes
 │ Record layer (§4)     │  AEAD records, padding
 │ Handshake (§3)        │  Noise IK, once per path
 └──────────┬───────────┘
        Transport (tcp, tls, ws, grpc, quic, …)
```

A **session** is identified by a 16-byte `session_id`. Every path joins a session with its own handshake and its own keys. Exactly one path is **active** in v1; the others are **standby** (handshaken, pinged, idle).

---

## 2. Identity

- Each node holds a 32-byte Ed25519 seed (`identity.key`).
- The Noise static key is the X25519 key derived from that seed (RFC 7748 birational map, as in libsodium `crypto_sign_ed25519_sk_to_curve25519`).
- Peers are pinned by Ed25519 public key in config (`ed25519:<base64>`). The responder rejects any initiator whose static key is not a configured peer.

---

## 3. Handshake

Pattern: `Noise_IK_25519_ChaChaPoly_BLAKE2s`, prologue `"marmot/1"`.

Each handshake message is sent as: `len:u16 | noise_message`.

### 3.1 Message 1 (initiator → responder), encrypted payload `Hello`
| Field | Size | Notes |
|---|---|---|
| version | 1 | `0x01` |
| flags | 1 | bit0 `JOIN` (join existing session), bit1 `ROTATE` |
| session_id | 16 | random for a new session; existing id for `JOIN`/`ROTATE` |
| timestamp | 8 | unix ms; rejected if skew > 60 s |
| nonce | 16 | random; responder keeps a 120 s replay cache of (static key, nonce) |
| node_id_len | 1 | |
| node_id | n | UTF-8 |
| caps | 4 | capability bits (§8) |

### 3.2 Message 2 (responder → initiator), encrypted payload `Welcome`
| Field | Size | Notes |
|---|---|---|
| status | 1 | `0` OK, `1` unknown session, `2` rejected, `3` overloaded |
| caps | 4 | intersection of capabilities |
| resume_offset | 8 | for `JOIN`: last contiguous byte offset received on this session (§5) |

After message 2 both sides hold a pair of Noise `CipherState`s for this path. Handshake timeout: 10 s.

---

## 4. Record layer

### 4.1 Stream transports
```
record     = length:u16 | ciphertext[length]
plaintext  = type:u8 | pad_len:u16 | body | padding[pad_len]
```
- `ciphertext` is one Noise transport message (ChaCha20-Poly1305, implicit 64-bit nonce counter). Max plaintext 16 384.
- Padding is zero bytes, chosen by the scheduler's size policy; receivers ignore it.
- Any decryption failure closes the **path** (not the session).

### 4.2 Datagram transports
One record per datagram, without the `length` prefix. Nonce is explicit: `nonce:u64 | ciphertext`, with a 1024-entry sliding replay window. The sender counts nonces up from 0 per path and direction; the receiver drops a record whose nonce is older than the window or already seen. The plaintext is laid out as in §4.1. (Used by v2 on QUIC datagram paths, [ADR-0014](../adr/0014-quic-datagram-paths-fec.md); v1 runs on stream transports and QUIC streams only.)

### 4.3 Record types
| Type | Name | Body |
|---|---|---|
| 0x01 | DATA | `offset:u64 | bytes` — session byte stream (§5) |
| 0x02 | ACK | `offset:u64` — all bytes `< offset` received |
| 0x03 | PING | `id:u32 | sent_us:u64` |
| 0x04 | PONG | `id:u32 | sent_us:u64` (echo) |
| 0x05 | ACTIVATE | `resume_offset:u64` — "this path is now active, resend from here" |
| 0x06 | ROTATE | `new_session_epoch:u32` — make-before-break notice |
| 0x07 | CLOSE | `code:u16 | reason_len:u8 | reason` |
| 0x08–0x7F | reserved | |
| 0x80–0x82 | v2 packets | §11 |
| 0x83–0xFF | reserved | |

Unknown types in the reserved range close the path with code `PROTOCOL_ERROR`.

---

## 5. Resumable conn (v1)

Turns a sequence of paths into one reliable byte stream per session direction, so smux streams survive a path failure.

- Sender assigns every byte of the session stream an offset (starting at 0) and keeps unacknowledged bytes in a send buffer (default cap 4 MiB; writes block when full = backpressure).
- Receiver delivers bytes in order, ignores duplicates (`offset` below its cursor), and sends `ACK` every 64 KiB or 50 ms, whichever first.
- **Failover:** when the controller picks a new active path, the side that detects it sends `ACTIVATE(resume_offset)` on the new path; the peer resends from `resume_offset` and replies with its own `ACTIVATE`. No stream is reset.
- **Rotation (make-before-break):** a new path is handshaken with `ROTATE`, then activated exactly like failover; the old path is closed after its last ACK.
- If no path becomes active within `session.resume_timeout` (default 30 s), the session is closed and its streams reset.

---

## 6. Stream header

The first bytes written to every new mux stream:

| Field | Size | Notes |
|---|---|---|
| version | 1 | `0x01` (`0x02` exit stream, §6.2; `0x03` path stream, §6.3) |
| proto | 1 | `1` TCP, `2` UDP |
| class | 1 | `1` tunneled, `2` vip |
| target_port | 2 | port on the receiving node (after `port_map`) |
| client_family | 1 | `4` or `6` |
| client_ip | 4/16 | real user address, for PROXY v2 |
| client_port | 2 | |
| route_len | 1 | number of remaining relay hops (0 = deliver locally) |
| route | n×(1+len) | `len:u8 | node_id` per hop |

Receiver replies with one byte: `0` OK, `1` target refused, `2` target unreachable, `3` policy denied, then raw data follows.

### 6.1 UDP inside a stream
Each datagram is framed as `len:u16 | payload`. One stream per `(client_addr, target_port)` flow, closed after `udp_idle_timeout` (default 60 s).

### 6.2 Exit streams (version 2)
A stream opened by the exit-mode SOCKS5 inbound names its destination ([ADR-0010](../adr/0010-exit-stream-destination.md)). Its header has `version = 2` and, after the version 1 fields, adds:

| Field | Size | Notes |
|---|---|---|
| dst_type | 1 | `1` IPv4, `3` domain name, `4` IPv6 |
| dst_addr | 4 / 16 / 1+n | IPv4, IPv6, or `len:u8 | name` (1..255 bytes, no control characters) |
| dst_port | 2 | |

`target_port` repeats `dst_port`. A header without a destination is always sent as version 1. The receiving node delivers a version 2 stream only if its role is `exit` or `hybrid`, and refuses (`3` policy denied) destinations in loopback, private, link-local, CGNAT, unspecified, multicast or broadcast ranges and the node's own interface addresses, checking every resolved address of a domain name at dial time.

---

### 6.3 Path streams (version 3)
A path stream carries a session path through relay nodes ([ADR-0012](../adr/0012-relay-path-streams.md)). Its header is only:

| Field | Size | Notes |
|---|---|---|
| version | 1 | `0x03` |
| route_len | 1 | hops after the receiving node, at most 4 |
| route | n×(1+len) | `len:u8 | node_id` per hop |

The receiver answers with the reply byte of §6. With `route_len = 0` it answers `0` and treats the rest of the stream as a connection accepted by an inter-node listener: a Noise handshake (§2) follows. Otherwise see §7.

---

## 7. Relay

User streams (versions 1 and 2) always run end to end; a user stream with `route_len > 0` is answered `3` (policy denied).

A node that receives a path stream with `route_len > 0` checks its transit policy ([ADR-0012](../adr/0012-relay-path-streams.md) §3), opens a path stream to the first hop of the route over a session whose active path is direct, sending the rest of the route, waits for that hop's reply byte, answers the sender with it, and if it is `0` pipes bytes both ways until either side closes. The relay never sees user bytes: the end-to-end session's Noise handshake and records run inside the path stream.

---

## 8. Capability bits

| Bit | Meaning |
|---|---|
| 0 | UDP streams |
| 1 | relay transit allowed |
| 2 | VIP duplication |
| 3 | v2 multipath frames |
| 4–31 | reserved |

---

## 9. Close codes

`0` normal, `1` protocol error, `2` auth failed, `3` rotate complete, `4` shutdown, `5` overloaded, `6` revoked.

---

## 10. Notes

- `skip_double_encryption` cannot be applied per stream: v1 interleaves streams in one record stream and v2 packs frames of several streams in one packet. The flag is accepted and ignored with a warning (Phase 4, [ADR-0013](../adr/0013-session-v2-multipath.md)).
- All parsers in this spec must have fuzz tests (`CONTRIBUTING` §6).

---

## 11. Session v2 ([ADR-0013](../adr/0013-session-v2-multipath.md))

Used when both sides keep capability bit 3 in the handshake. smux and the resumable conn (§5) are not used; ACTIVATE, ROTATE, DATA, ACK, PING and PONG records (§4.3) are not sent and close the path if received.

### 11.1 Paths
Every path of the session is used. A path's **id** is the first 8 bytes (big-endian `u64`) of the Noise handshake hash of that path; both sides compute it. A join whose id equals that of a live path is rejected. Each path has its own packet number space starting at 0.

### 11.2 Records
| Type | Name | Body |
|---|---|---|
| 0x07 | CLOSE | as §4.3. Code `3` (rotate complete) closes only this path; any other code closes the session |
| 0x80 | PKT | `pn:u64 | frame*` |
| 0x81 | REPAIR | `pn:u64 | group:u32 | k:u8 | m:u8 | index:u8 | parity` (FEC, §11.5) |
| 0x82 | PKT_FEC | `pn:u64 | group:u32 | index:u8 | frame*` (FEC source packet, §11.5) |

A packet is **ack-eliciting** if it holds any frame but ACK. REPAIR packets are numbered and acknowledged like others but never resent.

### 11.3 Frames
`v` is an unsigned LEB128 varint (Go `binary.AppendUvarint`), at most 10 bytes.

| Type | Name | Fields |
|---|---|---|
| 0x01 | PING | — (asks for an ACK) |
| 0x02 | ACK | `largest:v | delay_us:v | count:v | first:v | (gap:v | len:v)×count` |
| 0x03 | STREAM | `sid:v | off:v | fin:u8 | len:v | data[len]` |
| 0x04 | RESET | `sid:v | code:v | final:v` — the sender abandons its direction of the stream; `final` is how many bytes it sent |
| 0x05 | STOP | `sid:v` — the sender will read no more; the peer answers with RESET unless its FIN was already acknowledged |
| 0x06 | MAX_STREAM_DATA | `sid:v | max:v` — the peer may send stream bytes below `max` |
| 0x07 | MAX_DATA | `max:v` — the same for the sum over all streams |

- **ACK** acknowledges packets of the path it arrives on. The first range is `[largest − first, largest]`; each further range ends `gap + 2` below the previous range's smallest number and spans `len + 1` numbers (as QUIC). At most 32 ranges. `delay_us` is how long the receiver held the ACK.
- **STREAM**: the initiator opens odd stream ids, the responder even ones; the first frame of an unknown id from the peer opens a stream. `fin = 1` marks `off + len` as the final size. The stream carries the header and reply byte of §6.
- A stream is gone once both directions ended: FIN acknowledged or RESET acknowledged when sending; FIN reached or RESET received when receiving. Bytes up to a direction's final size count against the session window even if they are discarded, so a closed stream never leaks window.
- `Close` sends FIN after the data already written and STOP if the peer's direction has not ended. Aborting a stream sends RESET and STOP.
- Initial windows: 2 MiB per stream, 16 MiB per session. Receiving bytes beyond a window, a stream id of the wrong parity, or a final size that changes closes the session with code `1`.

### 11.4 Loss and acknowledgement
- The receiver acknowledges every second ack-eliciting packet, any packet received out of order, and otherwise within 25 ms.
- A packet is lost when a packet at least 3 numbers higher was acknowledged, or when it was sent more than 9/8 × max(smoothed RTT, latest RTT) before an acknowledged one. Its frames are sent again, preferably on another path; STREAM data already acknowledged is not resent.
- Probe timeout = smoothed RTT + max(4 × RTT variance, 1 ms) + 25 ms, doubled on each consecutive expiry. On expiry the path sends a PING, its unacknowledged frames are queued for other paths, and it takes no new data until something is acknowledged.

### 11.5 FEC ([ADR-0014](../adr/0014-quic-datagram-paths-fec.md))
On datagram paths only. A source packet is sent as PKT_FEC; its **symbol** is `path_id:u64 | pn:u64 | len:u16 | frames[len]`, zero-padded to the longest symbol of its group. `group` counts up per session and direction; `index` is `0..k−1` for sources and `k..k+m−1` for REPAIR, whose `parity` is the Reed-Solomon parity shard (`klauspost/reedsolomon`, `k` data and `m` parity shards) over the padded symbols. A receiver holding any `k` shards of a group rebuilds the missing sources and processes each as if it had arrived on path `path_id` with number `pn`. Groups older than 1 s are dropped.
