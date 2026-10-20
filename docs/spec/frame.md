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
One record per datagram, without the `length` prefix. Nonce is explicit: `nonce:u64 | ciphertext`, with a 1024-entry sliding replay window. (Used by v2; v1 runs on stream transports and QUIC streams only.)

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
| 0x80–0xFF | v2 multipath frames | defined in a later revision |

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
| version | 1 | `0x01` |
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

---

## 7. Relay

A relay node that receives a stream header with `route_len > 0` pops the first hop, opens a stream to that node with the rest of the route, writes the shortened header, and pipes bytes. The end-to-end user payload stays inside the two endpoint sessions' encryption; the relay only sees the header.

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

- `skip_double_encryption` cannot be applied per stream in v1 (smux interleaves streams inside one record stream). It becomes effective in v2, where records are per stream. In v1 the flag is accepted and ignored with a warning.
- All parsers in this spec must have fuzz tests (`CONTRIBUTING` §6).
