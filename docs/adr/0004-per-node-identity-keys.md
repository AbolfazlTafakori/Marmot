# ADR-0004: Per-node identity keys instead of a shared mesh secret

Status: Accepted

## Context
The original design used one `secret_key` for the whole mesh. If any single server is seized or compromised, every node is exposed and nothing can be revoked.

## Decision
Each node generates an Ed25519 identity key (`marmot keygen`). Peers are pinned by public key. Sessions use the Noise IK handshake with forward secrecy; keys rotate on every make-before-break.

## Consequences
- Compromising one node does not expose sessions between other nodes, nor past traffic.
- Removing a peer's key and reloading revokes it immediately.
- Adding a node requires exchanging public keys (the panel will provide a copy/paste "join" flow).
