# ADR-0010: Exit-mode streams carry their destination

Status: Accepted

## Context
In relay mode a stream names only a target port; the receiving node
delivers it to `panel_integration.target_host`. Exit mode (ARCHITECTURE
§3.2) is different: the local SOCKS5 inbound learns a destination (an IP
or a domain name, and a port) from the client, and the peer must connect
to exactly that. The v1 stream header has no field for it.

## Decision
1. **Stream header version 2** (spec §6.2) is the v1 header followed by a
   destination: `dst_type:u8` (`1` IPv4, `3` domain, `4` IPv6), the
   address (4 or 16 bytes, or `len:u8 | name`), and `dst_port:u16`. A
   header without a destination is always encoded as version 1, so relay
   mode is byte-for-byte unchanged. Receivers accept versions 1 and 2.
2. **Who may exit.** A node delivers a version 2 stream only when its
   `node.role` is `exit` or `hybrid`; otherwise it replies `policy denied`.
3. **Where an exit may go.** The exit node refuses destinations that are
   loopback, private (RFC 1918, RFC 4193), link-local, CGNAT
   (100.64.0.0/10), unspecified, multicast or broadcast, and every address
   of the exit server's own interfaces (such as its public IP), on any
   port. For a domain name the check runs on
   every address the name resolves to, at the moment of dialing, so DNS
   cannot be used to reach those ranges. This keeps a peer from using the
   exit to reach the exit server's own services or internal network.
4. **Name resolution** happens on the exit node, so the client's names are
   resolved where the traffic leaves.
5. **UDP** destinations use the same header with `proto = UDP`; the stream
   then carries framed datagrams (spec §6.1) for that one destination.

## Consequences
- Older nodes that know only version 1 reject version 2 headers as
  malformed, so exit mode needs both ends upgraded; relay mode does not.
- The private-range rule cannot be turned off in Phase 2. If an operator
  needs an exit into a private network, that becomes a configuration
  option with its own ADR.
