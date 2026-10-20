# ADR-0005: No spoofing of third-party source addresses

Status: Accepted

## Context
The original design proposed forging the source IP of packets using addresses owned by third parties.

## Decision
Marmot will not implement this. Every packet it sends carries a source address that the node legitimately owns (its IPv4 pool or its routed IPv6 subnet).

## Rationale
- It abuses networks and services that are not part of the system.
- Most hosting providers drop such packets (BCP 38) and suspend servers that emit them, which would take Marmot nodes offline.
- The same resilience goals are met by multi-IP, dual-stack, IPv6 rotation, reverse connections and relay routing.
