# ADR-0002: Web panel is React + TypeScript + Vite + Tailwind

Status: Accepted

## Context
Operators need a web panel, not only a terminal. It must be RTL/Persian first, with English available, and show live status.

## Decision
React 18 + TypeScript (strict) + Vite + Tailwind CSS. TanStack Query for server state, a generated API client from `backend/api/openapi.yaml`, WebSocket for live events.

## Consequences
- The OpenAPI spec is the single contract between frontend and backend; neither side hand-writes the other's types.
- Production build is static files embedded into/served by the backend container.
