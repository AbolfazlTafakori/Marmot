# ADR-0006: `marmot.toml` is the source of truth for node configuration

Status: Accepted

## Context
Configuration can be changed both by hand (terminal) and from the web panel. Two sources of truth would drift.

## Decision
The TOML file is authoritative. The panel edits it through the API: validate → atomic write (temp file + rename) → `Node.Reload`. Only panel users, sessions and the audit log are stored in SQLite.

## Consequences
- A node can always be recovered by editing one file over SSH.
- Invalid configs are rejected before being written; the running config is never replaced by a broken one.
- Hand edits are picked up on `SIGHUP` or via the panel's "reload" button.
