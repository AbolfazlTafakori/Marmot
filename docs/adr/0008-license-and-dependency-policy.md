# ADR-0008: Proprietary licence and dependency licence policy

Status: Accepted

## Context
Marmot is closed-source under its own licence (`LICENSE`). Some popular Go projects in this space use copyleft licences; importing them would force their licence onto Marmot.

## Decision
Allowed dependency licences:

| Licence | Status |
|---|---|
| MIT, BSD-2/3, ISC, Apache-2.0, Zlib, Unlicense, CC0 | Allowed |
| MPL-2.0 | Allowed only as an unmodified dependency (file-level copyleft); modifications to those files must be published. Needs review. |
| LGPL | Avoid (static linking in Go makes compliance awkward) |
| GPL, AGPL, SSPL, any "non-commercial" licence | **Forbidden** |

Notable examples: `sing-box` (GPL-3.0) must not be imported or copied. `Xray-core` (MPL-2.0) needs review before use. `quic-go`, `smux`, `klauspost/reedsolomon`, `flynn/noise`, `utls` are permissively licensed.

## Consequences
- CI runs a licence check (`go-licenses`, and `license-checker` for the frontend) and fails on forbidden licences.
- `THIRD_PARTY_NOTICES` is generated at release time.
- Protocols from copyleft projects may be **re-implemented from their specification**, never by copying code.
