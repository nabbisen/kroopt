# RFC handoffs

Companion execution documents for RFCs and cross-project integration records. Per
[RFC 000](../done/000-rfc-lifecycle-policy.md), handoffs are not a separate lifecycle: an RFC implementation
handoff inherits its status from the related RFC; review/correspondence records carry their own
resolved/open marker in their header.

Every new implementation or release handoff must use [`TEMPLATE.md`](TEMPLATE.md). In particular, each
acceptance item is `Done`, `Pending`, or `N/A` with candidate-specific evidence; a gate pass must identify
the exact revision and retained ledger. Handoff prose cannot promote project readiness by itself.

Organized by **owner**:

- **[`self/`](self/)** — kroopt-internal handoffs: RFC implementation companions and kroopt's own review
  documents.
- **[`iotakt/`](iotakt/)** — cross-project records with the iotakt sibling project (kroopt consumes iotakt
  for transport).
- **[`jemmet/`](jemmet/)** — cross-project API and release correspondence with kroopt's TLS consumer.

## Contents

- [`TEMPLATE.md`](TEMPLATE.md) — required evidence/status structure for new handoffs.

### `self/`
| Item | For | Status |
|------|-----|--------|
| [`040-native-traffic-secret-arena/`](self/040-native-traffic-secret-arena/README.md) | RFC 040 (native traffic-secret arena) | inherits RFC 040 (Proposed — design in progress) |
| [`REVIEW-secp256r1-capability-gap.md`](self/REVIEW-secp256r1-capability-gap.md) | secp256r1/P-256 group capability honesty | Resolved — superseded by RFC 039 |

### `iotakt/`
| Item | For | Status |
|------|-----|--------|
| [`HANDOFF-iotakt-consumer-review.md`](iotakt/HANDOFF-iotakt-consumer-review.md) | kroopt's use of iotakt as a non-blocking I/O consumer | accepted (see §O11); reconciled 2026-06-30 (adapter is jemmet's) |
| [`iotakt-review-orders.md`](iotakt/iotakt-review-orders.md) | order statements / acceptance criteria for the consumer-contract review | companion to the above |

### `jemmet/`
| Item | For | Status |
|------|-----|--------|
| [`kroopt-to-jemmet-m3-tls-accounting-response.md`](jemmet/kroopt-to-jemmet-m3-tls-accounting-response.md) | RFC 055 / jemmet M3 accounting and sizing request | Complete; released `0.126.0` with published provenance |
