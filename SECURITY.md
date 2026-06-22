# Security Policy

kroopt is a verification-first TLS 1.3 secure-channel library intended to terminate HTTPS at
the network edge. Security process is part of its design, not an afterthought. This document
states what kroopt does and does not claim, how to report a vulnerability, and how reports are
handled. The operational detail — review checkpoints, release blockers, and the triage
workflow — lives in [`docs/src/security-review-checklist.md`](docs/src/security-review-checklist.md)
(RFC 028).

## What kroopt proves, assumes, and excludes

kroopt never markets an assumed or out-of-scope property as proven. Reports are evaluated
against the honest trust boundary:

- **PROVEN** (machine-checked over the pure core `Kroopt.Core.step`): protocol-*structural*
  safety — no application plaintext before `connected`; no unauthenticated plaintext; per-key
  nonce uniqueness and sequence monotonicity with fatal overflow; directional/epoch key
  separation; transcript consistency over exact wire bytes; bounded parsing; action
  discipline; terminal-after-close. See
  [`docs/src/verification/theorem-inventory.md`](docs/src/verification/theorem-inventory.md).
- **ASSUMED** (inherited, not re-proved here): correctness and constant-time behavior of the
  borrowed HACL\*/EverCrypt primitives, and the quality of the OS CSPRNG. kroopt does **not**
  prove cryptographic secrecy. See
  [`docs/src/verification/proof-assumptions.md`](docs/src/verification/proof-assumptions.md).
- **TESTED** (not proved): FFI ownership, known-answer vectors, sanitizer builds, malformed-input
  behavior, and live interop.
- **OUTSCOPE** (not implemented in the supported server profile): peer certificate-chain / X.509
  path validation, client/mTLS roles, TLS 1.2, DTLS/QUIC, 0-RTT, session tickets,
  HelloRetryRequest, and KeyUpdate. A report that a server profile does not validate a peer
  chain is working as designed, not a vulnerability. See
  [`docs/src/verification/deferred-scope.md`](docs/src/verification/deferred-scope.md).

## Supported versions

kroopt is pre-1.0 and has not yet cut a stable release; the public API is explicitly not frozen
(RFC 027). Security fixes land on `main` and in the **latest `0.x` development release**, which
is the only supported line. A supported-version table will be published when a `1.0` stable line
exists. Older `0.x` snapshots are not maintained — update to the latest release.

| Version | Supported |
|---------|-----------|
| latest `0.x`-dev / `main` | ✅ |
| older `0.x` snapshots | ❌ |

## Reporting a vulnerability

**Do not open a public issue for a security report.** Use GitHub's private vulnerability
reporting for this repository:

- <https://github.com/nabbisen/kroopt/security/advisories/new>

Please include, where possible: affected version/commit, a minimal reproducer (a malformed
ClientHello, record, or event sequence is ideal), the observed vs. expected behavior, and which
trust-boundary claim above you believe is violated. Reports that include a failing test case or
a candidate theorem gap are triaged fastest.

There is no bug-bounty program. Coordinated disclosure is appreciated; please give the maintainer
a reasonable window to ship a fix before public disclosure.

## Severity and handling

Reports are classified Critical / High / Medium / Low and triaged per the workflow in the
review checklist. Because kroopt is verification-first, a fix is not considered complete until it
adds a **regression test or a theorem** (and updates the trust/proof artifacts) — a patch alone
is insufficient. Release blockers (early/unauthenticated plaintext, nonce reuse, non-fatal
sequence overflow, transcript mismatch, parser panic/unbounded allocation, printable/loggable
secrets, FFI memory unsafety, deterministic crashes from hostile input, and a stale
proof/trust/test matrix) hold a release until resolved.

Maintainer: **nabbisen**. License: Apache-2.0.
