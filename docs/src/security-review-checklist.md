# Security review checklist

This is the operational companion to [`SECURITY.md`](../../SECURITY.md), implementing RFC 028.
It defines the per-milestone review checkpoints, the release blockers and how each is enforced,
the vulnerability classification, and the triage workflow. The reporting channel and the
honest PROVEN / ASSUMED / TESTED / OUTSCOPE scope statement live in `SECURITY.md`.

## Review checkpoints

A security review is mandatory at each of these milestones before it is treated as accepted:

| Milestone | Review focus |
|-----------|--------------|
| M0 | verified-core architecture (pure core / thin interpreter separation) |
| v0.1 | parser, record, and handshake proof review |
| v0.2 | FFI and secret-handle review |
| v0.3 | network-exposure review **before** OpenSSL/curl interop counts as acceptance |
| v0.4 | browser-facing operational review |

## Release blockers

A release is **blocked** while any of the following is possible. Most are enforced
mechanically by the standard gate set (`lake build`, the test suites, and the `scripts/*.sh`
gates); the rest are enforced by manual review against this list. "Enforced manually at
minimum, preferably by CI" (RFC 028 §7.2) is satisfied as below.

| # | Blocker | Primary enforcement |
|---|---------|---------------------|
| 1 | Application plaintext before `connected` | PROVEN over `step` (no-early-plaintext family); `lake build` + `check-axioms.sh` |
| 2 | Unauthenticated plaintext emission | PROVEN (no-unauthenticated-plaintext family); `lake build` + `check-axioms.sh` |
| 3 | Nonce reuse under one key | PROVEN (`nonce_unique_within_epoch`; registered-seal/open sequence theorems); `lake build` |
| 4 | Sequence overflow not fatal | PROVEN (`no_crypto_on_write_seq_overflow`, overflow-fatal record model); `lake build` |
| 5 | Transcript mismatch in CertificateVerify / Finished | PROVEN (transcript-consistency family over exact wire bytes); `lake build` |
| 6 | Parser panic or unbounded allocation from hostile bytes | PROVEN (`parser_bounds_safe`, `reader_in_bounds`) + `kroopt-parse-fuzz` |
| 7 | Printable / loggable secret type | secret types are non-`Repr`/non-serializable by construction; `check-hygiene.sh` + review |
| 8 | FFI memory-unsafety finding | `sanitizer-check.sh` (ASan/UBSan over the shim) + known-answer tests |
| 9 | Deterministic crash from malformed network input | negative test suites + `kroopt-parse-fuzz` + `tls-interop.sh` |
| 10 | Stale proof/trust/test matrix for changed security behavior | manual review: `theorem-inventory.md` + `proof-assumptions.md` must be updated in the same change |

The axiom gate (`check-axioms.sh`) additionally fails the build if any public theorem depends
on `sorryAx` or an axiom outside `{propext, Quot.sound, Classical.choice}`, and `check-hygiene.sh`
rejects `sorry`/`axiom`/`unsafe`/`native_decide`/`admit` in the strict (pure/proof) zones — so a
security property cannot be silently weakened to "prove" a change.

## Vulnerability classification

- **Critical** — application-plaintext leakage, private-key leakage, nonce reuse,
  authentication bypass, remote code execution.
- **High** — remote crash, unbounded memory/CPU DoS, transcript-verification flaw, major FFI
  safety bug.
- **Medium** — deterministic connection failure from common valid clients, log injection with
  operational impact, resource-budget bypass.
- **Low** — diagnostic inconsistency, non-sensitive metadata leakage, documentation mismatch.

A report that targets an OUTSCOPE property (e.g. "the server does not validate the peer's
certificate chain") is not a vulnerability — it is the documented server-profile scope. Such
reports are closed with a pointer to `deferred-scope.md`.

## Triage workflow

```text
report received (private advisory)
  → assign category and affected versions
  → reproduce with a minimal test if possible
  → identify the proof / test / matrix gap that allowed it
  → patch core / interpreter / FFI / config as needed
  → add a regression test OR a theorem (a patch alone is not a complete fix)
  → update docs, the trust/proof matrix, and release notes
  → release according to severity
```

The "add a regression test or a theorem" step is mandatory: a fix that changes security
behavior without a corresponding test or proof update is itself a release blocker (#10).
