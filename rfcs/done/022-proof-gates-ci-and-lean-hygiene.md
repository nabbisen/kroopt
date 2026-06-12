# RFC 022 — Proof Gates, CI, and Lean Hygiene

**Project.** kroopt  
**Status.** Implemented (0.24.0-dev)  
**Type.** Implementation RFC  
**Target milestone.** M0 onward  
**Depends on.** RFC 002, RFC 005, RFC 006, RFC 007, RFC 014  
**Touches.** CI scripts (`scripts/`); `docs/src/{proof-assumptions,theorem-inventory}.md`  
**Canonical source.** kroopt fixed requirements and external design.  

---

## 1. Summary

This RFC defines kroopt's Lean proof hygiene policy and CI gates. The value of
kroopt depends on formal verification, but that value can silently erode if
`sorry`, local axioms, unsafe escapes, proof/model drift, or untracked assumptions
enter the core. This RFC makes proof cleanliness a release gate.

---

## 2. Goals

1. Prevent project-local `sorry`, `axiom`, and `unsafe` in verified core/proofs.
2. Track all accepted assumptions explicitly.
3. Separate pure verified modules from impure interpreter and native FFI.
4. Make CI fail on proof hygiene regressions.
5. Preserve proof/runtime correspondence as code evolves.

---

## 3. Module zones

| Zone | Modules | Allowed effects | Gate |
|---|---|---|---|
| Verified core | `Kroopt.Core.*`, `Kroopt.Parse.*` where pure | none | strict proof hygiene |
| Proofs | `Kroopt.Proofs.*` | none | strict proof hygiene |
| Crypto boundary | `Kroopt.Crypto.*` | FFI declarations/wrappers | tested + reviewed |
| Interpreter | `Kroopt.Conn.*` | iotakt and provider effects | no protocol branching rule |
| Native shim | `native/*` | C/HACL* calls | compiler warnings + sanitizers |
| Tests | `Kroopt.Tests.*` | test effects | relaxed, no production leakage |

---

## 4. Forbidden constructs

In verified core and proofs:

1. project-local `sorry`;
2. project-local `axiom`;
3. `unsafe` definitions;
4. opaque constants used to skip protocol logic;
5. FFI imports;
6. direct iotakt imports;
7. direct HACL*/EverCrypt imports;
8. unreviewed partial functions.

Any exception must appear in `docs/src/proof-assumptions.md` with owner, reason,
impact, and removal plan.

---

## 5. CI gates

Required jobs:

1. `lake build` for all Lean modules;
2. proof hygiene scan for forbidden constructs in strict zones;
3. module dependency scan ensuring `Core` and `Parse` do not import `Conn` or
   native FFI modules;
4. deterministic model tests;
5. property/model tests for parser boundaries and state transitions;
6. theorem inventory generation;
7. proof/trust/test matrix freshness check.

Later jobs:

1. HACL*/EverCrypt KATs;
2. ASan/UBSan native shim tests;
3. fuzz smoke tests;
4. OpenSSL/curl interop tests;
5. jemmet+iotakt E2E tests.

---

## 6. Theorem inventory

Maintain `docs/src/theorem-inventory.md` with:

- theorem name;
- module;
- informal claim;
- corresponding requirement/RFC;
- proof status;
- assumptions used;
- runtime code path protected.

This prevents orphan proofs that do not correspond to production behavior.

---

## 7. Proof/runtime correspondence gate

For every public runtime operation, identify the core function/theorem it relies
on.

Example:

| Runtime path | Core path | Theorem |
|---|---|---|
| `TlsConn.recv` emits bytes | `step` with authenticated record result | no unauthenticated plaintext |
| `TlsConn.send` before connected | `step` with `appSend` in non-connected state | no early plaintext |
| record seal | `callCrypto(AeadSeal epoch write seq)` | key separation + nonce uniqueness |

A runtime operation without a mapped core path is not accepted for v0.3.

---

## 8. Review policy

Changes to strict modules require review by someone acting in the verification
role. Changes to interpreter/native modules that affect protocol sequencing must
include a proof/runtime mapping update.

---

## 9. Acceptance criteria

1. CI blocks forbidden constructs in strict zones.
2. Module dependency checks enforce pure-core isolation.
3. The theorem inventory exists and is current.
4. Proof assumptions are explicit and reviewed.
5. Every v0.3 public runtime path has a mapped core theorem or tested assumption.
