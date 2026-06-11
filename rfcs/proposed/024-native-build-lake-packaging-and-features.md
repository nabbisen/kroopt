# RFC 024 — Native Build, Lake Packaging, and Feature Gates

**Project.** kroopt  
**Status.** Proposed  
**Type.** Implementation RFC  
**Target milestone.** M0 (skeleton); v0.2 (native)  
**Depends on.** RFC 008, RFC 009, RFC 022  
**Touches.** `lakefile.lean`; build profiles; `native/`  
**Canonical source.** kroopt fixed requirements and external design.  

---

## 1. Summary

This RFC defines kroopt's package layout, Lake build strategy, native shim build,
feature gates, and developer profiles. The build must preserve the separation
between pure verified core, FFI crypto provider, tests, and integration layers.

---

## 2. Goals

1. Let developers build the pure verified core without native crypto installed.
2. Enable HACL*/EverCrypt-backed builds behind an explicit feature/profile.
3. Keep test/fake providers available for proof and model testing.
4. Make sanitizer and KAT builds reproducible.
5. Avoid accidental dependency from core/proofs to native FFI.

---

## 3. Package layers

```text
lakefile.lean
Kroopt/Core/*       -- pure
Kroopt/Parse/*      -- pure
Kroopt/Proofs/*     -- pure proofs
Kroopt/Crypto/*     -- provider interface + FFI wrappers
Kroopt/Conn/*       -- interpreter and iotakt integration
native/*            -- C shim
Tests/*             -- deterministic, KAT, interop
docs/src/*          -- public docs and matrices (mdbook-compatible)
```

---

## 4. Build profiles

| Profile | Purpose | Native crypto | iotakt | Interop |
|---|---|---:|---:|---:|
| `core` | proof/model development | no | no | no |
| `fake` | synthetic handshake tests | no | no | no |
| `crypto` | HACL* provider tests | yes | no | no |
| `iotakt` | real transport integration | optional | yes | no |
| `interop` | OpenSSL/curl tests | yes | yes | yes |
| `dev-sanitize` | C shim sanitizer | yes | optional | optional |

The exact Lake feature mechanism may vary, but equivalent separation is
required.

---

## 5. Native shim build

Requirements:

1. compile with strict warnings;
2. support ASan/UBSan profile;
3. avoid retained Lean pointers;
4. bounds-check all lengths before C calls;
5. expose stable C ABI only to Lean wrapper, not to external consumers;
6. provide deterministic KAT binary/test target.

---

## 6. Vendored vs system HACL*/EverCrypt

The implementation RFC must choose one primary path and one developer fallback.

Criteria:

- reproducibility;
- ease of CI;
- security update workflow;
- supported algorithms;
- supported platforms;
- build complexity;
- license compatibility.

Until the choice is settled, the provider interface must not expose distribution
assumptions to the verified core.

---

## 7. Feature-gate rules

1. Pure core must compile without native dependencies.
2. Tests using fake crypto must not accidentally link real crypto.
3. Real crypto provider must not be selectable without KATs in CI.
4. Interop tests may be optional locally but required in release CI.
5. Unsafe/native code must be isolated and grep-checkable.

---

## 8. Acceptance criteria

1. `lake build` for pure core works on a clean Lean environment.
2. Native profile builds the shim and runs KATs.
3. Sanitizer profile runs in CI.
4. Module dependency scans prove core/proofs do not import native modules.
5. Packaging docs explain how jemmet depends on kroopt without pulling test-only
   providers into production.
