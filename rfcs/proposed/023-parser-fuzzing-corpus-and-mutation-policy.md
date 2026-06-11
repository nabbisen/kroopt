# RFC 023 — Parser Fuzzing, Corpus, and Mutation Policy

**Project.** kroopt  
**Status.** Proposed  
**Type.** Implementation RFC  
**Target milestone.** v0.1; mandatory before v0.4  
**Depends on.** RFC 003, RFC 004, RFC 006, RFC 014, RFC 017, RFC 019  
**Touches.** `fuzz/`, `testdata/fuzz/`; `docs/src/fuzzing.md`  
**Canonical source.** kroopt fixed requirements and external design.  

---

## 1. Summary

This RFC defines fuzzing targets, seed corpus management, mutation strategy, and
regression handling for kroopt's hostile-input surfaces. Fuzzing complements
proofs: proofs cover the intended parser and state invariants, while fuzzing
pressures byte-level implementation, native conversions, and unexpected
combinations.

---

## 2. Targets

Mandatory targets:

1. TLS record header and fragment parser;
2. TLSInnerPlaintext parser;
3. ClientHello parser;
4. extension parser;
5. supported_versions parser;
6. key_share parser;
7. signature_algorithms parser;
8. ALPN parser;
9. SNI parser;
10. minimal DER metadata reader;
11. full `step` input script fuzzer using fake transport/fake crypto.

---

## 3. Properties under fuzz

Fuzz targets assert:

1. no panic;
2. no unbounded allocation;
3. deterministic error classification;
4. parsed values satisfy bounds and policy invariants;
5. rejected inputs do not advance state incorrectly;
6. no `emitPlaintext` occurs from unauthenticated bytes;
7. terminal failure remains terminal;
8. parser does not call real crypto or I/O.

---

## 4. Corpus structure

```text
testdata/fuzz/
  record/
    valid-minimal.bin
    oversize-fragment.bin
    truncated-header.bin
  clienthello/
    valid-x25519-alpn-sni.bin
    missing-keyshare.bin
    duplicate-supported-versions.bin
  extensions/
    malformed-vector-length.bin
    unknown-extension.bin
  der/
    minimal-leaf-ed25519.der
    truncated-sequence.der
```

Seed files must be small, named by behavior, and never contain private keys or
real production certificates unless intentionally public test fixtures.

---

## 5. Mutation themes

1. length prefix off-by-one;
2. nested vector overrun;
3. duplicate extensions;
4. unknown extension ids;
5. random extension order;
6. valid record header with truncated body;
7. valid ciphertext length with bad tag;
8. inner plaintext missing content type;
9. excessive zero padding;
10. Unicode/control characters in SNI;
11. empty and duplicate ALPN strings;
12. DER indefinite length or unsupported forms.

---

## 6. Regression policy

When fuzzing finds a crash, panic, excessive allocation, or invalid state:

1. minimize input;
2. add it to corpus with a behavior name;
3. add a deterministic unit test if the issue is semantically meaningful;
4. link the regression to the relevant RFC;
5. update parser or budget proof notes if the issue indicates invariant drift.

---

## 7. CI policy

Early milestones:

- deterministic corpus tests run on every PR;
- fuzz smoke tests run with short time budget.

Later milestones:

- longer fuzz runs in scheduled CI;
- native shim fuzzing only after sanitizer builds are stable;
- coverage reports used as guidance, not as a release claim.

---

## 8. Acceptance criteria

1. Each mandatory parser has a fuzz target or documented reason for delay.
2. Corpus tests run in normal CI.
3. Fuzz-discovered bugs become regression fixtures.
4. Fuzz targets enforce resource budgets.
5. The fuzz policy is documented in `docs/src/fuzzing.md`.
