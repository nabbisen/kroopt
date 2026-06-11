# RFC 009 — HACL*/EverCrypt Shim, Known-Answer Tests, and Sanitizer Strategy

**Project.** kroopt  
**Status.** Proposed  
**Type.** Implementation RFC  
**Target milestone.** M6  
**Depends on.** RFC 008  
**Touches.** `native/kroopt_hacl_shim.c`, `kroopt.h`; `Kroopt/Crypto/Ffi.lean`; `lakefile.lean`  
**Canonical source.** kroopt fixed requirements and external design.  

---

## 1. Summary

This RFC defines the native C shim that binds kroopt to HACL\*/EverCrypt. HACL\*/EverCrypt supplies verified primitive implementations, but kroopt's shim remains a trusted/tested boundary. The shim must be small, boring, warning-clean, sanitizer-clean, and covered by known-answer tests.

## 2. Goals

- Define the C shim responsibilities and limits.
- Define build integration with Lake.
- Define memory ownership rules between Lean and C.
- Define known-answer test coverage.
- Define sanitizer CI requirements.

## 3. Shim principles

1. One C function per narrow primitive operation or secret-handle operation.
2. No retained Lean pointers.
3. All lengths are passed explicitly and checked before use.
4. Output buffers are either caller-provided with checked length or allocated by the shim with explicit ownership transfer.
5. Every function returns a small status code and writes detailed error state only through bounded output parameters.
6. No logging from C shim.
7. No protocol decisions in C.

## 4. Native API sketch

```c
typedef uint64_t kroopt_secret_handle;

typedef enum {
  KROOPT_OK = 0,
  KROOPT_ERR_INVALID_ARG,
  KROOPT_ERR_UNSUPPORTED,
  KROOPT_ERR_AUTH_FAILED,
  KROOPT_ERR_RANDOM_FAILED,
  KROOPT_ERR_INTERNAL
} kroopt_status;

kroopt_status kroopt_random(uint8_t *out, size_t out_len);
kroopt_status kroopt_x25519(uint8_t const *peer, size_t peer_len,
                            kroopt_secret_handle *out_shared);
kroopt_status kroopt_hkdf_extract(..., kroopt_secret_handle *out_secret);
kroopt_status kroopt_hkdf_expand_label(..., kroopt_secret_handle *out_secret_or_bytes);
kroopt_status kroopt_aead_seal(...);
kroopt_status kroopt_aead_open(...);
kroopt_status kroopt_sign_cert_verify(...);
kroopt_status kroopt_secret_release(kroopt_secret_handle h);
```

Exact signatures are implementation-defined, but every function must state ownership, input length bounds, output length requirements, and failure behavior.

## 5. Lake/build integration

The build must support:

- vendored HACL\*/EverCrypt source or pinned system dependency, selected by build option;
- reproducible CI configuration;
- strict compiler warnings for the shim;
- ASan/UBSan sanitizer builds;
- non-sanitized release builds;
- clear feature flags for optional algorithms.

The chosen distribution method must be documented in `docs/src/crypto-ffi-contract.md`.

## 6. Known-answer tests

KATs are required for:

- AES-128-GCM seal/open;
- ChaCha20-Poly1305 seal/open;
- SHA-256;
- SHA-384 if enabled;
- HKDF extract/expand with TLS 1.3 labels;
- X25519;
- P-256 if enabled;
- Ed25519 signing/verification if used;
- ECDSA P-256 if used;
- RSA-PSS if enabled.

KAT failures are release blockers.

## 7. Secret memory

The shim owns durable secret memory. It must:

- allocate from a secret arena or equivalent zeroizable allocation discipline;
- zeroize before free;
- track handle generation to reject stale handles;
- never expose secret bytes to Lean unless the operation explicitly returns public bytes;
- treat IV bases and traffic secrets conservatively as secret handles unless a specific proof/review classifies them otherwise.

## 8. Error handling

C status codes map to `CryptoError`. AEAD authentication failure must be distinguishable from internal failure so the TLS alert behavior can be deterministic. Internal errors must not include raw sensitive data.

## 9. Sanitizer strategy

CI should include:

- ASan build and test run for shim tests;
- UBSan build and test run;
- optional valgrind or leak sanitizer job if practical;
- compiler warnings as errors for shim code;
- test mode that exercises invalid lengths and null pointers where safe.

## 10. Security considerations

- C code is trusted/tested, not proven by Lean.
- Avoid complex allocation and parsing in C.
- Avoid algorithm negotiation in C.
- Avoid implicit global mutable provider state except secret arena internals.
- FFI must not call back into Lean while holding secret pointers.

## 11. Tests

- KATs for every primitive.
- Boundary tests for invalid lengths.
- Secret release and use-after-release tests.
- AEAD auth failure test.
- Random failure simulation where possible.
- Sanitizer runs over all native tests.

## 12. Acceptance criteria

- The shim compiles warning-clean.
- KATs pass.
- Sanitizer jobs pass.
- Secret handles are zeroized/released by explicit lifecycle tests.
- Lean core remains independent of native imports.
