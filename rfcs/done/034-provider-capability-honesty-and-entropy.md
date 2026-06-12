# RFC 034 — Provider Capability Honesty and Fail-Closed Entropy

**Project.** kroopt  
**Status.** Implemented (0.36.0-dev)  
**Type.** Implementation RFC  
**Target milestone.** M36-prelude (immediate; ahead of RFC 031–033 integration)  
**Depends on.** RFC 008 (crypto provider), RFC 011 (config validation)  
**Touches.** `Kroopt/Crypto/RealProvider.lean`, `Kroopt/Crypto/Provider.lean`, `Kroopt/Crypto/Random.lean`, `Kroopt/Native/kroopt_ffi.c`, `Kroopt/Config/*`, `docs/src/proof-trust-test-matrix.md`  
**Canonical source.** kroopt fixed requirements §3.3, §5.2, §12.2, §17; architect deep review (blocks 4/6) + RFC review (RFC 034 split: the 034A immediate half).  

---

## 1. Summary

Two safety defects in `0.35.0-dev` are **independent of the correspondence work** and
leave the tree in a known-misleading state. The architect review requires they be fixed
immediately rather than waiting behind M37:

1. **The real provider advertises capabilities it cannot perform.** `mkRealProvider` sets
   `capabilities := fakeCapabilities` (`RealProvider.lean:144`), advertising AES-GCM,
   SHA-384, P-256, ECDSA-P256, RSA-PSS — none implemented. Config validation could accept
   a suite/scheme the provider then cannot execute.
2. **Entropy fails open.** `kroopt_ffi_random` zero-fills the remainder and returns
   success when `getrandom` fails (`kroopt_ffi.c:148`).

This RFC is the **M36-prelude**: it corrects capability honesty, makes entropy
fail-closed, and separates the deterministic test/fake randomness from the real source.
The broader native/secret/budget hardening is RFC 037 (M37).

## 2. Provider capability honesty

Define a precise constrained profile and use it:

```lean
def realCapabilities : ProviderCapabilities :=
  { aeadSuites       := [.chacha20Poly1305Sha256]
    hashAlgorithms   := [.sha256]
    kexGroups        := [.x25519]
    signatureSchemes := [.ed25519]
    randomAvailable  := true }
```

- `mkRealProvider.capabilities := realCapabilities`.
- Config validation (RFC 011) **fails closed** at listener startup if any configured
  cipher suite, group, or signature scheme is outside `realCapabilities`, and if no
  certificate/key entry has a supported compatible scheme.
- This is consistent with the constrained profile of RFC 035; the provider may not claim
  what the vendored HACL\* subset cannot do.

## 3. Fail-closed entropy with a typed result

Randomness must never synthesize fallback bytes. Define an explicit Lean-side result and
thread it:

```lean
inductive RandomResult where
  | bytes (b : ByteArray)
  | error (e : EntropyError)
```

- `kroopt_ffi_random` returns a status-tagged result; on `getrandom` failure it reports
  the error rather than zero-filling and returning success.
- No caller may fabricate entropy on `error`; an entropy error aborts connection/listener
  setup (a server cannot start, a handshake cannot proceed, with degraded entropy).
- The OS CSPRNG remains the only source (requirements §3.3); kroopt implements no PRNG.

## 4. Deterministic-random / test-provider separation

The current real provider's `randomBytes` returns deterministic zeros — useful for tests,
dangerous if it can be mistaken for production randomness. Separate the two explicitly:

- a **deterministic test provider** (or a clearly named deterministic random source) used
  by model/fake tests and vectors;
- the **real provider** uses the §3 fail-closed OS CSPRNG only.

The selection is explicit at construction; no build path silently substitutes
deterministic randomness into the real provider.

## 5. Acceptance criteria

1. `mkRealProvider.capabilities = realCapabilities`; config validation rejects
   out-of-profile suites/groups/signature schemes (and certs with no supported scheme) at
   startup, with a typed `ConfigError`.
2. `kroopt_ffi_random` returns a typed result; entropy failure aborts setup; no
   zero-filled success path remains; the real provider draws only from the OS CSPRNG.
3. Deterministic randomness is confined to an explicitly named test/fake provider and
   cannot enter the real provider.
4. The proof/trust/test matrix is updated to state the real capability profile and the
   fail-closed entropy guarantee.

## 7. Status — Implemented (0.36.0-dev)

Shipped: `realCapabilities` (the constrained profile) used by `mkRealProvider`;
`validateServerConfigCapabilities` rejecting out-of-profile suites/signature schemes
with a typed `CapabilityError`; `Hacl.randomBytes` returns a typed `RandomResult` with
the native side failing closed (no zero-fill success); `provisionRealConfig` fails closed
with `entropyFailure`; deterministic randomness confined to the fake provider (a real
`randomBytes` op is a typed error). Evidence: `kroopt-capabilities-test` (8 checks),
updated `kroopt-provision-test` / `kroopt-hacl-test`; docs in `crypto-ffi-contract.md`
and `proof-assumptions.md`.

**Deferred (mechanical, tracked):** the *call-site* that runs
`validateServerConfigCapabilities` at live listener startup lands with the production
interpreter / iotakt listener (RFC 010 / RFC 031); the check itself is complete and
tested. No other RFC 034 work remains.

## 6. Notes

- This RFC is intentionally small and low-risk (no core/proof changes) so it can land as
  a prelude before the RFC 031–033 integration. It removes the "real provider lies about
  what it can do" and "entropy fails open" escape hatches the architect flagged.
- The remaining native hardening (FFI length contracts for all `uint32_t` params, native
  secret arena, budget plumbing, sanitizers, `close_notify` polish, record-size guards)
  is RFC 037, scheduled for M37.
