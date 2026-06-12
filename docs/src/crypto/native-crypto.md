# Native crypto binding (v0.3): HACL\* through Lean FFI

This page documents the **v0.3 native crypto binding**: the real, reproducible,
offline path that calls verified [HACL\*](https://github.com/hacl-star/hacl-star)
primitives from Lean, and the *honest boundary* between what this milestone
delivers and what full TLS key-schedule integration still requires.

## What is delivered

A vendored, portable-C subset of HACL\* (`Kroopt/Native/hacl/`) compiled into a
static library by Lake (`extern_lib krooptCrypto`), with a thin Lean-facing C
glue (`Kroopt/Native/kroopt_ffi.c`) and Lean wrappers (`Kroopt.Crypto.Hacl`).
The subset is exactly the primitives the `TLS_CHACHA20_POLY1305_SHA256` suite
needs, with X25519 key exchange and Ed25519 server authentication:

| Primitive | HACL\* function | Lean wrapper |
|---|---|---|
| SHA-256 / SHA-384 | `Hacl_Hash_SHA2_hash_256` / `_384` | `sha256` / `sha384` |
| X25519 public | `Hacl_Curve25519_51_secret_to_public` | `x25519Public` |
| X25519 ECDH | `Hacl_Curve25519_51_ecdh` | `x25519Shared` (rejects low-order) |
| ChaCha20-Poly1305 seal | `Hacl_Chacha20Poly1305_32_aead_encrypt` | `chachaPolySeal` |
| ChaCha20-Poly1305 open | `Hacl_Chacha20Poly1305_32_aead_decrypt` | `chachaPolyOpen` (auth-checked) |
| HKDF-Extract (SHA-256) | `Hacl_HKDF_extract_sha2_256` | `hkdfExtract256` |
| HKDF-Expand (SHA-256) | `Hacl_HKDF_expand_sha2_256` | `hkdfExpand256` |
| HMAC-SHA256 | `Hacl_HMAC_compute_sha2_256` | `hmac256` |
| Ed25519 sign / verify | `Hacl_Ed25519_sign` / `_verify` | `ed25519Sign` / `ed25519Verify` |
| OS CSPRNG | `getrandom(2)` | `randomBytes : IO` |

No vale assembly is vendored — the AES-GCM paths are omitted, so the build is
pure portable C and reproducible on any platform with a C11 compiler. Section
GC (`-ffunction-sections` + `-Wl,--gc-sections`) drops the agile-HMAC hash
variants (SHA-1, Blake2) that the suite never calls but that the HMAC
translation unit references.

### Verified end-to-end through Lean

`Tests.Hacl` (the `kroopt-hacl-test` executable) runs known-answer tests **across
the FFI**, not just in standalone C: SHA-256 against FIPS 180-4, X25519 against
RFC 7748, HKDF against RFC 5869 TC1, HMAC against RFC 4231 TC1, plus AEAD and
Ed25519 round-trips with tamper/forgery rejection, and CSPRNG length and
non-constancy. A green run proves the native crypto path works inside the Lean
build, exercising the real `Hacl_*` object code.

The deterministic primitives are pure `@[extern]` functions (they are
referentially transparent for fixed inputs); `randomBytes` is `IO` because it
draws OS entropy.

## The honest boundary: why this is not yet wired into the key schedule

kroopt's verified core talks to crypto through one pure interface
(`Kroopt.Crypto.CryptoProvider`):

```
submit : OperationId → CryptoOp → Except CryptoError CryptoResult
```

This interface is **pure and stateless**, and the ECDHE/HKDF operations return
*opaque secret handles* (`SecretKeyHandle`), not key bytes — by design, so that
secret material never becomes a printable Lean value and the safety proofs hold
for *any* provider (see [Crypto provider and FFI contract](crypto-ffi-contract.md)
and the [boundary](../architecture/boundary.md) note). The deterministic fake provider exploits
this: its AEAD is the identity function and it never threads real key material.

Real TLS, however, must thread real bytes through the key schedule:

```
ECDHE shared secret → HKDF-Extract → derive-secret → traffic keys → AEAD
```

A *pure, handle-returning* provider cannot do this, because resolving a handle to
the key bytes it names requires **state** (a secret arena) that a pure `submit`
cannot carry between calls. The fake sidesteps the problem by never using the
keys; a real provider cannot.

Therefore this milestone deliberately stops at *primitives callable and
KAT-verified through Lean*. Wiring them into the live key schedule is the next
step and needs a **provider-arena refactor**:

- give the provider an explicit, zeroizable secret arena (handles index into it);
- thread that arena through `submit` (either an `IO`/`ST` provider, or a pure
  provider parameterized by an arena value that the interpreter owns);
- keep the verified core's proofs intact by preserving the *handle opacity* the
  current theorems rely on (the core still never sees key bytes).

This is a design change to the crypto seam, not just a binding, which is why it
is scoped separately rather than rushed into v0.3. The binding here de-risks the
hard part — that the verified C builds, links, and computes correctly from Lean,
offline and reproducibly.

## Build and toolchain notes

- The native library requires a C11 compiler (gcc/clang). The pure verified
  Lean core still builds with **no** C toolchain (`lake build Kroopt`); only the
  FFI library and `kroopt-hacl-test` need a compiler.
- `lake build` (all default targets) now compiles the vendored C, so CI for the
  full target set requires gcc. This is expected for the native milestone.
- The vendored tree is ~1.2 MB of generated C and headers under
  `Kroopt/Native/hacl/`; see [`NOTICE`](../../NOTICE) for license attribution.
