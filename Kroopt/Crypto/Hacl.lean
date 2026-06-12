/-!
# Kroopt.Crypto.Hacl

The real native crypto binding (v0.3): Lean wrappers over the vendored
HACL*/EverCrypt portable-C primitives, via the `kroopt_ffi_*` glue
(`Kroopt/Native/kroopt_ffi.c`). These are the verified primitives the TLS 1.3
`TLS_CHACHA20_POLY1305_SHA256` suite needs — SHA-256/384, X25519, the
ChaCha20-Poly1305 AEAD, HKDF/HMAC-SHA256, and Ed25519 — plus an OS CSPRNG.

The crypto math is borrowed and ASSUMED-verified (Project Everest); kroopt only
marshals `ByteArray`s across the FFI. The deterministic primitives are pure
`@[extern]` functions; `randomBytes` is `IO` because it draws OS entropy.

This module lives in the trusted `Crypto` zone and is never imported by the pure
verified core (enforced by the dependency gate).
-/

namespace Kroopt.Crypto.Hacl

@[extern "kroopt_ffi_sha256"]
opaque sha256 (input : ByteArray) : ByteArray

@[extern "kroopt_ffi_sha384"]
opaque sha384 (input : ByteArray) : ByteArray

@[extern "kroopt_ffi_sha512"]
opaque sha512 (input : ByteArray) : ByteArray

@[extern "kroopt_ffi_x25519_public"]
opaque x25519Public (priv : ByteArray) : ByteArray

@[extern "kroopt_ffi_x25519_shared"]
opaque x25519SharedRaw (priv peer : ByteArray) : ByteArray

@[extern "kroopt_ffi_aead_seal"]
opaque chachaPolySeal (key nonce aad pt : ByteArray) : ByteArray

@[extern "kroopt_ffi_aead_open"]
opaque chachaPolyOpenRaw (key nonce aad ctTag : ByteArray) : ByteArray

@[extern "kroopt_ffi_hkdf_extract256"]
opaque hkdfExtract256 (salt ikm : ByteArray) : ByteArray

@[extern "kroopt_ffi_hkdf_expand256"]
opaque hkdfExpand256 (prk info : ByteArray) (len : UInt32) : ByteArray

@[extern "kroopt_ffi_hmac256"]
opaque hmac256 (key msg : ByteArray) : ByteArray

@[extern "kroopt_ffi_ed25519_public"]
opaque ed25519Public (priv : ByteArray) : ByteArray

@[extern "kroopt_ffi_ed25519_sign"]
opaque ed25519Sign (priv msg : ByteArray) : ByteArray

@[extern "kroopt_ffi_ed25519_verify"]
opaque ed25519VerifyRaw (pub msg sig : ByteArray) : ByteArray

/-- The outcome of an entropy draw. Randomness never fails open: a short or
failed `getrandom` becomes `error`, and no caller may synthesise fallback bytes
(RFC 034 §3). -/
inductive EntropyError where
  | unavailable
  deriving DecidableEq, Repr, Inhabited

inductive RandomResult where
  | bytes (b : ByteArray)
  | error (e : EntropyError)
  deriving Inhabited

/-- Raw OS-CSPRNG draw. Returns exactly `len` bytes on success, or a zero-length
array on failure (the native side fails closed). Use `randomBytes`, not this. -/
@[extern "kroopt_ffi_random"]
private opaque randomRaw (len : UInt32) : IO ByteArray

/-- Draw `len` bytes from the OS CSPRNG, failing closed. A short read (the native
fail-closed signal) becomes `RandomResult.error`; only a full-length draw yields
`bytes`. This is the single real entropy source; kroopt implements no PRNG and no
fallback (requirements §3.3). -/
def randomBytes (len : UInt32) : IO RandomResult := do
  let b ← randomRaw len
  pure (if b.size == len.toNat then .bytes b else .error .unavailable)

/-- X25519 ECDH. `none` if the peer key produces a low-order (all-zero) shared
secret, which TLS 1.3 must reject. -/
def x25519Shared (priv peer : ByteArray) : Option ByteArray :=
  let r := x25519SharedRaw priv peer
  if r.size == 33 ∧ r.get! 0 == 0 then some (r.extract 1 33) else none

/-- ChaCha20-Poly1305 open. `none` on authentication failure (no plaintext is
returned on failure). -/
def chachaPolyOpen (key nonce aad ctTag : ByteArray) : Option ByteArray :=
  let r := chachaPolyOpenRaw key nonce aad ctTag
  if r.size ≥ 1 ∧ r.get! 0 == 0 then some (r.extract 1 r.size) else none

/-- Ed25519 verification. -/
def ed25519Verify (pub msg sig : ByteArray) : Bool :=
  let r := ed25519VerifyRaw pub msg sig
  r.size == 1 ∧ r.get! 0 == 1

end Kroopt.Crypto.Hacl
