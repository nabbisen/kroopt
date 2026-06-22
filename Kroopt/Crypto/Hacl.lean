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

/-- P-256 (secp256r1) public key from a 32-byte scalar, as the 65-byte uncompressed wire point
`0x04 || X || Y`. Empty on failure (bad scalar / point at infinity). -/
@[extern "kroopt_ffi_p256_public"]
opaque p256Public (priv : ByteArray) : ByteArray

/-- P-256 ECDH: 33-byte result `status(1) || sharedX(32)` from a 32-byte scalar and the peer's
65-byte uncompressed point. `status = 0` on success; the TLS 1.3 shared secret is `sharedX` (RFC
8446 §7.4.2). -/
@[extern "kroopt_ffi_p256_shared"]
opaque p256SharedRaw (priv peer : ByteArray) : ByteArray

/-- ECDSA P-256 / SHA-256 sign. `m` is hashed with SHA-256 internally; `k` is the per-signature
nonce (must be fresh and in `[1, n-1]`). Returns 65 bytes `status(1) || raw(64 = r‖s)`. -/
@[extern "kroopt_ffi_ecdsa_p256_sign"]
opaque ecdsaP256SignRaw (m priv k : ByteArray) : ByteArray

/-- ECDSA P-256 / SHA-256 verify against the 65-byte uncompressed public point and a raw 64-byte
`r‖s`. Returns a 1-byte `0/1` result. -/
@[extern "kroopt_ffi_ecdsa_p256_verify"]
opaque ecdsaP256VerifyRaw (m pub sigraw : ByteArray) : ByteArray

/-- RSA-PSS / SHA-256 sign (RFC 8446 rsa_pss_rsae_sha256). Loads the private key from `n`, `e`, `d`
byte arrays and signs `msg` with `salt`. Returns `status(1) || sgnt(n.size)`. -/
@[extern "kroopt_ffi_rsapss_sign"]
opaque rsapssSignRaw (n e d salt msg : ByteArray) : ByteArray

/-- RSA-PSS / SHA-256 verify against the public key `(n, e)` with the given salt length. Returns a
1-byte `0/1` result. -/
@[extern "kroopt_ffi_rsapss_verify"]
opaque rsapssVerifyRaw (n e : ByteArray) (saltLen : UInt32) (sgnt msg : ByteArray) : ByteArray

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

/-- P-256 ECDH. `none` on failure (wrong-size inputs, malformed peer point, or point at
infinity); otherwise the 32-byte shared secret (the X-coordinate, per RFC 8446 §7.4.2). -/
def p256Shared (priv peer : ByteArray) : Option ByteArray :=
  let r := p256SharedRaw priv peer
  if r.size == 33 ∧ r.get! 0 == 0 then some (r.extract 1 33) else none

/-- DER-encode one 32-byte big-endian unsigned integer as an ASN.1 `INTEGER` (`0x02 len value`),
minimally (strip leading zero bytes; prepend `0x00` when the high bit is set so the value stays
positive). Each P-256 component is ≤ 33 content bytes, so the length is always short-form. -/
private def derInteger (bytes : ByteArray) : ByteArray :=
  let stripped := bytes.toList.dropWhile (· == 0)
  let stripped := if stripped.isEmpty then [0] else stripped
  let content := if stripped.head! &&& 0x80 != 0 then (0 : UInt8) :: stripped else stripped
  ByteArray.mk (#[0x02, content.length.toUInt8] ++ content.toArray)

/-- DER-encode a raw ECDSA signature `r‖s` (each 32 bytes) as `Ecdsa-Sig-Value ::= SEQUENCE { r
INTEGER, s INTEGER }`, the form TLS 1.3 carries in CertificateVerify (RFC 8446 §4.4.3, RFC 3279
§2.2.3). `none` if `raw` is not 64 bytes. -/
def derEncodeEcdsaSig (raw : ByteArray) : Option ByteArray :=
  if raw.size != 64 then none else
    let body := derInteger (raw.extract 0 32) ++ derInteger (raw.extract 32 64)
    some (ByteArray.mk (#[0x30, body.size.toUInt8] ++ body.data))

/-- ECDSA P-256 / SHA-256 sign, returning the DER-encoded signature ready for the wire, or `none`
on failure (wrong-size key/nonce, or HACL rejection). -/
def ecdsaP256SignDer (m priv k : ByteArray) : Option ByteArray :=
  let r := ecdsaP256SignRaw m priv k
  if r.size == 65 ∧ r.get! 0 == 0 then derEncodeEcdsaSig (r.extract 1 65) else none

/-- ECDSA P-256 / SHA-256 verify over the raw 64-byte `r‖s`. -/
def ecdsaP256Verify (m pub sigraw : ByteArray) : Bool :=
  let r := ecdsaP256VerifyRaw m pub sigraw
  r.size == 1 ∧ r.get! 0 == 1

/-- RSA-PSS / SHA-256 sign of `msg` (the CertificateVerify signing input) with the private key
`(n, e, d)` and a 32-byte salt (TLS 1.3 requires saltLen = hashLen = 32, RFC 8446 §4.2.3). Returns
the raw RSA signature (`n.size` bytes), or `none` on failure. -/
def rsapssSign (n e d salt msg : ByteArray) : Option ByteArray :=
  let r := rsapssSignRaw n e d salt msg
  if r.size == n.size + 1 ∧ r.get! 0 == 0 then some (r.extract 1 r.size) else none

/-- RSA-PSS / SHA-256 verify of `sgnt` over `msg` against the public key `(n, e)`. -/
def rsapssVerify (n e : ByteArray) (saltLen : UInt32) (sgnt msg : ByteArray) : Bool :=
  let r := rsapssVerifyRaw n e saltLen sgnt msg
  r.size == 1 ∧ r.get! 0 == 1

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
