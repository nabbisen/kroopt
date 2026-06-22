/*
 * kroopt_ffi.c — Lean <-> HACL* FFI glue (v0.3 native crypto binding).
 *
 * Thin, boring marshalling between Lean `ByteArray`s and the vendored HACL*
 * portable-C primitives (Kroopt/Native/hacl/). No protocol logic, no algorithm
 * negotiation, no logging — just buffer conversion and a direct primitive call
 * (RFC 009 §10). Each function borrows its Lean inputs (`b_lean_obj_arg`) and
 * returns a freshly allocated owned `ByteArray`.
 *
 * Status conventions where a primitive can fail:
 *   - x25519_shared / aead_open / *_verify prepend or use a 1-byte status
 *     (0 = ok, 1 = failure) so the Lean side gets a total result.
 *
 * The crypto math is HACL* and EverCrypt (Project Everest), ASSUMED-verified and
 * borrowed; this file only wires it to Lean.
 */
#include <lean/lean.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/random.h>

#include "Hacl_Hash_SHA2.h"
#include "Hacl_Curve25519_51.h"
#include "Hacl_Chacha20Poly1305_32.h"
#include "Hacl_HKDF.h"
#include "Hacl_HMAC.h"
#include "Hacl_Ed25519.h"
#include "Hacl_P256.h"

static inline uint8_t *ba_ptr(b_lean_obj_arg a) { return lean_sarray_cptr(a); }
static inline size_t   ba_len(b_lean_obj_arg a) { return lean_sarray_size(a); }
static inline lean_object *mk_ba(size_t n) { return lean_alloc_sarray(1, n, n); }

/* RFC 037 §2: a variable-length input must fit the uint32_t HACL parameter; a length
   that does not is rejected (empty result), never truncated. */
static inline bool len_u32_ok(b_lean_obj_arg a) { return ba_len(a) <= (size_t)UINT32_MAX; }

LEAN_EXPORT lean_object *kroopt_ffi_sha256(b_lean_obj_arg input) {
  if (!len_u32_ok(input)) return mk_ba(0);
  lean_object *r = mk_ba(32);
  Hacl_Hash_SHA2_hash_256(ba_ptr(input), (uint32_t)ba_len(input), lean_sarray_cptr(r));
  return r;
}

LEAN_EXPORT lean_object *kroopt_ffi_sha384(b_lean_obj_arg input) {
  if (!len_u32_ok(input)) return mk_ba(0);
  lean_object *r = mk_ba(48);
  Hacl_Hash_SHA2_hash_384(ba_ptr(input), (uint32_t)ba_len(input), lean_sarray_cptr(r));
  return r;
}

LEAN_EXPORT lean_object *kroopt_ffi_sha512(b_lean_obj_arg input) {
  if (!len_u32_ok(input)) return mk_ba(0);
  lean_object *r = mk_ba(64);
  Hacl_Hash_SHA2_hash_512(ba_ptr(input), (uint32_t)ba_len(input), lean_sarray_cptr(r));
  return r;
}

LEAN_EXPORT lean_object *kroopt_ffi_x25519_public(b_lean_obj_arg priv) {
  if (ba_len(priv) != 32) return mk_ba(0);
  lean_object *r = mk_ba(32);
  Hacl_Curve25519_51_secret_to_public(lean_sarray_cptr(r), ba_ptr(priv));
  return r;
}

/* returns [status]++shared(32); status 1 if the result is a low-order point. */
LEAN_EXPORT lean_object *kroopt_ffi_x25519_shared(b_lean_obj_arg priv, b_lean_obj_arg peer) {
  lean_object *r = mk_ba(33);
  uint8_t *q = lean_sarray_cptr(r);
  /* RFC 037 §2: X25519 requires 32-byte scalars; reject (status 1), never read OOB. */
  if (ba_len(priv) != 32 || ba_len(peer) != 32) { q[0] = 1; memset(q + 1, 0, 32); return r; }
  bool ok = Hacl_Curve25519_51_ecdh(q + 1, ba_ptr(priv), ba_ptr(peer));
  q[0] = ok ? 0 : 1;
  if (!ok) memset(q + 1, 0, 32);
  return r;
}

/* returns ciphertext(mlen)++tag(16); empty ByteArray on a length violation (reject). */
LEAN_EXPORT lean_object *kroopt_ffi_aead_seal(b_lean_obj_arg key, b_lean_obj_arg nonce,
                                              b_lean_obj_arg aad, b_lean_obj_arg pt) {
  size_t mlen = ba_len(pt);
  /* RFC 037 §2: validate before the HACL call; reject (empty result, the random-style
     fail-closed sentinel), never truncate. key=32, nonce=12; AAD and plaintext lengths
     must fit the uint32_t HACL parameters. Unreachable for well-formed kroopt inputs. */
  if (ba_len(key) != 32 || ba_len(nonce) != 12 ||
      ba_len(aad) > UINT32_MAX || mlen > UINT32_MAX) {
    return mk_ba(0);
  }
  lean_object *r = mk_ba(mlen + 16);
  uint8_t *out = lean_sarray_cptr(r);
  Hacl_Chacha20Poly1305_32_aead_encrypt(ba_ptr(key), ba_ptr(nonce),
                                        (uint32_t)ba_len(aad), ba_ptr(aad),
                                        (uint32_t)mlen, ba_ptr(pt), out, out + mlen);
  return r;
}

/* input is ciphertext(mlen)++tag(16); returns [status]++plaintext(mlen). */
LEAN_EXPORT lean_object *kroopt_ffi_aead_open(b_lean_obj_arg key, b_lean_obj_arg nonce,
                                              b_lean_obj_arg aad, b_lean_obj_arg ctTag) {
  size_t ctlen = ba_len(ctTag);
  /* RFC 037 §2: validate every length before the HACL call and reject (status 1),
     never truncate. ChaCha20-Poly1305 requires key=32 and nonce=12; the AAD and
     message lengths must fit the uint32_t HACL parameters. Fails closed — a length
     violation is indistinguishable to the caller from an authentication failure
     (Option none), so no plaintext is ever emitted on a malformed call. */
  if (ba_len(key) != 32 || ba_len(nonce) != 12 ||
      ba_len(aad) > UINT32_MAX || ctlen < 16 || (ctlen - 16) > UINT32_MAX) {
    lean_object *r = mk_ba(1); lean_sarray_cptr(r)[0] = 1; return r;
  }
  size_t mlen = ctlen - 16;
  lean_object *r = mk_ba(1 + mlen);
  uint8_t *out = lean_sarray_cptr(r);
  uint8_t *ct = ba_ptr(ctTag);
  uint32_t res = Hacl_Chacha20Poly1305_32_aead_decrypt(ba_ptr(key), ba_ptr(nonce),
                                                       (uint32_t)ba_len(aad), ba_ptr(aad),
                                                       (uint32_t)mlen, out + 1, ct, ct + mlen);
  out[0] = (res == 0) ? 0 : 1;
  if (res != 0) memset(out + 1, 0, mlen);
  return r;
}

LEAN_EXPORT lean_object *kroopt_ffi_hkdf_extract256(b_lean_obj_arg salt, b_lean_obj_arg ikm) {
  if (!len_u32_ok(salt) || !len_u32_ok(ikm)) return mk_ba(0);
  lean_object *r = mk_ba(32);
  Hacl_HKDF_extract_sha2_256(lean_sarray_cptr(r), ba_ptr(salt), (uint32_t)ba_len(salt),
                             ba_ptr(ikm), (uint32_t)ba_len(ikm));
  return r;
}

LEAN_EXPORT lean_object *kroopt_ffi_hkdf_expand256(b_lean_obj_arg prk, b_lean_obj_arg info,
                                                   uint32_t len) {
  if (!len_u32_ok(prk) || !len_u32_ok(info)) return mk_ba(0);
  lean_object *r = mk_ba(len);
  Hacl_HKDF_expand_sha2_256(lean_sarray_cptr(r), ba_ptr(prk), (uint32_t)ba_len(prk),
                            ba_ptr(info), (uint32_t)ba_len(info), len);
  return r;
}

LEAN_EXPORT lean_object *kroopt_ffi_hmac256(b_lean_obj_arg key, b_lean_obj_arg msg) {
  if (!len_u32_ok(key) || !len_u32_ok(msg)) return mk_ba(0);
  lean_object *r = mk_ba(32);
  Hacl_HMAC_compute_sha2_256(lean_sarray_cptr(r), ba_ptr(key), (uint32_t)ba_len(key),
                             ba_ptr(msg), (uint32_t)ba_len(msg));
  return r;
}

LEAN_EXPORT lean_object *kroopt_ffi_ed25519_public(b_lean_obj_arg priv) {
  if (ba_len(priv) != 32) return mk_ba(0);
  lean_object *r = mk_ba(32);
  Hacl_Ed25519_secret_to_public(lean_sarray_cptr(r), ba_ptr(priv));
  return r;
}

LEAN_EXPORT lean_object *kroopt_ffi_ed25519_sign(b_lean_obj_arg priv, b_lean_obj_arg msg) {
  if (ba_len(priv) != 32 || !len_u32_ok(msg)) return mk_ba(0);
  lean_object *r = mk_ba(64);
  Hacl_Ed25519_sign(lean_sarray_cptr(r), ba_ptr(priv), (uint32_t)ba_len(msg), ba_ptr(msg));
  return r;
}

/* returns a 1-byte result: 1 = valid, 0 = invalid. */
LEAN_EXPORT lean_object *kroopt_ffi_ed25519_verify(b_lean_obj_arg pub, b_lean_obj_arg msg,
                                                   b_lean_obj_arg sig) {
  lean_object *r = mk_ba(1);
  /* RFC 037 §2: Ed25519 requires a 32-byte public key and 64-byte signature; the
     message length must fit the uint32_t HACL parameter. Any violation is rejected
     as invalid (result 0) before the HACL call — fails closed, never reads OOB. */
  if (ba_len(pub) != 32 || ba_len(sig) != 64 || ba_len(msg) > UINT32_MAX) {
    lean_sarray_cptr(r)[0] = 0; return r;
  }
  bool ok = Hacl_Ed25519_verify(ba_ptr(pub), (uint32_t)ba_len(msg), ba_ptr(msg), ba_ptr(sig));
  lean_sarray_cptr(r)[0] = ok ? 1 : 0;
  return r;
}

/* IO: fill `len` bytes from the OS CSPRNG (getrandom). Fails CLOSED: on any
 * getrandom failure it returns a zero-length ByteArray (never a zero-filled
 * buffer reported as success), and the Lean wrapper turns a short read into a
 * typed entropy error so no caller can proceed with degraded entropy. */
LEAN_EXPORT lean_object *kroopt_ffi_random(uint32_t len, lean_object *w) {
  (void)w;
  uint8_t *tmp = (uint8_t *)malloc(len ? len : 1);
  size_t got = 0;
  int failed = 0;
  while (got < len) {
    ssize_t n = getrandom(tmp + got, (size_t)len - got, 0);
    if (n <= 0) { failed = 1; break; }
    got += (size_t)n;
  }
  lean_object *r;
  if (failed) {
    r = lean_alloc_sarray(1, 0, 0);          /* empty => entropy failure */
  } else {
    r = lean_alloc_sarray(1, len, len);
    memcpy(lean_sarray_cptr(r), tmp, len);
  }
  free(tmp);
  return lean_io_result_mk_ok(r);
}


/* ── P-256 (secp256r1) ECDHE — RFC 8446 §4.2.8 / §7.4.2 (v0.4 group breadth) ──
   Wire key_share is the uncompressed point 0x04||X||Y (65 bytes); HACL works on the
   raw 64-byte X||Y. The ECDH shared secret is the 32-byte X-coordinate. */
LEAN_EXPORT lean_object *kroopt_ffi_p256_public(b_lean_obj_arg priv) {
  if (ba_len(priv) != 32) return mk_ba(0);
  lean_object *r = mk_ba(65);
  uint8_t *out = lean_sarray_cptr(r);
  out[0] = 0x04;
  bool ok = Hacl_P256_ecp256dh_i(out + 1, ba_ptr(priv));
  if (!ok) return mk_ba(0);   /* point at infinity / bad scalar: empty result */
  return r;
}

LEAN_EXPORT lean_object *kroopt_ffi_p256_shared(b_lean_obj_arg priv, b_lean_obj_arg peer) {
  lean_object *r = mk_ba(33);
  uint8_t *q = lean_sarray_cptr(r);
  /* priv must be 32 bytes; peer must be a 65-byte uncompressed point. Reject otherwise
     (status 1), never read out of bounds. */
  if (ba_len(priv) != 32 || ba_len(peer) != 65 || ba_ptr(peer)[0] != 0x04) {
    q[0] = 1; memset(q + 1, 0, 32); return r;
  }
  uint8_t shared[64];
  bool ok = Hacl_P256_ecp256dh_r(shared, ba_ptr(peer) + 1, ba_ptr(priv));
  q[0] = ok ? 0 : 1;
  if (ok) memcpy(q + 1, shared, 32); else memset(q + 1, 0, 32);
  return r;
}


/* ── ECDSA P-256 over SHA-256 — RFC 8446 ecdsa_secp256r1_sha256 (v0.4 server auth) ──
   sign: hashes m with SHA-256 internally, signs with privKey using nonce k. Returns 65 bytes
   status(1) || raw(64 = r‖s); the caller DER-encodes raw for the CertificateVerify wire. Fails
   closed (status 1) on wrong-size key/nonce. verify: pub is the 65-byte uncompressed point. */
LEAN_EXPORT lean_object *kroopt_ffi_ecdsa_p256_sign(b_lean_obj_arg m, b_lean_obj_arg priv,
                                                    b_lean_obj_arg k) {
  lean_object *r = mk_ba(65);
  uint8_t *q = lean_sarray_cptr(r);
  if (ba_len(priv) != 32 || ba_len(k) != 32 || ba_len(m) > UINT32_MAX) {
    q[0] = 1; memset(q + 1, 0, 64); return r;
  }
  bool ok = Hacl_P256_ecdsa_sign_p256_sha2(q + 1, (uint32_t)ba_len(m), ba_ptr(m),
                                           ba_ptr(priv), ba_ptr(k));
  q[0] = ok ? 0 : 1;
  if (!ok) memset(q + 1, 0, 64);
  return r;
}

LEAN_EXPORT lean_object *kroopt_ffi_ecdsa_p256_verify(b_lean_obj_arg m, b_lean_obj_arg pub,
                                                      b_lean_obj_arg sigraw) {
  lean_object *r = mk_ba(1);
  if (ba_len(pub) != 65 || ba_ptr(pub)[0] != 0x04 || ba_len(sigraw) != 64 || ba_len(m) > UINT32_MAX) {
    lean_sarray_cptr(r)[0] = 0; return r;
  }
  bool ok = Hacl_P256_ecdsa_verif_p256_sha2((uint32_t)ba_len(m), ba_ptr(m), ba_ptr(pub) + 1,
                                            ba_ptr(sigraw), ba_ptr(sigraw) + 32);
  lean_sarray_cptr(r)[0] = ok ? 1 : 0;
  return r;
}
