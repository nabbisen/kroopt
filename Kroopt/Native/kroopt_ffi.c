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

static inline uint8_t *ba_ptr(b_lean_obj_arg a) { return lean_sarray_cptr(a); }
static inline size_t   ba_len(b_lean_obj_arg a) { return lean_sarray_size(a); }
static inline lean_object *mk_ba(size_t n) { return lean_alloc_sarray(1, n, n); }

LEAN_EXPORT lean_object *kroopt_ffi_sha256(b_lean_obj_arg input) {
  lean_object *r = mk_ba(32);
  Hacl_Hash_SHA2_hash_256(ba_ptr(input), (uint32_t)ba_len(input), lean_sarray_cptr(r));
  return r;
}

LEAN_EXPORT lean_object *kroopt_ffi_sha384(b_lean_obj_arg input) {
  lean_object *r = mk_ba(48);
  Hacl_Hash_SHA2_hash_384(ba_ptr(input), (uint32_t)ba_len(input), lean_sarray_cptr(r));
  return r;
}

LEAN_EXPORT lean_object *kroopt_ffi_sha512(b_lean_obj_arg input) {
  lean_object *r = mk_ba(64);
  Hacl_Hash_SHA2_hash_512(ba_ptr(input), (uint32_t)ba_len(input), lean_sarray_cptr(r));
  return r;
}

LEAN_EXPORT lean_object *kroopt_ffi_x25519_public(b_lean_obj_arg priv) {
  lean_object *r = mk_ba(32);
  Hacl_Curve25519_51_secret_to_public(lean_sarray_cptr(r), ba_ptr(priv));
  return r;
}

/* returns [status]++shared(32); status 1 if the result is a low-order point. */
LEAN_EXPORT lean_object *kroopt_ffi_x25519_shared(b_lean_obj_arg priv, b_lean_obj_arg peer) {
  lean_object *r = mk_ba(33);
  uint8_t *q = lean_sarray_cptr(r);
  bool ok = Hacl_Curve25519_51_ecdh(q + 1, ba_ptr(priv), ba_ptr(peer));
  q[0] = ok ? 0 : 1;
  if (!ok) memset(q + 1, 0, 32);
  return r;
}

/* returns ciphertext(mlen)++tag(16). */
LEAN_EXPORT lean_object *kroopt_ffi_aead_seal(b_lean_obj_arg key, b_lean_obj_arg nonce,
                                              b_lean_obj_arg aad, b_lean_obj_arg pt) {
  size_t mlen = ba_len(pt);
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
  if (ctlen < 16) { lean_object *r = mk_ba(1); lean_sarray_cptr(r)[0] = 1; return r; }
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
  lean_object *r = mk_ba(32);
  Hacl_HKDF_extract_sha2_256(lean_sarray_cptr(r), ba_ptr(salt), (uint32_t)ba_len(salt),
                             ba_ptr(ikm), (uint32_t)ba_len(ikm));
  return r;
}

LEAN_EXPORT lean_object *kroopt_ffi_hkdf_expand256(b_lean_obj_arg prk, b_lean_obj_arg info,
                                                   uint32_t len) {
  lean_object *r = mk_ba(len);
  Hacl_HKDF_expand_sha2_256(lean_sarray_cptr(r), ba_ptr(prk), (uint32_t)ba_len(prk),
                            ba_ptr(info), (uint32_t)ba_len(info), len);
  return r;
}

LEAN_EXPORT lean_object *kroopt_ffi_hmac256(b_lean_obj_arg key, b_lean_obj_arg msg) {
  lean_object *r = mk_ba(32);
  Hacl_HMAC_compute_sha2_256(lean_sarray_cptr(r), ba_ptr(key), (uint32_t)ba_len(key),
                             ba_ptr(msg), (uint32_t)ba_len(msg));
  return r;
}

LEAN_EXPORT lean_object *kroopt_ffi_ed25519_public(b_lean_obj_arg priv) {
  lean_object *r = mk_ba(32);
  Hacl_Ed25519_secret_to_public(lean_sarray_cptr(r), ba_ptr(priv));
  return r;
}

LEAN_EXPORT lean_object *kroopt_ffi_ed25519_sign(b_lean_obj_arg priv, b_lean_obj_arg msg) {
  lean_object *r = mk_ba(64);
  Hacl_Ed25519_sign(lean_sarray_cptr(r), ba_ptr(priv), (uint32_t)ba_len(msg), ba_ptr(msg));
  return r;
}

/* returns a 1-byte result: 1 = valid, 0 = invalid. */
LEAN_EXPORT lean_object *kroopt_ffi_ed25519_verify(b_lean_obj_arg pub, b_lean_obj_arg msg,
                                                   b_lean_obj_arg sig) {
  lean_object *r = mk_ba(1);
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
