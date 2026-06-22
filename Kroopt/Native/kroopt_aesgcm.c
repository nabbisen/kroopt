/* AES-128/256-GCM FFI wrappers over the HACL-star EverCrypt Vale verified x86_64 assembly
 * (RFC 008/009).
 *
 * The cipher math stays in the ASSUMED-verified crypto tier — this file only marshals Lean ByteArrays
 * to EverCrypt's AEAD interface, which dispatches AES-GCM to the Vale-generated gcm128/256 opt
 * routines (AES-NI + PCLMULQDQ). Built with -DHACL_CAN_COMPILE_VALE=1 -DHACL_CAN_COMPILE_VEC128
 * -DHACL_CAN_COMPILE_VEC256 -mavx2 -maes -mpclmul, which gate both the CPUID detection in
 * EverCrypt_AutoConfig2_init and the create_in AES path.
 *
 * ABI mirrors kroopt's ChaCha20-Poly1305 wrappers exactly:
 *   seal(key, nonce, aad, pt)    -> ciphertext(mlen) ++ tag(16);    empty result = fail-closed reject.
 *   open(key, nonce, aad, ctTag) -> [status(1)] ++ plaintext(mlen); status 0 = ok, 1 = auth/length fail.
 */
#include <lean/lean.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "EverCrypt_AEAD.h"
#include "EverCrypt_AutoConfig2.h"
#include "EverCrypt_Error.h"
#include "Hacl_Spec.h"

static inline uint8_t   *ba_ptr(b_lean_obj_arg a) { return lean_sarray_cptr(a); }
static inline size_t     ba_len(b_lean_obj_arg a) { return lean_sarray_size(a); }
static inline lean_object *mk_ba(size_t n)        { return lean_alloc_sarray(1, n, n); }

/* kroopt drives ChaCha20-Poly1305 via Hacl_Chacha20Poly1305_32 directly; the EverCrypt AEAD
 * dispatcher references these only in its CHACHA20_POLY1305 case, which the AES path never reaches.
 * Defined here to satisfy the link; abort() makes an accidental call fail loudly rather than silently. */
void EverCrypt_Chacha20Poly1305_aead_encrypt(uint8_t *k, uint8_t *n, uint32_t al, uint8_t *a,
                                             uint32_t ml, uint8_t *m, uint8_t *c, uint8_t *t) {
  (void)k;(void)n;(void)al;(void)a;(void)ml;(void)m;(void)c;(void)t; abort();
}
uint32_t EverCrypt_Chacha20Poly1305_aead_decrypt(uint8_t *k, uint8_t *n, uint32_t al, uint8_t *a,
                                                 uint32_t ml, uint8_t *m, uint8_t *c, uint8_t *t) {
  (void)k;(void)n;(void)al;(void)a;(void)ml;(void)m;(void)c;(void)t; abort(); return 1;
}

/* EverCrypt CPU-feature detection is idempotent; init once before the first AES op. */
static int g_autoconfig_done = 0;
static void ensure_autoconfig(void) {
  if (!g_autoconfig_done) { EverCrypt_AutoConfig2_init(); g_autoconfig_done = 1; }
}

static lean_object *gcm_seal(Spec_Agile_AEAD_alg alg, size_t key_len,
                             b_lean_obj_arg key, b_lean_obj_arg nonce,
                             b_lean_obj_arg aad, b_lean_obj_arg pt) {
  size_t mlen = ba_len(pt);
  /* RFC 037 §2: validate before the call and reject (empty result), never truncate. */
  if (ba_len(key) != key_len || ba_len(nonce) != 12 ||
      ba_len(aad) > UINT32_MAX || mlen > UINT32_MAX) {
    return mk_ba(0);
  }
  ensure_autoconfig();
  EverCrypt_AEAD_state_s *st = NULL;
  if (EverCrypt_AEAD_create_in(alg, &st, ba_ptr(key)) != EverCrypt_Error_Success) {
    return mk_ba(0);
  }
  lean_object *r = mk_ba(mlen + 16);
  uint8_t *out = lean_sarray_cptr(r);
  EverCrypt_AEAD_encrypt(st, ba_ptr(nonce), 12, ba_ptr(aad), (uint32_t)ba_len(aad),
                         ba_ptr(pt), (uint32_t)mlen, out, out + mlen);
  EverCrypt_AEAD_free(st);
  return r;
}

static lean_object *gcm_open(Spec_Agile_AEAD_alg alg, size_t key_len,
                             b_lean_obj_arg key, b_lean_obj_arg nonce,
                             b_lean_obj_arg aad, b_lean_obj_arg ctTag) {
  size_t ctlen = ba_len(ctTag);
  /* Fail-closed on any length violation — indistinguishable from an auth failure (status 1),
   * so no plaintext is ever emitted on a malformed call. */
  if (ba_len(key) != key_len || ba_len(nonce) != 12 ||
      ba_len(aad) > UINT32_MAX || ctlen < 16 || (ctlen - 16) > UINT32_MAX) {
    lean_object *r = mk_ba(1); lean_sarray_cptr(r)[0] = 1; return r;
  }
  ensure_autoconfig();
  EverCrypt_AEAD_state_s *st = NULL;
  if (EverCrypt_AEAD_create_in(alg, &st, ba_ptr(key)) != EverCrypt_Error_Success) {
    lean_object *r = mk_ba(1); lean_sarray_cptr(r)[0] = 1; return r;
  }
  size_t mlen = ctlen - 16;
  lean_object *r = mk_ba(1 + mlen);
  uint8_t *out = lean_sarray_cptr(r);
  uint8_t *ct  = ba_ptr(ctTag);
  EverCrypt_Error_error_code res =
    EverCrypt_AEAD_decrypt(st, ba_ptr(nonce), 12, ba_ptr(aad), (uint32_t)ba_len(aad),
                           ct, (uint32_t)mlen, ct + mlen, out + 1);
  EverCrypt_AEAD_free(st);
  out[0] = (res == EverCrypt_Error_Success) ? 0 : 1;
  if (res != EverCrypt_Error_Success) memset(out + 1, 0, mlen);
  return r;
}

LEAN_EXPORT lean_object *kroopt_ffi_aes128_gcm_seal(b_lean_obj_arg k, b_lean_obj_arg n,
                                                    b_lean_obj_arg a, b_lean_obj_arg p) {
  return gcm_seal(Spec_Agile_AEAD_AES128_GCM, 16, k, n, a, p);
}
LEAN_EXPORT lean_object *kroopt_ffi_aes128_gcm_open(b_lean_obj_arg k, b_lean_obj_arg n,
                                                    b_lean_obj_arg a, b_lean_obj_arg c) {
  return gcm_open(Spec_Agile_AEAD_AES128_GCM, 16, k, n, a, c);
}
LEAN_EXPORT lean_object *kroopt_ffi_aes256_gcm_seal(b_lean_obj_arg k, b_lean_obj_arg n,
                                                    b_lean_obj_arg a, b_lean_obj_arg p) {
  return gcm_seal(Spec_Agile_AEAD_AES256_GCM, 32, k, n, a, p);
}
LEAN_EXPORT lean_object *kroopt_ffi_aes256_gcm_open(b_lean_obj_arg k, b_lean_obj_arg n,
                                                    b_lean_obj_arg a, b_lean_obj_arg c) {
  return gcm_open(Spec_Agile_AEAD_AES256_GCM, 32, k, n, a, c);
}
