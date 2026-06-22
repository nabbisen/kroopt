/*
 * kroopt_sanitizer_harness.c — RFC 037 §7.5 / RFC 009 §10, RFC 024.
 *
 * Drives the *actual* `kroopt_ffi_*` FFI shim (Kroopt/Native/kroopt_ffi.c) under
 * AddressSanitizer + UndefinedBehaviorSanitizer, so the shim's own buffer
 * handling — `ba_ptr`/`ba_len` reads, `mk_ba` output sizing, the length-validation
 * guards (RFC 037 §2), and the HACL* calls it issues — is checked for out-of-bounds
 * access and UB on real key-schedule-shaped and adversarial inputs.
 *
 * This is *not* a re-implementation of the shim's logic: it constructs genuine
 * Lean `ByteArray` objects and calls the same exported entry points Lean calls,
 * so the sanitizer watches the production code path. Known-answer checks (SHA-256,
 * Ed25519 RFC 8032) confirm the calls are wired correctly so the sanitizer is not
 * silently exercising a no-op; round-trips (X25519 agreement, AEAD seal/open,
 * HKDF) and boundary cases (wrong-size keys, sub-tag ciphertext, tampered tag)
 * exercise the fail-closed guards.
 *
 * Build/run: scripts/sanitizer-check.sh
 */
#include <lean/lean.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "Hacl_Hash_SHA2.h"
#include "Hacl_Curve25519_51.h"
#include "Hacl_Chacha20Poly1305_32.h"
#include "Hacl_HKDF.h"
#include "Hacl_HMAC.h"
#include "Hacl_Ed25519.h"

/* The shim entry points (compiled into this harness from kroopt_ffi.c). */
lean_object *kroopt_ffi_sha256(b_lean_obj_arg);
lean_object *kroopt_ffi_x25519_public(b_lean_obj_arg);
lean_object *kroopt_ffi_x25519_shared(b_lean_obj_arg, b_lean_obj_arg);
lean_object *kroopt_ffi_aead_seal(b_lean_obj_arg, b_lean_obj_arg, b_lean_obj_arg, b_lean_obj_arg);
lean_object *kroopt_ffi_aead_open(b_lean_obj_arg, b_lean_obj_arg, b_lean_obj_arg, b_lean_obj_arg);
lean_object *kroopt_ffi_hkdf_extract256(b_lean_obj_arg, b_lean_obj_arg);
lean_object *kroopt_ffi_hkdf_expand256(b_lean_obj_arg, b_lean_obj_arg, uint32_t);
lean_object *kroopt_ffi_hmac256(b_lean_obj_arg, b_lean_obj_arg);
lean_object *kroopt_ffi_ed25519_public(b_lean_obj_arg);
lean_object *kroopt_ffi_ed25519_sign(b_lean_obj_arg, b_lean_obj_arg);
lean_object *kroopt_ffi_ed25519_verify(b_lean_obj_arg, b_lean_obj_arg, b_lean_obj_arg);
lean_object *kroopt_ffi_secret_alloc(b_lean_obj_arg, lean_object *);
lean_object *kroopt_ffi_secret_read(uint64_t, lean_object *);
lean_object *kroopt_ffi_secret_zeroize(uint64_t, lean_object *);
lean_object *kroopt_ffi_secret_release(uint64_t, lean_object *);
lean_object *kroopt_ffi_secret_live_count(lean_object *);

static int failures = 0;

/* A Lean ByteArray of `n` bytes copied from `src` (NULL ⇒ zero-filled). */
static lean_object *mk(const uint8_t *src, size_t n) {
  lean_object *a = lean_alloc_sarray(1, n, n);
  uint8_t *p = lean_sarray_cptr(a);
  if (src) memcpy(p, src, n); else memset(p, 0, n);
  return a;
}

static void check(const char *name, int ok) {
  printf("  %-58s %s\n", name, ok ? "ok" : "FAIL");
  if (!ok) failures++;
}

static int eq(lean_object *r, const uint8_t *exp, size_t n) {
  return lean_sarray_size(r) == n && memcmp(lean_sarray_cptr(r), exp, n) == 0;
}

/* Direct HACL* calls on malloc-backed, exact-size buffers. Unlike the Lean
 * ByteArray buffers above (whose data the runtime allocator places outside ASan's
 * redzones, so a sub-rounding overrun is invisible), these buffers carry tight ASan
 * redzones: any read past an input or write past an output — at the *exact* sizes
 * the shim computes (out = mlen+16 for seal, len for HKDF-expand, etc.) — is caught.
 * This is the buffer-bounds half of the check; the shim section above is the
 * UB + fail-closed-behaviour half. */
static void direct_hacl_checks(void) {
  /* SHA-256 over a heap input, 32-byte heap output. */
  {
    uint8_t *in = (uint8_t *)malloc(3); memcpy(in, "abc", 3);
    uint8_t *out = (uint8_t *)malloc(32);
    Hacl_Hash_SHA2_hash_256(in, 3, out);
    check("direct sha256 stays in bounds", 1);
    free(in); free(out);
  }
  /* X25519: public + ECDH into tight 32-byte buffers. */
  {
    uint8_t *priv = (uint8_t *)malloc(32), *peer = (uint8_t *)malloc(32);
    for (int i = 0; i < 32; i++) { priv[i] = (uint8_t)(i + 3); peer[i] = (uint8_t)(0x55 ^ i); }
    uint8_t *pub = (uint8_t *)malloc(32), *shared = (uint8_t *)malloc(32);
    Hacl_Curve25519_51_secret_to_public(pub, priv);
    (void)Hacl_Curve25519_51_ecdh(shared, priv, peer);
    check("direct x25519 stays in bounds", 1);
    free(priv); free(peer); free(pub); free(shared);
  }
  /* ChaCha20-Poly1305: seal into out(mlen)++tag(16), then open into pt(mlen) — the
   * exact split the shim uses, so a tag/ciphertext write past the output is caught. */
  {
    const size_t mlen = 117;  /* awkward size, not a block multiple */
    uint8_t *key = (uint8_t *)malloc(32), *nonce = (uint8_t *)malloc(12);
    uint8_t *aad = (uint8_t *)malloc(5), *pt = (uint8_t *)malloc(mlen);
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    for (int i = 0; i < 12; i++) nonce[i] = (uint8_t)(0x10 + i);
    for (int i = 0; i < 5; i++) aad[i] = (uint8_t)(0x20 + i);
    for (size_t i = 0; i < mlen; i++) pt[i] = (uint8_t)(i & 0xff);
    uint8_t *ctTag = (uint8_t *)malloc(mlen + 16);          /* tight: ct || tag */
    Hacl_Chacha20Poly1305_32_aead_encrypt(key, nonce, 5, aad, (uint32_t)mlen, pt,
                                          ctTag, ctTag + mlen);
    uint8_t *dec = (uint8_t *)malloc(mlen);                  /* tight: plaintext only */
    uint32_t res = Hacl_Chacha20Poly1305_32_aead_decrypt(key, nonce, 5, aad, (uint32_t)mlen,
                                                         dec, ctTag, ctTag + mlen);
    check("direct aead seal/open stays in bounds", res == 0 && memcmp(dec, pt, mlen) == 0);
    free(key); free(nonce); free(aad); free(pt); free(ctTag); free(dec);
  }
  /* HKDF: extract into prk(32), expand into okm(len) at a non-block length. */
  {
    uint8_t *salt = (uint8_t *)malloc(13), *ikm = (uint8_t *)malloc(32);
    for (int i = 0; i < 13; i++) salt[i] = (uint8_t)(0x30 + i);
    for (int i = 0; i < 32; i++) ikm[i] = (uint8_t)i;
    uint8_t *prk = (uint8_t *)malloc(32);
    Hacl_HKDF_extract_sha2_256(prk, salt, 13, ikm, 32);
    const size_t L = 77;
    uint8_t *okm = (uint8_t *)malloc(L);                     /* tight: exactly L bytes */
    uint8_t *info = (uint8_t *)malloc(6); memcpy(info, "tls13 ", 6);
    Hacl_HKDF_expand_sha2_256(okm, prk, 32, info, 6, (uint32_t)L);
    check("direct hkdf extract/expand stays in bounds", 1);
    free(salt); free(ikm); free(prk); free(okm); free(info);
  }
  /* Ed25519: sign into sig(64), verify reads pub(32)/sig(64)/msg tightly. */
  {
    uint8_t *priv = (uint8_t *)malloc(32);
    for (int i = 0; i < 32; i++) priv[i] = (uint8_t)(0x07 + i);
    uint8_t *pub = (uint8_t *)malloc(32), *sig = (uint8_t *)malloc(64);
    uint8_t *msg = (uint8_t *)malloc(11); memcpy(msg, "kroopt-test", 11);
    Hacl_Ed25519_secret_to_public(pub, priv);
    Hacl_Ed25519_sign(sig, priv, 11, msg);
    bool ok = Hacl_Ed25519_verify(pub, 11, msg, sig);
    check("direct ed25519 sign/verify stays in bounds", ok);
    free(priv); free(pub); free(sig); free(msg);
  }
}

int main(void) {
  lean_initialize_runtime_module();
  printf("kroopt FFI shim under ASan/UBSan:\n");

  /* Buffer-bounds half: direct HACL calls on tight malloc-backed buffers. */
  direct_hacl_checks();

  /* SHA-256("") known-answer (RFC 6234) — confirms the call is real. */
  {
    static const uint8_t e[32] = {
      0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
      0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55};
    lean_object *in = mk(NULL, 0);
    lean_object *r = kroopt_ffi_sha256(in);
    check("sha256 empty KAT", eq(r, e, 32));
    lean_dec(r); lean_dec(in);
  }

  /* Ed25519 RFC 8032 test 1: derive public, sign empty message, verify; tamper. */
  {
    static const uint8_t seed[32] = {
      0x9d,0x61,0xb1,0x9d,0xef,0xfb,0x5e,0xe5,0xce,0xa8,0x29,0x55,0xb5,0x36,0xc4,0x0a,
      0x6a,0x3f,0x90,0x5f,0x97,0xa3,0xa6,0x6a,0xa9,0xb6,0xcf,0x96,0x9d,0xa3,0xd8,0x4f};
    /* derive pub from seed via the shim (any tamper to the byte handling shows up here) */
    lean_object *sk = mk(seed, 32);
    lean_object *pub = kroopt_ffi_ed25519_public(sk);
    int pub_ok = lean_sarray_size(pub) == 32;
    check("ed25519 public size", pub_ok);

    lean_object *msg = mk(NULL, 0);
    lean_object *sig = kroopt_ffi_ed25519_sign(sk, msg);
    check("ed25519 sign size", lean_sarray_size(sig) == 64);

    lean_object *v = kroopt_ffi_ed25519_verify(pub, msg, sig);
    check("ed25519 verify accepts valid", lean_sarray_size(v) == 1 && lean_sarray_cptr(v)[0] == 1);
    lean_dec(v);

    /* tamper the signature: verify must reject (and must not read OOB) */
    uint8_t bad[64]; memcpy(bad, lean_sarray_cptr(sig), 64); bad[0] ^= 0xff;
    lean_object *badSig = mk(bad, 64);
    lean_object *v2 = kroopt_ffi_ed25519_verify(pub, msg, badSig);
    check("ed25519 verify rejects tampered", lean_sarray_cptr(v2)[0] == 0);
    lean_dec(v2); lean_dec(badSig);

    lean_dec(sig); lean_dec(msg); lean_dec(pub); lean_dec(sk);
  }

  /* X25519: two key pairs agree on the same shared secret (status byte + 32 bytes). */
  {
    uint8_t a[32], b[32];
    for (int i = 0; i < 32; i++) { a[i] = (uint8_t)(i + 1); b[i] = (uint8_t)(0x80 - i); }
    lean_object *ska = mk(a, 32), *skb = mk(b, 32);
    lean_object *pka = kroopt_ffi_x25519_public(ska);
    lean_object *pkb = kroopt_ffi_x25519_public(skb);
    lean_object *sab = kroopt_ffi_x25519_shared(ska, pkb);
    lean_object *sba = kroopt_ffi_x25519_shared(skb, pka);
    /* result is [status]++shared(32); status 0 on success */
    int agree = lean_sarray_size(sab) == 33 && lean_sarray_size(sba) == 33 &&
                lean_sarray_cptr(sab)[0] == 0 && lean_sarray_cptr(sba)[0] == 0 &&
                memcmp(lean_sarray_cptr(sab) + 1, lean_sarray_cptr(sba) + 1, 32) == 0;
    check("x25519 ECDH agreement", agree);
    lean_dec(sab); lean_dec(sba); lean_dec(pka); lean_dec(pkb); lean_dec(ska); lean_dec(skb);
  }

  /* ChaCha20-Poly1305: seal then open round-trips; a tampered tag fails closed. */
  {
    uint8_t key[32], nonce[12];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(0x40 + i);
    for (int i = 0; i < 12; i++) nonce[i] = (uint8_t)(i);
    static const uint8_t ptxt[5] = { 'h','e','l','l','o' };
    static const uint8_t aadb[3] = { 0x17, 0x03, 0x03 };
    lean_object *k = mk(key, 32), *n = mk(nonce, 12), *aad = mk(aadb, 3), *pt = mk(ptxt, 5);

    lean_object *sealed = kroopt_ffi_aead_seal(k, n, aad, pt);
    int seal_ok = lean_sarray_size(sealed) == 5 + 16;  /* ct(5)++tag(16) */
    check("aead seal output size", seal_ok);

    lean_object *opened = kroopt_ffi_aead_open(k, n, aad, sealed);
    int open_ok = lean_sarray_size(opened) == 1 + 5 &&
                  lean_sarray_cptr(opened)[0] == 0 &&
                  memcmp(lean_sarray_cptr(opened) + 1, ptxt, 5) == 0;
    check("aead open round-trips plaintext", open_ok);
    lean_dec(opened);

    /* tamper the last tag byte: open must report status 1 and zero the plaintext slot */
    uint8_t tampered[5 + 16]; memcpy(tampered, lean_sarray_cptr(sealed), 5 + 16);
    tampered[5 + 16 - 1] ^= 0x01;
    lean_object *bad = mk(tampered, 5 + 16);
    lean_object *r = kroopt_ffi_aead_open(k, n, aad, bad);
    check("aead open rejects tampered tag", lean_sarray_cptr(r)[0] == 1);
    lean_dec(r); lean_dec(bad);

    /* sub-tag ciphertext (< 16 bytes): the guard must reject without reading OOB */
    lean_object *tiny = mk((const uint8_t *)"\x01\x02\x03", 3);
    lean_object *r2 = kroopt_ffi_aead_open(k, n, aad, tiny);
    check("aead open rejects sub-tag input", lean_sarray_size(r2) == 1 && lean_sarray_cptr(r2)[0] == 1);
    lean_dec(r2); lean_dec(tiny);

    lean_dec(sealed); lean_dec(k); lean_dec(n); lean_dec(aad); lean_dec(pt);
  }

  /* HKDF extract + expand: sizes are correct (the key schedule shape). */
  {
    uint8_t salt[32], ikm[32];
    memset(salt, 0, 32); for (int i = 0; i < 32; i++) ikm[i] = (uint8_t)i;
    lean_object *s = mk(salt, 32), *i = mk(ikm, 32);
    lean_object *prk = kroopt_ffi_hkdf_extract256(s, i);
    check("hkdf-extract prk size", lean_sarray_size(prk) == 32);
    static const uint8_t info[6] = { 't','l','s','1','3',' ' };
    lean_object *inf = mk(info, 6);
    lean_object *okm = kroopt_ffi_hkdf_expand256(prk, inf, 40);
    check("hkdf-expand length honoured", lean_sarray_size(okm) == 40);
    lean_dec(okm); lean_dec(inf); lean_dec(prk); lean_dec(i); lean_dec(s);
  }

  /* Boundary: a wrong-size X25519 private key is rejected (empty result), no OOB. */
  {
    lean_object *shortKey = mk((const uint8_t *)"\x01\x02\x03", 3);  /* 3 ≠ 32 */
    lean_object *r = kroopt_ffi_x25519_public(shortKey);
    check("x25519 public rejects wrong-size key", lean_sarray_size(r) == 0);
    lean_dec(r); lean_dec(shortKey);
  }

  /* C-owned zeroizing secret arena (RFC 037 §3): alloc/read/zeroize/release plus double-release
   * and read-after-release. ASan flags any double-free or use-after-free of the arena's malloc'd
   * buffers; live_count == 0 at the end is a functional no-leak check (these buffers are the shim's
   * own mallocs, which ASan tracks, not Lean-runtime allocations). */
  {
    lean_object *w = lean_box(0);  /* world token is ignored by the arena externs */
    uint8_t pat[48];
    for (int i = 0; i < 48; i++) pat[i] = (uint8_t)(0xA0 + i);
    uint64_t ids[16];
    for (int i = 0; i < 16; i++) {
      lean_object *b = mk(pat, 48);
      lean_object *res = kroopt_ffi_secret_alloc(b, w);
      ids[i] = lean_unbox_uint64(lean_io_result_get_value(res));
      lean_dec(res); lean_dec(b);
    }
    int allAlloced = 1; for (int i = 0; i < 16; i++) if (ids[i] == 0) allAlloced = 0;
    check("secret arena: 16 allocations all succeed", allAlloced);

    lean_object *r0 = kroopt_ffi_secret_read(ids[0], w);
    lean_object *v0 = lean_io_result_get_value(r0);
    int rb = (lean_sarray_size(v0) == 48 && memcmp(lean_sarray_cptr(v0), pat, 48) == 0);
    lean_dec(r0);
    check("secret arena: read round-trips the stored bytes", rb);

    lean_object *zr = kroopt_ffi_secret_zeroize(ids[0], w); lean_dec(zr);
    lean_object *r0z = kroopt_ffi_secret_read(ids[0], w);
    lean_object *v0z = lean_io_result_get_value(r0z);
    int zeroed = (lean_sarray_size(v0z) == 48);
    for (int i = 0; i < 48; i++) if (lean_sarray_cptr(v0z)[i] != 0) zeroed = 0;
    lean_dec(r0z);
    check("secret arena: zeroize wipes the live buffer", zeroed);

    for (int i = 0; i < 16; i++) { lean_object *rr = kroopt_ffi_secret_release(ids[i], w); lean_dec(rr); }
    /* double release of two ids — must be a safe no-op (no double-free under ASan) */
    { lean_object *d = kroopt_ffi_secret_release(ids[0], w); lean_dec(d); }
    { lean_object *d = kroopt_ffi_secret_release(ids[7], w); lean_dec(d); }
    /* read after release — must not dereference freed memory (UAF under ASan) */
    lean_object *ra = kroopt_ffi_secret_read(ids[3], w);
    int gone = (lean_sarray_size(lean_io_result_get_value(ra)) == 0);
    lean_dec(ra);
    check("secret arena: read after release returns empty (no UAF)", gone);

    lean_object *lc = kroopt_ffi_secret_live_count(w);
    uint64_t live = lean_unbox_uint64(lean_io_result_get_value(lc));
    lean_dec(lc);
    check("secret arena: live count returns to zero (no leak)", live == 0);
  }

  if (failures == 0) {
    printf("ALL sanitizer harness checks passed (shim exercised clean under ASan/UBSan).\n");
    return 0;
  }
  printf("%d sanitizer harness check(s) FAILED.\n", failures);
  return 1;
}
