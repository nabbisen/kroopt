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
#include <stdlib.h>
#include <sys/random.h>

#include "Hacl_Hash_SHA2.h"
#include "Hacl_Curve25519_51.h"
#include "Hacl_Chacha20Poly1305_32.h"
#include "Hacl_HKDF.h"
#include "Hacl_HMAC.h"
#include "Hacl_Ed25519.h"
#include "Hacl_P256.h"
#include "Hacl_RSAPSS.h"

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

/* HMAC-SHA384 (48-byte tag) — direct HACL primitive. */
LEAN_EXPORT lean_object *kroopt_ffi_hmac384(b_lean_obj_arg key, b_lean_obj_arg msg) {
  if (!len_u32_ok(key) || !len_u32_ok(msg)) return mk_ba(0);
  lean_object *r = mk_ba(48);
  Hacl_HMAC_compute_sha2_384(lean_sarray_cptr(r), ba_ptr(key), (uint32_t)ba_len(key),
                             ba_ptr(msg), (uint32_t)ba_len(msg));
  return r;
}

/* HKDF-Extract-SHA384 (RFC 5869): PRK = HMAC-Hash(salt, IKM). HACL ships HKDF for SHA-256/512 but
 * not SHA-384, so kroopt builds the SHA-384 HKDF on the verified HMAC-SHA384 primitive exactly as
 * HACL builds its own (extract is a single HMAC). 48-byte output. */
LEAN_EXPORT lean_object *kroopt_ffi_hkdf_extract384(b_lean_obj_arg salt, b_lean_obj_arg ikm) {
  if (!len_u32_ok(salt) || !len_u32_ok(ikm)) return mk_ba(0);
  lean_object *r = mk_ba(48);
  Hacl_HMAC_compute_sha2_384(lean_sarray_cptr(r), ba_ptr(salt), (uint32_t)ba_len(salt),
                             ba_ptr(ikm), (uint32_t)ba_len(ikm));
  return r;
}

/* HKDF-Expand-SHA384 (RFC 5869): OKM = T(1) | T(2) | ... truncated to len, where
 * T(i) = HMAC(PRK, T(i-1) | info | i). The iterated-HMAC construction HACL uses internally for its
 * 256/512 HKDF, here over HMAC-SHA384 (HashLen = 48). Fails closed on len > 255*48 (RFC 5869 bound).*/
LEAN_EXPORT lean_object *kroopt_ffi_hkdf_expand384(b_lean_obj_arg prk, b_lean_obj_arg info,
                                                   uint32_t len) {
  if (!len_u32_ok(prk) || !len_u32_ok(info)) return mk_ba(0);
  const uint32_t HL = 48;
  if (len > 255U * HL) return mk_ba(0);
  lean_object *r = mk_ba(len);
  uint8_t *okm = lean_sarray_cptr(r);
  uint8_t *prkp = ba_ptr(prk); uint32_t prklen = (uint32_t)ba_len(prk);
  uint8_t *infop = ba_ptr(info); size_t infolen = ba_len(info);
  uint8_t *text = (uint8_t *)malloc((size_t)HL + infolen + 1);
  if (!text) return mk_ba(0);
  uint8_t Ti[48];
  uint32_t Ti_len = 0, done = 0; uint8_t i = 0;
  while (done < len) {
    i++;
    uint32_t off = 0;
    memcpy(text + off, Ti, Ti_len); off += Ti_len;
    memcpy(text + off, infop, infolen); off += (uint32_t)infolen;
    text[off++] = i;
    Hacl_HMAC_compute_sha2_384(Ti, prkp, prklen, text, off);
    Ti_len = HL;
    uint32_t take = (len - done < HL) ? (len - done) : HL;
    memcpy(okm + done, Ti, take);
    done += take;
  }
  free(text);
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


/* ── RSA-PSS over SHA-256 — RFC 8446 rsa_pss_rsae_sha256 (v0.4 server auth) ──
   sign: loads the private key from (n‖e‖d) byte arrays, signs `msg` (already the CertificateVerify
   signing input) with the given salt, returns `status(1) || sgnt(modBytes)`. TLS 1.3 requires
   saltLen = hashLen = 32. Bit lengths are byte-aligned (size*8); HACL tolerates leading-zero key
   limbs. Fails closed on empty key material or HACL rejection. modBytes = n.size. */
LEAN_EXPORT lean_object *kroopt_ffi_rsapss_sign(b_lean_obj_arg nb, b_lean_obj_arg eb,
                                                b_lean_obj_arg db, b_lean_obj_arg salt,
                                                b_lean_obj_arg msg) {
  size_t modBytes = ba_len(nb);
  lean_object *r = mk_ba(1 + modBytes);
  uint8_t *q = lean_sarray_cptr(r);
  memset(q, 0, 1 + modBytes);
  if (modBytes == 0 || ba_len(eb) == 0 || ba_len(db) == 0 || ba_len(msg) > UINT32_MAX) {
    q[0] = 1; return r;
  }
  uint32_t modBits = (uint32_t)(modBytes * 8);
  uint32_t eBits   = (uint32_t)(ba_len(eb) * 8);
  uint32_t dBits   = (uint32_t)(ba_len(db) * 8);
  uint64_t *skey = Hacl_RSAPSS_new_rsapss_load_skey(modBits, eBits, dBits,
                                                    ba_ptr(nb), ba_ptr(eb), ba_ptr(db));
  if (skey == NULL) { q[0] = 1; return r; }
  bool ok = Hacl_RSAPSS_rsapss_sign(Spec_Hash_Definitions_SHA2_256, modBits, eBits, dBits, skey,
                                    (uint32_t)ba_len(salt), ba_ptr(salt),
                                    (uint32_t)ba_len(msg), ba_ptr(msg), q + 1);
  free(skey);
  q[0] = ok ? 0 : 1;
  if (!ok) memset(q + 1, 0, modBytes);
  return r;
}

/* RSA-PSS verify against the public key (n‖e) with the given salt length. Returns 1-byte 0/1. */
LEAN_EXPORT lean_object *kroopt_ffi_rsapss_verify(b_lean_obj_arg nb, b_lean_obj_arg eb,
                                                  uint32_t saltLen, b_lean_obj_arg sgnt,
                                                  b_lean_obj_arg msg) {
  lean_object *r = mk_ba(1);
  lean_sarray_cptr(r)[0] = 0;
  if (ba_len(nb) == 0 || ba_len(eb) == 0 || ba_len(msg) > UINT32_MAX) return r;
  uint32_t modBits = (uint32_t)(ba_len(nb) * 8);
  uint32_t eBits   = (uint32_t)(ba_len(eb) * 8);
  uint64_t *pkey = Hacl_RSAPSS_new_rsapss_load_pkey(modBits, eBits, ba_ptr(nb), ba_ptr(eb));
  if (pkey == NULL) return r;
  bool ok = Hacl_RSAPSS_rsapss_verify(Spec_Hash_Definitions_SHA2_256, modBits, eBits, pkey,
                                      saltLen, (uint32_t)ba_len(sgnt), ba_ptr(sgnt),
                                      (uint32_t)ba_len(msg), ba_ptr(msg));
  free(pkey);
  lean_sarray_cptr(r)[0] = ok ? 1 : 0;
  return r;
}

/* ===== C-owned zeroizing secret arena (RFC 037 §3, requirements §13) =====
 * A process-global registry of malloc'd secret buffers addressed by a monotonic, never-reused
 * u64 id. kroopt runs a single event loop with no kroopt-spawned threads, so the registry needs
 * no locking. `release` (and a contents-only `zeroize`) overwrite the buffer through a volatile
 * pointer before (release) freeing it, so the store is not dead-store-eliminated and a durable
 * secret's home is wiped rather than left for the GC. Best-effort by nature: the C standard cannot
 * guarantee that no spilled copy survives elsewhere, but this buffer is the canonical home and is
 * never the Lean heap. Monotonic ids are never reused, so a freed id reads as absent — no ABA and
 * no use-after-free of a recycled id. */

#ifndef KROOPT_SECRET_SLOTS
#define KROOPT_SECRET_SLOTS 4096
#endif

typedef struct { uint64_t id; uint8_t *ptr; size_t len; } kroopt_secret_slot;
static kroopt_secret_slot kroopt_secret_table[KROOPT_SECRET_SLOTS];
static uint64_t kroopt_secret_next_id = 1; /* 0 reserved for "none"/failure */

/* Secure wipe that the optimizer may not elide (volatile store). */
static void kroopt_wipe(uint8_t *p, size_t n) {
  volatile uint8_t *vp = (volatile uint8_t *)p;
  while (n--) *vp++ = 0;
}

static kroopt_secret_slot *kroopt_secret_find(uint64_t id) {
  if (id == 0) return NULL;
  for (int i = 0; i < KROOPT_SECRET_SLOTS; i++)
    if (kroopt_secret_table[i].id == id && kroopt_secret_table[i].ptr)
      return &kroopt_secret_table[i];
  return NULL;
}

/* alloc: copy `bytes` into a fresh C-owned buffer; return its id (0 on OOM / table full). */
LEAN_EXPORT lean_object *kroopt_ffi_secret_alloc(b_lean_obj_arg bytes, lean_object *w) {
  (void)w;
  size_t n = ba_len(bytes);
  uint64_t id = 0;
  int slot = -1;
  for (int i = 0; i < KROOPT_SECRET_SLOTS; i++) if (!kroopt_secret_table[i].ptr) { slot = i; break; }
  if (slot >= 0) {
    uint8_t *buf = (uint8_t *)malloc(n ? n : 1);
    if (buf) {
      if (n) memcpy(buf, ba_ptr(bytes), n);
      id = kroopt_secret_next_id++;
      kroopt_secret_table[slot].id = id;
      kroopt_secret_table[slot].ptr = buf;
      kroopt_secret_table[slot].len = n;
    }
  }
  return lean_io_result_mk_ok(lean_box_uint64(id));
}

/* read: a Lean ByteArray copy of the buffer, or empty if the id is absent (released/stale/0). */
LEAN_EXPORT lean_object *kroopt_ffi_secret_read(uint64_t id, lean_object *w) {
  (void)w;
  kroopt_secret_slot *s = kroopt_secret_find(id);
  lean_object *r;
  if (s) { r = mk_ba(s->len); if (s->len) memcpy(lean_sarray_cptr(r), s->ptr, s->len); }
  else r = mk_ba(0);
  return lean_io_result_mk_ok(r);
}

/* zeroize: overwrite the buffer contents in place, keeping the slot allocated. */
LEAN_EXPORT lean_object *kroopt_ffi_secret_zeroize(uint64_t id, lean_object *w) {
  (void)w;
  kroopt_secret_slot *s = kroopt_secret_find(id);
  if (s) kroopt_wipe(s->ptr, s->len);
  return lean_io_result_mk_ok(lean_box(0));
}

/* release: wipe then free; clears the slot. Idempotent — an absent id is a no-op, so a double
 * release is safe. */
LEAN_EXPORT lean_object *kroopt_ffi_secret_release(uint64_t id, lean_object *w) {
  (void)w;
  kroopt_secret_slot *s = kroopt_secret_find(id);
  if (s) { kroopt_wipe(s->ptr, s->len); free(s->ptr); s->ptr = NULL; s->len = 0; s->id = 0; }
  return lean_io_result_mk_ok(lean_box(0));
}

/* live count — for leak assertions in tests (number of un-released slots). */
LEAN_EXPORT lean_object *kroopt_ffi_secret_live_count(lean_object *w) {
  (void)w;
  uint64_t live = 0;
  for (int i = 0; i < KROOPT_SECRET_SLOTS; i++) if (kroopt_secret_table[i].ptr) live++;
  return lean_io_result_mk_ok(lean_box_uint64(live));
}

/* Ed25519 sign with a private key resident in the C-owned secret arena (RFC 037 §3, design §9.10:
 * "config-lifetime private keys are owned by the secret arena and referenced by kroopt"). The key
 * bytes never enter the Lean heap — they are read from the arena slot here, used for the HACL sign,
 * and the 64-byte signature is returned. Fails closed (empty result) if the handle is absent (e.g.
 * released) or the stored key is not 32 bytes, so a wiped key can no longer produce a signature. */
LEAN_EXPORT lean_object *kroopt_ffi_ed25519_sign_h(uint64_t keyId, b_lean_obj_arg msg) {
  kroopt_secret_slot *s = kroopt_secret_find(keyId);
  if (!s || s->len != 32 || !len_u32_ok(msg)) return mk_ba(0);
  lean_object *r = mk_ba(64);
  Hacl_Ed25519_sign(lean_sarray_cptr(r), s->ptr, (uint32_t)ba_len(msg), ba_ptr(msg));
  return r;
}
