/*
 * kroopt.h — native crypto shim contract (RFC 009).
 *
 * This header is the *contract* between kroopt's Lean crypto provider and the
 * HACL*/EverCrypt-backed C shim. It is intentionally small and boring: one C
 * function per narrow primitive or secret-handle operation, explicit lengths,
 * status codes, and documented ownership (RFC 009 §3). No protocol decisions,
 * no algorithm negotiation, and no logging happen in C (RFC 009 §10).
 *
 * STATUS: the contract and signatures are fixed here; the *implementation*
 * (kroopt_hacl_shim.c) links HACL*/EverCrypt and is wired into the Lake build
 * once HACL* is vendored or pinned (RFC 009 §5, Requirements Open Question 1).
 * Until then the Lean side uses the deterministic fake provider
 * (Kroopt.Crypto.fakeProvider). The fake and the real shim satisfy the same
 * provider interface (Kroopt.Crypto.CryptoProvider), so swapping is local.
 *
 * MEMORY OWNERSHIP RULES (RFC 009 §3, §7):
 *   - The shim never retains a Lean-managed pointer past a call.
 *   - Every input length is passed explicitly and checked before use.
 *   - Output buffers are caller-provided with a checked capacity, OR the shim
 *     allocates and transfers ownership with a documented free path.
 *   - Durable secrets (private keys, traffic secrets, IV bases) live in a
 *     C-owned zeroizable secret arena and are referenced only by handle.
 *   - Handle generation is tracked so a stale/released handle is rejected.
 */
#ifndef KROOPT_H
#define KROOPT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t kroopt_secret_handle;

typedef enum {
  KROOPT_OK = 0,
  KROOPT_ERR_INVALID_ARG,   /* a length/pointer precondition was violated   */
  KROOPT_ERR_UNSUPPORTED,   /* configuration error: primitive not available */
  KROOPT_ERR_AUTH_FAILED,   /* attacker-caused: AEAD open / signature check */
  KROOPT_ERR_RANDOM_FAILED, /* entropy source failure (fatal, not alert)    */
  KROOPT_ERR_INTERNAL       /* allocation / invalid handle / internal fault */
} kroopt_status;

/* Randomness. Fills out[0..out_len). KROOPT_ERR_RANDOM_FAILED is fatal. */
kroopt_status kroopt_random(uint8_t *out, size_t out_len);

/* X25519: derive the ephemeral public key, and the shared secret as a handle. */
kroopt_status kroopt_x25519_public(const uint8_t priv[32], uint8_t out_pub[32]);
kroopt_status kroopt_x25519_shared(const uint8_t priv[32], const uint8_t peer[32],
                                   kroopt_secret_handle *out_shared);

/* HKDF (TLS 1.3 key schedule). Secrets in/out are handles, never raw bytes. */
kroopt_status kroopt_hkdf_extract(int hash_alg,
                                  kroopt_secret_handle salt,
                                  kroopt_secret_handle ikm,
                                  kroopt_secret_handle *out_prk);
kroopt_status kroopt_hkdf_expand_label(int hash_alg,
                                       kroopt_secret_handle secret,
                                       const uint8_t *label, size_t label_len,
                                       const uint8_t *context, size_t context_len,
                                       size_t out_len,
                                       kroopt_secret_handle *out_secret);

/* AEAD record protection. nonce is derived by the caller from (iv XOR seq). */
kroopt_status kroopt_aead_seal(int aead_alg, kroopt_secret_handle key,
                               const uint8_t nonce[12],
                               const uint8_t *aad, size_t aad_len,
                               const uint8_t *plaintext, size_t pt_len,
                               uint8_t *out_ciphertext, size_t out_cap,
                               size_t *out_len);
kroopt_status kroopt_aead_open(int aead_alg, kroopt_secret_handle key,
                               const uint8_t nonce[12],
                               const uint8_t *aad, size_t aad_len,
                               const uint8_t *ciphertext, size_t ct_len,
                               uint8_t *out_plaintext, size_t out_cap,
                               size_t *out_len); /* KROOPT_ERR_AUTH_FAILED on bad tag */

/* Server authentication: sign the CertificateVerify input with a config key. */
kroopt_status kroopt_sign_cert_verify(int sig_scheme, kroopt_secret_handle key,
                                      const uint8_t *input, size_t input_len,
                                      uint8_t *out_sig, size_t out_cap,
                                      size_t *out_len);

/* Secret-handle lifecycle. Release zeroizes; double-release is a safe no-op
 * reported only as an internal diagnostic (RFC 008 §6, RFC 009 §7). */
kroopt_status kroopt_secret_release(kroopt_secret_handle h);

#ifdef __cplusplus
}
#endif

#endif /* KROOPT_H */
