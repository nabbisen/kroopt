/*
 * kroopt_hacl_shim.c — HACL*/EverCrypt binding for the kroopt.h contract
 * (RFC 009 §4).
 *
 * NOT YET BUILT. This file is intentionally a documented placeholder, not a
 * working implementation. The real shim links HACL*/EverCrypt (Project Everest)
 * for every primitive and is compiled into the Lake build only once HACL* is
 * vendored or pinned as a system dependency (RFC 009 §5; Requirements Open
 * Question 1: "HACL*/EverCrypt distribution/build integration").
 *
 * The mapping each function will use, and the discipline it must follow:
 *
 *   kroopt_random            -> EverCrypt_AutoConfig2 + a vetted CSPRNG; a hard
 *                               failure returns KROOPT_ERR_RANDOM_FAILED.
 *   kroopt_x25519_*          -> Hacl_Curve25519_51 (scalarmult / base).
 *   kroopt_hkdf_*            -> Hacl_HKDF (extract / expand) with TLS 1.3 labels
 *                               assembled by the caller, secrets kept in the arena.
 *   kroopt_aead_seal/open    -> EverCrypt_AEAD (AES-128/256-GCM, ChaCha20-Poly1305);
 *                               open returns KROOPT_ERR_AUTH_FAILED on tag mismatch,
 *                               distinct from KROOPT_ERR_INTERNAL so the TLS alert
 *                               stays deterministic (RFC 009 §8).
 *   kroopt_sign_cert_verify  -> Hacl_Ed25519 / EverCrypt_ECDSA (P-256) /
 *                               RSA-PSS as EverCrypt exposes it.
 *   kroopt_secret_*          -> a zeroizable secret arena with generation-tagged
 *                               handles; release zeroizes before free (RFC 009 §7).
 *
 * Build discipline when this lands (RFC 009 §5, §9):
 *   - strict warnings as errors for shim code;
 *   - ASan + UBSan CI builds run over the native tests;
 *   - known-answer tests for every primitive are release blockers (RFC 009 §6);
 *   - no retained Lean pointers; lengths checked before use; no logging in C.
 *
 * Until this is implemented, Kroopt.Crypto.fakeProvider satisfies the same
 * Kroopt.Crypto.CryptoProvider interface for the deterministic test suites, and
 * the operation-id correlation that makes provider results safe is already
 * proved in the verified core (stale_crypto_result_rejected).
 */
