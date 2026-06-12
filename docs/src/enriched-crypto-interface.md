# Enriched crypto interface and the real provider (M14)

M13 made the crypto seam *stateful* and validated a real key schedule as
standalone functions. M14 makes the seam *expressive enough to drive that
schedule*, and ships a real `CryptoProvider` that performs a full TLS 1.3
handshake's cryptography through the actual `submit` interface — the one the
verified core calls.

## Why the operation shapes had to grow

The core asks for cryptography by emitting `CryptoOp` values; the provider answers
with `CryptoResult`. After M13 those shapes were too abstract to express a real
key schedule:

* `hkdfExtract` named only a hash algorithm — no salt, no input keying material;
* `hkdfExpandLabel` named only a length — no input secret, no label, no context;
* AEAD and ECDHE could not say *which* secret to use or return the server's
  public share.

A real schedule (RFC 8446 §7.1) is a chain where each step consumes the secret
the previous step produced. To express that without ever putting key bytes in the
core, the operations now name their secret inputs by **opaque handle**:

* `hkdfExtract alg (salt : Option SecretKeyHandle) (ikm : Option SecretKeyHandle)`
  — both absent for the Early Secret, salt-only for the Master Secret, both
  present for the Handshake Secret.
* `hkdfExpandLabel alg (secret : SecretKeyHandle) label context len` — expresses
  Derive-Secret and the traffic-secret expansions.
* `installTrafficKeys suite dir epoch (secret : SecretKeyHandle)` (new) — asks the
  provider to expand a traffic secret into the record key and IV and install them
  for a (direction, epoch).
* ECDHE now returns `ecdheComplete (serverShare : ByteArray) (shared :
  SecretKeyHandle)`: the server's public key for the wire, plus a handle to the
  shared secret.

The AEAD operations are deliberately **unchanged** — they remain keyed by record
metadata, and the provider resolves the installed key for that (direction, epoch)
internally. That choice keeps the safety-critical AEAD shapes, the only crypto
constructors the proofs destructure, exactly as they were.

## Proofs unmoved

Because the proofs reason about an operation's *kind* and the *discipline* of
which actions may be emitted in which state — never the secret payloads — and
because the AEAD shapes did not change, all 78 machine-checked theorems hold over
the enriched interface unchanged. The axiom audit is identical. Handle opacity is
preserved: the core still sees only `SecretKeyHandle`s.

## The real provider

`Kroopt.Crypto.mkRealProvider` answers every enriched operation with genuine
cryptography on the native HACL\* primitives, threading the secret arena:

* ECDHE via X25519 (server public + shared secret);
* `hkdfExtract` / `hkdfExpandLabel` resolving their input handles from the arena
  and storing the output under a new handle;
* `installTrafficKeys` deriving the record key/IV and recording them (plus the
  base secret, for the Finished key) in the arena's installed-key index;
* `aeadSeal` / `aeadOpen` resolving the installed key by record metadata and
  using ChaCha20-Poly1305 with the per-record nonce;
* `signCertificateVerify` producing a real Ed25519 signature;
* `verifyFinished` computing the Finished MAC from the handshake base secret.

`Tests.RealProvider` (`kroopt-realprovider-test`, 17 checks) drives this provider
through the **exact RFC 8448 §3 operation sequence via `submit`** — the same calls
the core will emit — and reads every produced secret back out of the arena to
confirm it matches the published trace, checks the install path against the RFC's
AES traffic key/IV, round-trips a real record, verifies a real signature, and
accepts/rejects Finished MACs.

## The honest boundary (still ahead)

The seam is now expressive and a real provider satisfies it, but two things remain
before a real interoperating handshake:

1. **The verified core does not yet *emit* this sequence.** Its handshake still
   emits the simpler op set from earlier milestones. Making `Kroopt.Core.step`
   orchestrate the full schedule — emitting the extract/expand/install chain and
   threading the handles through its negotiation state — is the next step. The
   interface and proofs are now ready for it; the AEAD shapes being fixed means
   that work should not disturb the safety proofs.

2. **Production entropy and certificate provisioning.** A pure `submit` cannot
   draw randomness or hold the server's long-term key, so the real provider takes
   the server's ephemeral X25519 key and Ed25519 certificate key from an injected
   `RealCryptoConfig` (fixed to the RFC 8448 values in the test for
   determinism). Seeding the ephemeral from the OS CSPRNG and loading the cert key
   through the interpreter at connection start is a small, scoped follow-up.

After those, a real TLS 1.3 handshake on `TLS_CHACHA20_POLY1305_SHA256` against
OpenSSL/curl is in reach — but it builds real wire messages and a real transcript,
which is its own milestone.
