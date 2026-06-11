# Secret arena and the TLS 1.3 key schedule (M13)

This is the provider-arena refactor: the change that lets **real key material
flow** through kroopt's crypto seam, and the real TLS 1.3 key schedule built on
the native HACL\* primitives and validated against the RFC 8448 trace.

## Why the seam had to become stateful

Before M13, `CryptoProvider.submit` was pure and stateless:

```
submit : OperationId → CryptoOp → Except CryptoError CryptoResult
```

ECDHE and HKDF return *opaque handles* (`SecretKeyHandle`), and AEAD operations
carry no key — by design, so secret bytes never become a printable Lean value
and the safety proofs hold for any provider. The fake exploited this: its AEAD is
the identity function and it never touches real key material.

Real TLS cannot. The key schedule threads real bytes:

```
ECDHE shared → HKDF-Extract → Derive-Secret → traffic secrets → traffic keys → AEAD
```

A pure, handle-returning `submit` cannot resolve a handle back to its bytes,
because that needs state it cannot carry between calls. So M13 introduces a
**secret arena** and threads it through the seam:

```
submit : SecretArena → OperationId → CryptoOp → Except CryptoError (SecretArena × CryptoResult)
```

`Kroopt.Crypto.SecretArena` is a bounded, generation-tagged store mapping handle
ids to secret bytes. Handles carry the arena generation, so a handle from a prior
generation is rejected after `bumpGeneration` (the same stale-reference
discipline the core proves for crypto *results*). The arena is a pure value
threaded explicitly through the interpreter's `RuntimeState`, not a hidden
`IORef`, so the seam stays deterministic. **Handle opacity is preserved** — the
verified core still sees only `SecretKeyHandle`s, so its 78 theorems are
untouched. The fake provider now allocates real handles from the arena, so the
existing handshake tests exercise arena allocation end-to-end.

## The real key schedule, validated against RFC 8448

`Kroopt.Crypto.KeySchedule` implements the RFC 8446 §7.1 schedule on the HACL\*
primitives: `HKDF-Expand-Label`, `Derive-Secret`, the early/handshake/master
secret chain, the handshake and application traffic secrets, and the traffic
key/IV and Finished-key expansions (SHA-256 suite).

`Tests.KeySchedule` (`kroopt-keyschedule-test`, 20 checks) validates the **entire
chain against the RFC 8448 §3 "Simple 1-RTT Handshake" trace** — every published
intermediate value matches: the empty-transcript hash, the Early Secret, the
X25519 ECDH from both sides, `Derive-Secret(.,"derived",.)`, the Handshake
Secret, the client/server handshake traffic secrets, the Master Secret, the
client/server application traffic secrets, the traffic keys and IVs, and the
Finished key. This is authoritative evidence that the schedule is a correct
TLS 1.3 schedule, not merely self-consistent.

## Real keys through the arena into the AEAD

`Kroopt.Crypto.Real` closes the loop: it installs a derived traffic key and IV
into the arena under handles, then seals and opens a record by looking the key up
**by handle** and deriving the per-record nonce (RFC 8446 §5.3). The test derives
a real ChaCha20-Poly1305 key from the RFC 8448 server handshake secret, installs
it, and round-trips a record — and confirms a tampered record fails to open. Real
key material flows from derivation, through the arena, into authenticated record
protection.

## The honest boundary: still not driven by the core

This milestone delivers the stateful seam and a correct, real crypto engine. It
is **not** yet wired into the verified core's handshake, because the core's
current `CryptoOp`s are too abstract to drive a real schedule: `hkdfExtract`
carries no salt/IKM, `hkdfExpandLabel` no label or input-secret handle, and
`aeadSeal`/`aeadOpen` no key reference (only record metadata). Driving the real
provider from `Kroopt.Core.step` is the next milestone and requires:

* enriching the `CryptoOp`/`CryptoResult` shapes with the key-schedule inputs
  (labels, input-secret handles, epoch-keyed key installation);
* re-proving operation-id correlation and the no-emit/no-accept discipline over
  the richer shapes (the proofs constrain shapes, so they must move with them);
* keeping handle opacity intact so the core still never sees key bytes.

Until then, the schedule and arena are exercised directly by the test harness,
which is exactly what proves they are ready to be wired in.
