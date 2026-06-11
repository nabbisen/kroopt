# RFC 005 — Nonce, Sequence, Epoch, and Key-Separation Proofs

**Project.** kroopt  
**Status.** Proposed  
**Type.** Implementation RFC  
**Target milestone.** M3  
**Depends on.** RFC 004  
**Touches.** `Kroopt/Core/Record.lean`, `KeySchedule.lean`; `Kroopt/Proofs/{Nonces,KeySeparation}.lean`  
**Canonical source.** kroopt fixed requirements and external design.  

---

## 1. Summary

This RFC defines the proof and implementation structure that prevents AEAD nonce reuse and key confusion. These are among the highest-severity TLS implementation risks. Even if HACL\*/EverCrypt is correct, kroopt can destroy security by passing the wrong nonce, reusing a sequence number, using a read key for write, or confusing handshake and application epochs.

## 2. Goals

- Define sequence-number types and overflow behavior.
- Define epoch installation and reset rules.
- Prove per-key nonce uniqueness.
- Prove sequence monotonicity.
- Prove directional and epoch key separation.
- Ensure crypto operations carry sufficient metadata for runtime checks.

## 3. Data model

```lean
structure SeqNo where
  value : UInt64

def SeqNo.next : SeqNo -> Except SeqOverflow SeqNo

structure KeyEpochId where
  conn : ConnId
  direction : Direction
  epoch : Epoch
  generation : UInt64

structure TrafficKey where
  epochId : KeyEpochId
  suite : CipherSuite
  keyHandle : SecretKeyHandle
  ivHandle : SecretKeyHandle
  seq : SeqNo
```

The key epoch id is not secret. It is used to correlate proofs, logs, test diagnostics, and crypto operation metadata without exposing secret bytes.

## 4. Epoch installation rules

- `initial` epoch has no AEAD traffic keys.
- `handshake` read/write keys are installed after ServerHello/key schedule steps.
- `application` read/write keys are installed after Finished derivations.
- Installing a new epoch resets that direction's sequence to zero.
- Old epoch keys must be retired or made inaccessible when state no longer permits their use.
- KeyUpdate is not implemented; therefore no application rekey occurs in the initial release line.

## 5. Nonce derivation model

```lean
def paddedSeq (suite : CipherSuite) (seq : SeqNo) : ByteArray
def nonceBytes (ivBase : PublicIvModel) (suite : CipherSuite) (seq : SeqNo) : ByteArray :=
  xorBytes ivBase (paddedSeq suite seq)
```

The proof model may represent `ivBase` abstractly rather than exposing secret-handle content. The uniqueness theorem is conditional on a fixed epoch and fixed IV base value.

## 6. Core crypto operation metadata

Every seal/open operation includes:

```lean
structure RecordCryptoMeta where
  opId : OperationId
  conn : ConnId
  direction : Direction
  epoch : Epoch
  keyEpochId : KeyEpochId
  seq : SeqNo
  suite : CipherSuite
  contentRole : RecordContentRole
```

The interpreter must pass this metadata through to debug/test hooks and must reject mismatched provider results.

## 7. Proof obligations

### 7.1 Sequence monotonicity

For every successful record open/seal transition, the corresponding sequence number increases by exactly one. For failure before record acceptance, it does not increase unless the TLS specification requires otherwise for a specific operation; any such exception must be documented.

### 7.2 No silent wrap

If `SeqNo.next` would overflow, the core emits fatal behavior and does not emit a crypto operation using a wrapped sequence value.

### 7.3 Nonce uniqueness

For fixed `(conn, direction, epoch, generation, ivBase)`, two accepted record crypto operations with different positions use different sequence numbers and therefore different nonces.

### 7.4 Directional key separation

A write operation uses only write keys, and a read operation uses only read keys. No transition can produce a `callCrypto` action with a key direction inconsistent with the operation direction.

### 7.5 Epoch separation

Handshake records use handshake epoch keys, application records use application epoch keys, and unencrypted initial handshake data uses no AEAD key. The core must not accept application plaintext under handshake keys.

## 8. Internal proof strategy

Recommended theorem family:

```lean
theorem step_preserves_seq_monotonicity : ...
theorem successful_seal_increments_write_seq : ...
theorem successful_open_increments_read_seq : ...
theorem no_crypto_on_seq_overflow : ...
theorem nonce_unique_within_epoch : ...
theorem callCrypto_direction_matches_state : ...
theorem callCrypto_epoch_matches_content_role : ...
```

Use small transition-specific lemmas and combine them through `step` dispatcher lemmas. Avoid one enormous global theorem that becomes brittle.

## 9. Security considerations

Nonce reuse with AEAD is catastrophic. This RFC treats sequence/nonce logic as a first-class proof target, not a tested convention. Runtime assertions should still exist because FFI/interpreter bugs are possible, but tests are not a substitute for the core theorem.

## 10. Tests

- Unit tests for sequence increment and overflow.
- Fake-provider tests verifying metadata on each crypto operation.
- Negative tests that inject stale crypto results with wrong sequence, direction, epoch, or operation id.
- Trace tests over a full synthetic handshake and multiple application records.

## 11. Acceptance criteria

- Sequence and epoch types exist and are used by record crypto operations.
- The core cannot emit seal/open operations without direction and epoch metadata.
- Proofs cover monotonicity, no silent wrap, nonce uniqueness, and key separation.
- Runtime tests reject stale or mismatched crypto results.
