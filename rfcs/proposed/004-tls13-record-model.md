# RFC 004 — TLS 1.3 Record Model

**Project.** kroopt  
**Status.** Proposed  
**Type.** Implementation RFC  
**Target milestone.** M2  
**Depends on.** RFC 003  
**Touches.** `Kroopt/Core/Record.lean`; record parse/frame in `Kroopt/Parse/`  
**Canonical source.** kroopt fixed requirements and external design.  

---

## 1. Summary

This RFC defines kroopt's TLS 1.3 record model. TLS 1.3 records are deceptively subtle: encrypted records have an outer content type of `application_data`, while the true inner content type is inside the authenticated plaintext. Sequence numbers, epochs, nonces, size bounds, partial reads, and authentication failures must all be modeled carefully.

## 2. Goals

- Model TLSPlaintext, TLSInnerPlaintext, and TLSCiphertext separately.
- Enforce record size limits and AEAD expansion limits.
- Define reassembly of partial transport bytes.
- Define seal/open orchestration without implementing AEAD in Lean.
- Ensure no plaintext is emitted until authentication succeeds.

## 3. Core data types

```lean
inductive ContentType where
  | changeCipherSpec
  | alert
  | handshake
  | applicationData

structure TLSPlaintext where
  ctype : ContentType
  legacyRecordVersion : UInt16
  fragment : BoundedBytes maxPlaintextFragment

structure TLSInnerPlaintext where
  content : ByteArray
  ctype   : ContentType
  paddingZeros : Nat
  paddingProof : AllZeros paddingZeros

structure TLSCiphertext where
  opaqueType : ContentType -- must be applicationData for TLS 1.3 protected records
  legacyRecordVersion : UInt16
  encryptedRecord : BoundedBytes maxCiphertextFragment
```

Use type-level or constructor-level validation so invalid encrypted outer types cannot be treated as protected TLS 1.3 records.

## 4. Epochs and directions

```lean
inductive Direction where | read | write
inductive Epoch where | initial | handshake | application

structure EpochKeys where
  direction : Direction
  epoch : Epoch
  suite : CipherSuite
  key : SecretKeyHandle
  ivBase : SecretKeyHandle
  seq : SeqNo
```

Sequence numbers are per direction and per epoch. They reset only on epoch installation. Overflow is fatal.

## 5. Inbound record processing

Inbound processing occurs in stages:

1. Append transport bytes to the bounded inbound record buffer.
2. Parse a complete record header only if enough bytes are present.
3. If the full record is not available, keep buffering within configured limits.
4. For plaintext handshake records before encryption, parse as TLSPlaintext.
5. For protected records, call AEAD open with the read epoch key, derived nonce, and additional data.
6. Validate inner plaintext padding and inner content type.
7. Emit handshake bytes, alert, or application plaintext according to state.

At no point may partially decrypted or unauthenticated bytes be exposed.

## 6. Outbound record processing

Outbound processing occurs in stages:

1. Accept a bounded plaintext fragment from the core.
2. Construct TLSInnerPlaintext with inner content type and padding policy.
3. Derive nonce from write epoch and sequence number.
4. Call AEAD seal through `CryptoOp`.
5. Frame TLSCiphertext with outer `application_data`.
6. Increment sequence only after the seal operation is accepted by the state model.
7. Queue ciphertext as bounded pending output for the interpreter.

For handshake messages before ServerHello encryption is installed, send plaintext handshake records as required by TLS 1.3 state.

## 7. Additional data and nonce derivation

AEAD additional data is the TLSCiphertext header for the protected record. The nonce is:

```text
nonce = iv_base XOR left_pad_zeros(seq, iv_length)
```

The model must not assume a fixed IV length except through the selected suite metadata. The proof must show injectivity of nonce derivation for strictly increasing sequence numbers within a fixed epoch and fixed IV base.

## 8. CCS compatibility

TLS 1.3 permits certain compatibility `change_cipher_spec` records. kroopt should accept-and-ignore only the narrow allowed form and only in states where it is harmless. All other CCS records are rejected with a deterministic alert.

The allowed behavior must be represented explicitly in the core, not hidden in the interpreter.

## 9. Buffering policy

- Inbound reassembly buffer is bounded.
- Pending outbound ciphertext queue is bounded by bytes and record count.
- kroopt buffers at most one record's plaintext for application delivery.
- `TlsConn.send` may accept plaintext into kroopt ownership only if enough pending-output budget remains.
- `wouldBlock` means zero plaintext consumed.

## 10. Proof obligations

- A complete record is processed only after its declared length is fully buffered.
- Decrypt/auth failure emits no plaintext and transitions to failed/alert behavior.
- Protected application plaintext is emitted only from connected state.
- Sequence increment occurs exactly once per accepted record operation.
- Sequence overflow produces fatal behavior before nonce derivation for a wrapped value.
- Record size bounds are preserved by parse and frame operations.

## 11. Internal design notes

Separate pure record functions from core transition functions:

```lean
def parseRecordHeader : ByteArray -> Except ParseError ValidRecordHeader
def tryTakeRecord : BoundedBuffer -> Except ParseError (Option (TLSRecordBytes × BoundedBuffer))
def buildInner : ContentType -> ByteArray -> Except TlsError TLSInnerPlaintext
def openRecordRequest : EpochKeys -> TLSCiphertext -> Except TlsError CryptoOp
def sealRecordRequest : EpochKeys -> TLSInnerPlaintext -> Except TlsError CryptoOp
def handleOpenResult : State -> OperationId -> OpenResult -> Except TlsError (State × List OutputAction)
```

The core requests crypto; it does not call crypto.

## 12. Security considerations

- Record-layer authentication failure is fatal.
- Oversize records are fatal and must not allocate oversize buffers first.
- Padding validation must be done after AEAD open and before plaintext emission.
- Inner content type must be validated; unknown or illegal inner types are rejected.
- Sequence numbers must be modeled as bounded values with explicit overflow checks.

## 13. Tests

- Record header parse tests.
- Fragment reassembly tests over all split points.
- AEAD fake-open success/failure tests.
- Oversize record tests.
- Sequence overflow tests.
- CCS accept/reject tests.
- Tests proving no plaintext action occurs on failed open.

## 14. Acceptance criteria

- Record data types represent TLS 1.3 outer/inner distinction.
- Record processing is driven by core actions.
- Size, sequence, and epoch constraints are expressed in types or constructors.
- Required record proof skeletons and tests are present.
