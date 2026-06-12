# RFC 007 — Transcript Model Using Exact Wire Bytes

**Project.** kroopt  
**Status.** Implemented (0.24.0-dev)  
**Type.** Implementation RFC  
**Target milestone.** M4  
**Depends on.** RFC 006  
**Touches.** `Kroopt/Core/Transcript.lean`; transcript binding in `Kroopt/Parse/`  
**Canonical source.** kroopt fixed requirements and external design.  

---

## 1. Summary

This RFC defines transcript handling. TLS 1.3 security depends on hashing the exact ordered handshake bytes. kroopt must never parse a handshake message, reconstruct it later, and assume the reconstructed bytes are transcript-equivalent. Parsed values must be bound to the exact bytes consumed or emitted.

## 2. Goals

- Maintain transcript state over exact wire bytes.
- Bind parser outputs to consumed byte slices.
- Bind server-generated structures to emitted frame bytes.
- Provide transcript snapshot ids for crypto operation correlation.
- Support Finished and CertificateVerify input construction.

## 3. Data model

```lean
structure TranscriptState where
  hashAlg : HashAlgorithm
  digestState : TranscriptDigestHandle
  events : List TranscriptEventMeta -- non-secret debug metadata only
  snapshotCounter : UInt64

structure TranscriptSnapshot where
  id : UInt64
  hashAlg : HashAlgorithm
  digest : TranscriptDigestHandle
  eventCount : Nat

structure TranscriptEventMeta where
  kind : HandshakeMessageType
  direction : Direction
  length : Nat
  redactedSummary : String
```

The digest handle may be provider-backed. Event metadata is for diagnostics and proofs, not for recomputing the transcript.

## 4. Transcript input rules

- ClientHello transcript bytes are exactly the parsed ClientHello handshake bytes.
- ServerHello transcript bytes are exactly the framed bytes emitted by kroopt.
- EncryptedExtensions, Certificate, CertificateVerify, and Finished are transcript-bound from their framed handshake message bytes before record encryption.
- Finished verification uses the transcript state up to, but not including, the Finished message being verified.
- CertificateVerify signs the specified TLS 1.3 context string plus transcript hash according to the signature scheme.

## 5. API sketch

```lean
def transcriptAppendParsed : TranscriptState -> Parsed HandshakeMessage -> Except TlsError TranscriptState
def transcriptAppendFramed : TranscriptState -> HandshakeMessageType -> ByteArray -> Except TlsError TranscriptState
def transcriptSnapshot : TranscriptState -> TranscriptSnapshot
def makeCertificateVerifyInput : TranscriptSnapshot -> SignatureContext -> ByteArray
def makeFinishedInput : TranscriptSnapshot -> FinishedContext -> ByteArray
```

## 6. Exact-byte binding

Parser output includes `wireBytes`. Frame functions return `ByteArray`. These are the only bytes that may enter transcript append functions. A structured message value alone is insufficient.

This rule prevents a class of bugs where parser normalization, extension ordering, padding, or DER encoding differences cause the transcript used for cryptographic verification to differ from the peer's transcript.

## 7. Crypto operation correlation

Crypto operations that depend on transcript state include the snapshot id:

```lean
structure TranscriptBoundCrypto where
  snapshot : TranscriptSnapshot
  purpose : TranscriptPurpose
  op : CryptoOp
```

A crypto result must match the pending operation and snapshot id. A result produced for an older transcript snapshot is stale and rejected.

## 8. Proof obligations

- Transcript event order follows legal handshake transitions.
- Finished verification uses the transcript snapshot before the peer Finished bytes are appended.
- CertificateVerify signing uses the transcript snapshot before CertificateVerify is appended.
- No transition can replace exact wire bytes with reserialized bytes for transcript input.
- Transcript hash algorithm matches the selected cipher suite.

## 9. Internal design notes

### 9.1 Hash in proof vs provider

Two approaches are acceptable:

1. Model transcript as an abstract sequence of exact bytes and treat hash computation as provider action.
2. Maintain a provider-backed hash handle while proving event ordering and exact-byte binding.

The first is proof-friendlier. The second is runtime-efficient. The RFC permits a hybrid: proof model stores an abstract event sequence, runtime stores a digest handle, and correspondence tests verify append calls.

### 9.2 Redaction

Transcript metadata may include message kind and length but must not log raw attacker-controlled bytes or secret-derived values.

## 10. Tests

- Golden transcript trace for a synthetic handshake.
- Tests that altered server frame bytes alter transcript snapshot id/digest.
- Bad Finished MAC test.
- CertificateVerify input construction test.
- Negative test: reconstructed ClientHello bytes must not be accepted as transcript substitute in production code.

## 11. Acceptance criteria

- Every parsed handshake message used by the core has exact wire bytes.
- Every generated handshake message enters transcript from framed bytes.
- Transcript snapshots are used in crypto operation metadata.
- Proofs cover transcript event order and binding discipline.
