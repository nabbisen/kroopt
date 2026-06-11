# RFC 006 — Handshake State Model without HelloRetryRequest

**Project.** kroopt  
**Status.** Proposed  
**Type.** Implementation RFC  
**Target milestone.** M4  
**Depends on.** RFC 003, RFC 004  
**Touches.** `Kroopt/Core/{State,Step}.lean`; `Kroopt/Proofs/StateMachine.lean`  
**Canonical source.** kroopt fixed requirements and external design.  

---

## 1. Summary

This RFC defines the TLS 1.3 server handshake state model for kroopt's initial release line. The model deliberately excludes HelloRetryRequest. Clients must provide an acceptable X25519 key_share in the initial ClientHello or the handshake fails cleanly.

This simplification is intentional. HRR changes transcript rules and adds significant proof and interop surface. kroopt should first prove and ship a strict, small, server-side TLS 1.3 path.

## 2. Goals

- Define the server handshake path from ClientHello to connected.
- Model legal states and transitions.
- Reject unsupported or unexpected messages deterministically.
- Integrate key schedule orchestration through crypto actions.
- Keep HTTP and ALPN policy outside the handshake core.

## 3. Non-goals

- HelloRetryRequest.
- 0-RTT early data.
- Session tickets or resumption.
- Client authentication.
- KeyUpdate.
- Post-handshake authentication.
- TLS 1.2 fallback.

## 4. State machine

```lean
inductive HandshakeState where
  | start
  | recvdClientHello
  | requestedEcdhe
  | derivedHandshakeSecrets
  | sentServerHello
  | sentEncryptedExtensions
  | sentCertificate
  | requestedCertificateVerifySignature
  | sentCertificateVerify
  | sentServerFinished
  | requestedClientFinishedVerify
  | recvdClientFinished
  | connected
  | closing
  | closed
  | failed (alert : AlertDescription)
```

The exact state names may be compressed later, but the implementation must not hide materially different phases in one broad state if doing so makes proofs weaker or logs ambiguous.

## 5. ClientHello handling

The ClientHello parser and policy checker must validate:

- TLS 1.3 in `supported_versions`;
- acceptable cipher suite;
- X25519 key_share present;
- supported_groups includes X25519 or is otherwise compatible with the key_share;
- signature_algorithms compatible with configured certificate/key material;
- SNI extension is valid if present;
- ALPN list is valid if present;
- duplicate extensions are rejected;
- unknown extensions are handled according to strict policy;
- no 0-RTT early_data accepted.

A missing acceptable key_share results in failure, not HRR.

## 6. Server flight

The core emits actions to produce:

1. ServerHello;
2. handshake secret derivation;
3. EncryptedExtensions;
4. Certificate;
5. CertificateVerify;
6. Finished;
7. application traffic secret derivation;
8. wait for client Finished.

The flight may be queued as multiple records, but sequencing is decided by the core.

## 7. Crypto operations

Handshake crypto operations include:

- ECDHE shared secret calculation;
- HKDF extract/expand stages;
- transcript hash operations or provider hash operations if not purely modeled;
- CertificateVerify signing;
- Finished MAC generation;
- client Finished MAC verification.

Each operation uses an operation id and expected result kind. The core must not continue a state transition using an uncorrelated result.

## 8. Negotiation outputs

After client Finished is verified, the core may emit:

```lean
OutputAction.reportHandshakeComplete conn {
  selectedCipherSuite : CipherSuite,
  selectedServerName : Option ServerName,
  selectedAlpn : Option ALPNProtocol,
  configGeneration : ConfigGeneration
}
```

jemmet consumes ALPN after this point. kroopt does not select an HTTP handler.

## 9. Proof obligations

- No transition skips required handshake messages.
- No application send/receive action is accepted before `connected`.
- Client Finished must be verified before `connected`.
- CertificateVerify is signed over the correct transcript context.
- Unsupported ClientHello parameters lead to failed/alert states.
- Terminal states are absorbing except for idempotent close/cleanup.

## 10. Internal design

Implement the handshake as small transition functions:

```lean
def onClientHello : State -> ValidClientHello -> Except TlsError (State × List OutputAction)
def onEcdheDone : State -> OperationId -> EcdheResult -> Except TlsError (State × List OutputAction)
def onServerFlightSigned : State -> OperationId -> SignatureResult -> Except TlsError (State × List OutputAction)
def onClientFinishedBytes : State -> ByteArray -> Except TlsError (State × List OutputAction)
def onClientFinishedVerified : State -> OperationId -> VerifyResult -> Except TlsError (State × List OutputAction)
```

The `step` dispatcher routes events to these functions.

## 11. Security considerations

- Reject early application_data before connected.
- Reject or ignore CCS only according to RFC 004 policy.
- Reject unsupported versions, groups, ciphers, or signatures before using them.
- Do not log raw ClientHello blobs.
- Do not select a certificate based on unvalidated SNI bytes.

## 12. Tests

- Successful synthetic handshake trace.
- Missing X25519 key_share failure.
- Unsupported version failure.
- Duplicate extension failure.
- Bad Finished failure.
- Out-of-order message failure.
- Application data before connected failure.
- Terminal after fatal alert behavior.

## 13. Acceptance criteria

- The handshake state model is implemented in the core.
- A full synthetic handshake succeeds with fake crypto.
- Negative handshake traces fail deterministically.
- Proofs cover legal transitions and no early plaintext.
