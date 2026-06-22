# RFC 012 — Server Certificate/Key Presentation

**Project.** kroopt  
**Status.** Implemented (0.24.0-dev)  
**Type.** Implementation RFC  
**Target milestone.** M8  
**Depends on.** RFC 003, RFC 008, RFC 011  
**Touches.** `Kroopt/Cert/Present.lean`  
**Canonical source.** kroopt fixed requirements and external design.  

---

## 1. Summary

This RFC defines server certificate and private-key handling for kroopt's initial server role. kroopt presents configured certificate chains and proves private-key possession via CertificateVerify. It does not perform peer certificate path validation in server mode.

## 2. Goals

- Load configured certificate chains as opaque DER.
- Parse minimal leaf metadata needed for signature-scheme compatibility and config lint.
- Store private keys behind secret handles.
- Verify certificate/private-key compatibility at config load.
- Produce Certificate and CertificateVerify handshake messages.

## 3. Non-goals

- ACME or certificate issuance.
- System trust store management.
- Peer certificate path validation.
- Revocation checking.
- General-purpose X.509 library.
- mTLS client certificate verification.

## 4. Data model

```lean
structure CertificateChainHandle where
  id : UInt64
  generation : ConfigGeneration
  chainLen : Nat
  leafMeta : LeafCertificateMeta

structure LeafCertificateMeta where
  publicKeyKind : PublicKeyKind
  subjectNamesPreview : RedactedNames
  notBefore : Option Time
  notAfter : Option Time
  signatureSchemesCompatible : List SignatureScheme

structure PrivateKeyHandle where
  secret : SecretKeyHandle
  keyKind : PrivateKeyKind
  generation : ConfigGeneration
```

The DER chain remains opaque for handshake presentation. Only minimal metadata is parsed for config lint and signature selection.

## 5. Config lint

Config validation checks:

- leaf public key kind is compatible with private key kind;
- private key can sign with at least one configured signature scheme;
- certificate chain is non-empty;
- DER items are within configured size limits;
- optional warnings for expiry and name mismatch against configured route names.

Expiry/name warnings are lint, not peer path validation.

## 6. Handshake behavior

During handshake:

1. SNI selects endpoint configuration.
2. Signature scheme is selected from client signature_algorithms and endpoint/provider capabilities.
3. Certificate message sends configured chain DER.
4. CertificateVerify input is constructed from transcript snapshot and TLS context string.
5. Provider signs with `PrivateKeyHandle`.
6. The framed CertificateVerify bytes enter the transcript.

## 7. Public API sketch

```lean
def loadCertificateChain : List ByteArray -> IO (Except CertConfigError CertificateChainHandle)
def loadPrivateKey : ByteArray -> PrivateKeyFormat -> IO (Except CertConfigError PrivateKeyHandle)
def validateEndpointCertKey : CertificateChainHandle -> PrivateKeyHandle -> List SignatureScheme -> IO (Except ConfigError EndpointCertInfo)
def releaseCertificateChain : CertificateChainHandle -> IO Unit
def releasePrivateKey : PrivateKeyHandle -> IO Unit
```

Loading private keys must avoid printable secret-bearing values.

## 8. Internal design

Minimal DER reader from RFC 003 may parse:

- SubjectPublicKeyInfo algorithm and key type;
- optional validity timestamps for lint;
- optional SAN/CN preview for lint.

The parser must be size/depth bounded and must not evolve into full path validation without a future RFC.

## 9. Security considerations

- Private keys are secret handles, not Lean byte arrays after load.
- DER parse errors must not dump full certificate bytes.
- Certificate selection is based on validated SNI, not raw input.
- Signature scheme selection must reject downgrade to unsupported/unsafe schemes.
- CertificateVerify failures due to internal signing errors abort the handshake without leaking key details.

## 10. Tests

- Load valid Ed25519 and ECDSA P-256 configurations.
- Reject incompatible cert/private-key pairs.
- Reject empty chain.
- Reject oversized DER.
- Select compatible signature scheme from client list.
- CertificateVerify signing path uses the expected transcript snapshot.
- Release private key handle zeroizes provider storage.

## 11. Acceptance criteria

- Server certificate presentation works with synthetic and real crypto providers.
- Private keys are never exposed through printable Lean structures.
- Config lint is documented as lint, not validation.
- Peer path validation remains explicitly deferred.

## Amendment (RFC 010 socket arc) — configured DER now reaches the wire

The original increment modelled the cert/key as opaque handles and serialized an *empty* Certificate
(self-consistent in-model, since the in-model client computed its transcript over the same empty message).
The real-socket arc requires a real client to accept the flight, so the public chain DER now flows end to
end, transcript-consistently: `EndpointConfig.der` → `NegotiationState.selectedCertDer` → a single
`serializeServerCertificate` used for *both* the core's transcript contribution and the bytes the
interpreter writes (the `writeCertificate` action carries the DER, not the handle). The DER is public, so
it lives only on `Inhabited`-only structures and disturbs no `Repr`/`DecidableEq` derivation; the private
key stays behind its secret handle. Empty DER reproduces the prior empty `certificate_list`, so all in-model
proofs and tests are unchanged. `Tests.SocketDriver` drives the handshake with the fixture Ed25519 leaf cert
and reaches `connected` over the real-cert transcript. Multi-cert chains and client/mTLS validation remain
out of scope here.
