# RFC 008 — Crypto Provider Capability Matrix and FFI Contract

**Project.** kroopt  
**Status.** Proposed  
**Type.** Implementation RFC  
**Target milestone.** M6  
**Depends on.** RFC 002, RFC 005  
**Touches.** `Kroopt/Crypto/Provider.lean`; `Kroopt/Core/Action.lean` (`CryptoOp`/`CryptoResult`)  
**Canonical source.** kroopt fixed requirements and external design.  

---

## 1. Summary

This RFC defines the crypto provider interface and FFI contract. kroopt borrows primitive cryptography from HACL\*/EverCrypt, but the correctness of the FFI call boundary, operation selection, secret-handle lifecycle, and error mapping belongs to kroopt.

The verified core does not call FFI. It emits `CryptoOp` actions. The interpreter passes those operations to a provider implementation and returns correlated `CryptoResult` events.

## 2. Goals

- Define a provider-neutral crypto operation interface.
- Define provider capability negotiation.
- Define operation id and result correlation.
- Define secret-handle ownership and zeroization contract.
- Define error mapping and test requirements.

## 3. Provider capabilities

```lean
structure CryptoCapabilities where
  aeadSuites : List AeadSuite
  hashAlgorithms : List HashAlgorithm
  hkdfAlgorithms : List HashAlgorithm
  groups : List NamedGroup
  signatureSchemes : List SignatureScheme
  randomSource : RandomSourceKind
  supportsSecretHandles : Bool
```

The production provider must cover at least the required initial cipher/group/signature set chosen by the implementation plan. Capability mismatch is a configuration error, not a runtime fallback opportunity.

## 4. Crypto operations

```lean
inductive CryptoOp where
  | randomBytes (len : BoundedNat maxRandomRequest)
  | ecdheX25519 (peerShare : PublicKeyBytes)
  | hkdfExtract (alg : HashAlgorithm) (salt : SecretRef) (ikm : SecretRef)
  | hkdfExpandLabel (alg : HashAlgorithm) (secret : SecretRef) (label : TlsLabel) (context : ByteArray) (len : Nat)
  | aeadSeal (meta : RecordCryptoMeta) (aad : ByteArray) (plaintext : ByteArray)
  | aeadOpen (meta : RecordCryptoMeta) (aad : ByteArray) (ciphertext : ByteArray)
  | signCertificateVerify (scheme : SignatureScheme) (key : PrivateKeyHandle) (input : ByteArray)
  | verifyFinished (alg : HashAlgorithm) (secret : SecretRef) (transcriptHash : ByteArray) (received : ByteArray)
```

Exact constructors may be refactored, but crypto operations must be typed by purpose. Avoid a generic `call(name, bytes)` API.

## 5. Crypto results

```lean
inductive CryptoResult where
  | randomBytes (b : ByteArray)
  | sharedSecret (h : SecretKeyHandle)
  | hkdfSecret (h : SecretKeyHandle)
  | aeadSealed (ciphertext : ByteArray)
  | aeadOpened (plaintext : ByteArray)
  | signature (bytes : ByteArray)
  | verified
  | failed (e : CryptoError)
```

The result is accepted only if it matches the pending operation's expected kind, connection id, operation id, epoch metadata, and transcript snapshot where applicable.

## 6. Secret-handle contract

```lean
structure SecretKeyHandle where
  id : UInt64
  kind : SecretKind
  owner : SecretOwner
  generation : UInt64
```

Rules:

- Long-lived secrets are C-owned where feasible.
- Handles are not printable, not serializable, not structurally comparable in public APIs.
- Releasing a handle zeroizes backing memory when supported.
- Duplicate release is safe and reported as an internal diagnostic.
- Use-after-release is rejected by the provider.
- Secret handles are scoped to connection/config generation where possible.

## 7. Error mapping

Provider errors are separated into:

- attacker-caused TLS failures, such as AEAD open failure or bad Finished;
- configuration failures, such as unsupported private key type;
- internal provider failures, such as allocation failure or invalid handle;
- entropy failures.

Only attacker-caused TLS failures map to peer-facing alerts. Internal and configuration failures become typed kroopt errors and abort the connection without leaking details.

## 8. Internal design

### 8.1 Provider interface

```lean
class CryptoProvider where
  capabilities : IO CryptoCapabilities
  submit : OperationId -> CryptoOp -> IO (Except CryptoError CryptoResult)
  releaseSecret : SecretKeyHandle -> IO Unit
```

For the fake provider, `submit` may be deterministic and pure behind an IO wrapper. For HACL\*/EverCrypt, `submit` calls the C shim.

### 8.2 Synchronous vs asynchronous provider

The initial provider may be synchronous, but the core still models calls as actions/results. This preserves the possibility of asynchronous provider execution later and keeps proof/runtime correspondence clean.

## 9. Security considerations

- Do not expose raw private keys or traffic secrets to Lean logging or `Repr`.
- Do not branch on secret bytes in Lean code.
- Do not accept provider results without operation id matching.
- Do not silently downgrade cipher suites based on provider absence.
- Do not treat random failure as recoverable handshake noise.

## 10. Tests

- Capability matrix tests.
- Unsupported capability rejection tests.
- Stale operation id result tests.
- Wrong result kind tests.
- Released secret handle tests.
- Fake provider deterministic handshake tests.

## 11. Acceptance criteria

- Provider-neutral `CryptoOp` and `CryptoResult` types exist.
- Operation/result correlation is implemented.
- Secret-handle lifecycle is documented and tested.
- Production HACL provider can be added without importing FFI into the core.
