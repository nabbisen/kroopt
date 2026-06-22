import Kroopt.Crypto.Provider
import Kroopt.Crypto.Arena
import Kroopt.Crypto.KeySchedule
import Kroopt.Crypto.Real
import Kroopt.Crypto.Hacl
import Kroopt.Crypto.NativeSecret
import Kroopt.Core.Crypto
import Kroopt.Core.Record

/-!
# Kroopt.Crypto.RealProvider

A real `CryptoProvider` that answers the enriched `CryptoOp` interface with
genuine TLS 1.3 cryptography on the native HACL* primitives, threading the secret
arena. This is the provider the verified core will eventually drive: it performs
the real key schedule (RFC 8446 §7.1) operation by operation, derives and
installs real record keys, seals/opens real records, and produces/verifies real
signatures and Finished MACs — all while the core sees only opaque handles.

It is validated end-to-end against the RFC 8448 §3 trace in `Tests.RealProvider`,
driven through `submit` exactly as the core would drive it.

## The honest boundary (config-injected secrets)

A *pure* `submit` cannot draw entropy, and it does not hold the server's
long-term certificate key. Both are supplied by a `RealCryptoConfig` the provider
closes over:

* `ephemeralPrivate` — the server's X25519 ephemeral private key. In production
  the interpreter seeds this from the OS CSPRNG (`Hacl.randomBytes`, an `IO`
  action) at connection start and stores it in the arena; here it is injected so
  the schedule is deterministic and checkable against RFC 8448.
* `certPrivate` / `certPublic` — the server's Ed25519 certificate key pair, used
  for the CertificateVerify signature.

Wiring production entropy seeding and certificate provisioning through the
interpreter is a small, scoped follow-up; the cryptography itself is real here.
-/

namespace Kroopt.Crypto

open Kroopt (CryptoError)
open Kroopt.Core (CryptoOp CryptoResult OperationId SecretKeyHandle HashAlgorithm
  CipherSuite Direction Epoch SignatureScheme RecordCryptoMeta)

/-- Static secrets the pure provider cannot itself produce (see module doc). -/
structure RealCryptoConfig where
  ephemeralPrivate : ByteArray
  certPrivate      : ByteArray
  certPublic       : ByteArray
  /-- Handle into the C-owned zeroizing secret arena (`Kroopt.Crypto.NativeSecret`) for the Ed25519
  certificate private key. When non-zero the provider signs CertificateVerify *by handle*, so the
  key bytes stay in zeroizable C memory and never enter the Lean heap (`certPrivate` is then empty);
  `0` means no handle and the provider falls back to `certPrivate` bytes (the deterministic test
  path). Set by `provisionRealConfig` (RFC 037 §3, design §9.10). -/
  certKeyHandle    : Kroopt.Crypto.NativeSecret.SecretId := 0
  /-- Per-connection ECDSA signing nonce `k` (32 bytes), drawn fresh from the CSPRNG at the IO
  layer when the certificate key is ECDSA-P256. Unused for Ed25519 (deterministic). Must never be
  reused across signatures; the server signs CertificateVerify once per handshake. For RSA-PSS it
  doubles as the 32-byte PSS salt (also fresh per connection, saltLen = hashLen). -/
  signNonce        : ByteArray := ByteArray.empty
  /-- RSA private key material `(modulus n, public exponent e, private exponent d)` for an RSA
  certificate. Empty unless the configured leaf is RSA. -/
  rsaN             : ByteArray := ByteArray.empty
  rsaE             : ByteArray := ByteArray.empty
  rsaD             : ByteArray := ByteArray.empty
  /-- The ECDSA-P256 private scalar for an ECDSA certificate, kept separate from `certPrivate` (the
  Ed25519 seed) so a single config can hold an Ed25519 *and* an ECDSA *and* an RSA key at once and
  the provider dispatches on the negotiated scheme (multi-certificate / SNI serving). -/
  ecdsaPriv        : ByteArray := ByteArray.empty
  /-- Arena handles for the ECDSA-P256 scalar and the RSA private exponent `d`, mirroring
  `certKeyHandle` for Ed25519: when non-zero the provider signs by handle (key resident only in C),
  else it falls back to the `ecdsaPriv` / `rsaD` bytes. -/
  ecdsaKeyHandle   : Kroopt.Crypto.NativeSecret.SecretId := 0
  rsaKeyHandle     : Kroopt.Crypto.NativeSecret.SecretId := 0
  deriving Inhabited

namespace RealProvider

/-- Resolve the bytes a handle names, or a typed `invalidHandle` failure. -/
private def need (a : SecretArena) (h : SecretKeyHandle) : Except CryptoError ByteArray :=
  match a.get h with
  | some b => .ok b
  | none => .error .invalidHandle

/-- The real per-operation answer. Threads the arena: secret-producing ops store
their output and return a handle; key installation derives and stores the record
key/IV and records the index; AEAD resolves the installed key by record metadata.
The schedule is parameterized by each op's `HashAlgorithm` (SHA-256 or SHA-384) and the
AEAD by `meta.suite` / the installed suite; X25519 / Ed25519 / ECDSA-P256 / RSA-PSS signing. -/
def submit (cfg : RealCryptoConfig) (a : SecretArena) (_ : OperationId) :
    CryptoOp → Except CryptoError (SecretArena × CryptoResult)
  | .randomBytes _ =>
      -- The real provider draws no entropy in pure `submit`: it would be
      -- deterministic, and deterministic randomness must never enter the real
      -- provider (RFC 034 §4). Real entropy is drawn at the IO/interpreter layer
      -- via the fail-closed `Hacl.randomBytes`; a `randomBytes` op reaching the
      -- real provider is therefore a provider-internal error, not silent zeros.
      .error .providerInternal
  | .ecdheX25519 peerShare =>
      match Hacl.x25519Public cfg.ephemeralPrivate, Hacl.x25519Shared cfg.ephemeralPrivate peerShare with
      | serverShare, some shared => do
          let (h, a') ← a.store shared
          .ok (a', .ecdheComplete serverShare h)
      | _, none => .error .providerInternal
  | .ecdheP256 peerShare =>
      -- secp256r1 ECDHE (RFC 8446 §4.2.8). The ephemeral scalar is the same 32-byte secret
      -- drawn for x25519; a random value is a valid P-256 scalar with overwhelming probability,
      -- and HACL fails closed (empty public / `none` shared) on the negligible bad-scalar case.
      match Hacl.p256Public cfg.ephemeralPrivate, Hacl.p256Shared cfg.ephemeralPrivate peerShare with
      | serverShare, some shared => do
          let (h, a') ← a.store shared
          .ok (a', .ecdheComplete serverShare h)
      | serverShare, none =>
          -- A `none` *after* the server public derived fine isolates the fault to the peer
          -- point (off-curve / point at infinity) — a peer-controlled invalid key_share
          -- (RFC 039 §4.8 → `illegal_parameter`). An empty server public means the server
          -- ephemeral scalar itself failed — a genuine provider-internal fault.
          if serverShare.isEmpty then .error .providerInternal
          else .error .peerInvalidKeyShare
  | .hkdfExtract alg salt ikm => do
      let z := KeySchedule.zeros (KeySchedule.hashLen alg)
      let saltBytes ← match salt with | some h => need a h | none => .ok z
      let ikmBytes  ← match ikm  with | some h => need a h | none => .ok z
      let (h, a') ← a.store (KeySchedule.hkdfExtractH alg saltBytes ikmBytes)
      .ok (a', .hkdfSecret h)
  | .hkdfExpandLabel alg secret label context len => do
      let secretBytes ← need a secret
      let (h, a') ← a.store (KeySchedule.expandLabel secretBytes label context len alg)
      .ok (a', .hkdfSecret h)
  | .installTrafficKeys suite dir epoch secret => do
      let secretBytes ← need a secret
      let key := KeySchedule.trafficKey suite secretBytes
      let iv  := KeySchedule.trafficIv secretBytes suite.hashAlg
      let (kh, a1) ← a.store key
      let (ih, a2) ← a1.store iv
      let (bh, a3) ← a2.store secretBytes
      let a4 := ((a3.recordInstalled dir epoch kh.id ih.id).recordBaseSecret dir epoch bh.id).recordInstalledSuite dir epoch suite
      .ok (a4, .keysInstalled)
  | .aeadSeal meta _aad plaintext =>
      match a.lookupInstalled meta.direction meta.epoch with
      | none => .error .invalidHandle
      | some (kId, ivId) =>
        match a.getById kId, a.getById ivId with
        | some key, some iv =>
            .ok (a, .aeadSealed (Real.aeadSealBySuite meta.suite key (Real.nonce iv meta.seq.value) _aad plaintext))
        | _, _ => .error .invalidHandle
  | .aeadOpen meta _aad ciphertext =>
      match a.lookupInstalled meta.direction meta.epoch with
      | none => .error .invalidHandle
      | some (kId, ivId) =>
        match a.getById kId, a.getById ivId with
        | some key, some iv =>
            match Real.aeadOpenBySuite meta.suite key (Real.nonce iv meta.seq.value) _aad ciphertext with
            | some pt => .ok (a, .aeadOpened pt)
            | none => .ok (a, .verifyFailed)
        | _, _ => .error .invalidHandle
  | .signCertificateVerify scheme input =>
      match scheme with
      | .ed25519 =>
          -- Sign by arena handle when the key is C-resident (production), else by bytes (tests).
          let sig := if cfg.certKeyHandle != 0 then Hacl.ed25519SignH cfg.certKeyHandle input
                     else Hacl.ed25519Sign cfg.certPrivate input
          .ok (a, .signature sig)
      | .ecdsaSecp256r1Sha256 =>
          -- ECDSA P-256 / SHA-256 (RFC 8446 §4.4.3): hash the signing input with SHA-256 and
          -- sign with the cert key and the fresh per-connection nonce, returning the DER-encoded
          -- Ecdsa-Sig-Value for the wire. Sign by arena handle when the scalar is C-resident.
          let der := if cfg.ecdsaKeyHandle != 0
                     then Hacl.ecdsaP256SignDerH input cfg.ecdsaKeyHandle cfg.signNonce
                     else Hacl.ecdsaP256SignDer input cfg.ecdsaPriv cfg.signNonce
          match der with
          | some der => .ok (a, .signature der)
          | none     => .error .providerInternal
      | .rsaPssRsaeSha256 =>
          -- RSA-PSS / SHA-256 (RFC 8446 rsa_pss_rsae_sha256): sign the signing input with the RSA
          -- private key (n, e, d) and the fresh per-connection 32-byte salt; the raw RSA signature
          -- goes on the wire (no DER wrapper, unlike ECDSA).
          if cfg.rsaN.isEmpty then .error .unsupportedOperation
          else
            let sig := if cfg.rsaKeyHandle != 0
                       then Hacl.rsapssSignH cfg.rsaN cfg.rsaE cfg.rsaKeyHandle cfg.signNonce input
                       else Hacl.rsapssSign cfg.rsaN cfg.rsaE cfg.rsaD cfg.signNonce input
            match sig with
            | some sig => .ok (a, .signature sig)
            | none     => .error .providerInternal
  | .computeServerFinished alg transcriptHash =>
      -- The server Finished verify_data = HMAC(server_finished_key, H) over the transcript
      -- hash through CertificateVerify, using the *write* (server) handshake-traffic secret
      -- (RFC 8446 §4.4.4). Mirror of `verifyFinished`'s read-secret path.
      match a.lookupBaseSecret .write .handshake with
      | none => .error .invalidHandle
      | some sid =>
        match a.getById sid with
        | none => .error .invalidHandle
        | some baseSecret =>
            let finKey := KeySchedule.finishedKey baseSecret alg
            .ok (a, .finishedMac (KeySchedule.hmacH alg finKey transcriptHash))
  | .verifyFinished alg transcriptHash received =>
      -- A TLS 1.3 server verifies the client's Finished with the *read* (client)
      -- handshake-traffic secret; finished_key = HKDF-Expand-Label(secret,
      -- "finished", "", H.len) and Finished = HMAC(finished_key, H) (RFC 8446 §4.4.4).
      match a.lookupBaseSecret .read .handshake with
      | none => .error .invalidHandle
      | some sid =>
        match a.getById sid with
        | none => .error .invalidHandle
        | some baseSecret =>
            let finKey := KeySchedule.finishedKey baseSecret alg
            let expected := KeySchedule.hmacH alg finKey transcriptHash
            -- `received` is the client Finished handshake message; its verify_data is
            -- the body after the 4-octet handshake header (`0x14 || u24 length`).
            let verifyData :=
              if received.size == expected.size + 4 then received.extract 4 received.size
              else received
            if expected.toList == verifyData.toList then .ok (a, .verified)
            else .ok (a, .verifyFailed)

end RealProvider

/-- Build a real provider closing over the injected static secrets. Advertises
the suites the vendored HACL subset supports for record protection
(ChaCha20-Poly1305) and the SHA-256 schedule. -/
def mkRealProvider (cfg : RealCryptoConfig) : CryptoProvider where
  capabilities := realCapabilities
  submit := RealProvider.submit cfg

end Kroopt.Crypto
