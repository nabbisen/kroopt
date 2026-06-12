import Kroopt.Crypto.Provider
import Kroopt.Crypto.Arena
import Kroopt.Crypto.KeySchedule
import Kroopt.Crypto.Real
import Kroopt.Crypto.Hacl
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
  deriving Inhabited

namespace RealProvider

/-- Resolve the bytes a handle names, or a typed `invalidHandle` failure. -/
private def need (a : SecretArena) (h : SecretKeyHandle) : Except CryptoError ByteArray :=
  match a.get h with
  | some b => .ok b
  | none => .error .invalidHandle

/-- 32 zero bytes (HKDF zero salt / IKM). -/
private def z32 : ByteArray := KeySchedule.zeros 32

/-- The real per-operation answer. Threads the arena: secret-producing ops store
their output and return a handle; key installation derives and stores the record
key/IV and records the index; AEAD resolves the installed key by record metadata.
SHA-256 / X25519 / ChaCha20-Poly1305 / Ed25519 only (the vendored HACL subset). -/
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
  | .hkdfExtract _ salt ikm => do
      let saltBytes ← match salt with | some h => need a h | none => .ok z32
      let ikmBytes  ← match ikm  with | some h => need a h | none => .ok z32
      let (h, a') ← a.store (Hacl.hkdfExtract256 saltBytes ikmBytes)
      .ok (a', .hkdfSecret h)
  | .hkdfExpandLabel _ secret label context len => do
      let secretBytes ← need a secret
      let (h, a') ← a.store (KeySchedule.expandLabel secretBytes label context len)
      .ok (a', .hkdfSecret h)
  | .installTrafficKeys suite dir epoch secret => do
      let secretBytes ← need a secret
      let key := KeySchedule.trafficKey suite secretBytes
      let iv  := KeySchedule.trafficIv secretBytes
      let (kh, a1) ← a.store key
      let (ih, a2) ← a1.store iv
      let (bh, a3) ← a2.store secretBytes
      let a4 := (a3.recordInstalled dir epoch kh.id ih.id).recordBaseSecret dir epoch bh.id
      .ok (a4, .keysInstalled)
  | .aeadSeal meta _aad plaintext =>
      match a.lookupInstalled meta.direction meta.epoch with
      | none => .error .invalidHandle
      | some (kId, ivId) =>
        match a.getById kId, a.getById ivId with
        | some key, some iv =>
            .ok (a, .aeadSealed (Hacl.chachaPolySeal key (Real.nonce iv meta.seq.value) _aad plaintext))
        | _, _ => .error .invalidHandle
  | .aeadOpen meta _aad ciphertext =>
      match a.lookupInstalled meta.direction meta.epoch with
      | none => .error .invalidHandle
      | some (kId, ivId) =>
        match a.getById kId, a.getById ivId with
        | some key, some iv =>
            match Hacl.chachaPolyOpen key (Real.nonce iv meta.seq.value) _aad ciphertext with
            | some pt => .ok (a, .aeadOpened pt)
            | none => .ok (a, .verifyFailed)
        | _, _ => .error .invalidHandle
  | .signCertificateVerify scheme input =>
      match scheme with
      | .ed25519 => .ok (a, .signature (Hacl.ed25519Sign cfg.certPrivate input))
      | _ => .error .unsupportedOperation
  | .computeServerFinished _ transcriptHash =>
      -- The server Finished verify_data = HMAC(server_finished_key, H) over the transcript
      -- hash through CertificateVerify, using the *write* (server) handshake-traffic secret
      -- (RFC 8446 §4.4.4). Mirror of `verifyFinished`'s read-secret path.
      match a.lookupBaseSecret .write .handshake with
      | none => .error .invalidHandle
      | some sid =>
        match a.getById sid with
        | none => .error .invalidHandle
        | some baseSecret =>
            let finKey := KeySchedule.finishedKey baseSecret
            .ok (a, .finishedMac (Hacl.hmac256 finKey transcriptHash))
  | .verifyFinished _ transcriptHash received =>
      -- A TLS 1.3 server verifies the client's Finished with the *read* (client)
      -- handshake-traffic secret; finished_key = HKDF-Expand-Label(secret,
      -- "finished", "", H.len) and Finished = HMAC(finished_key, H) (RFC 8446 §4.4.4).
      match a.lookupBaseSecret .read .handshake with
      | none => .error .invalidHandle
      | some sid =>
        match a.getById sid with
        | none => .error .invalidHandle
        | some baseSecret =>
            let finKey := KeySchedule.finishedKey baseSecret
            let expected := Hacl.hmac256 finKey transcriptHash
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
