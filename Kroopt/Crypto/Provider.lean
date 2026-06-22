import Kroopt.Core.CipherSuite
import Kroopt.Core.Crypto
import Kroopt.Crypto.Arena
import Kroopt.Error

/-!
# Kroopt.Crypto.Provider

The crypto-provider interface and capability model (RFC 008 §3, §8). This is the
**trusted boundary**, not the verified core: the verified core never calls a
provider — it emits `CryptoOp` actions, and the interpreter (M7) submits them to
a provider and feeds correlated `CryptoResult` events back (RFC 008 §1). The
operation-id correlation that makes that safe is proved in the core
(`Kroopt.Core.Proofs.stale_crypto_result_rejected`).

What lives here:

* `CryptoCapabilities` — what a provider can do, and `validateCapabilities`, the
  deterministic config-time check that the configured suites/groups/signature
  schemes/hashes are all supported (RFC 008 §3 — *capability mismatch is a
  configuration error, not a runtime fallback opportunity*);
* `CryptoProvider` — a synchronous provider abstraction (RFC 008 §8.2: the
  initial provider may be synchronous; the core still models calls as
  actions/results, so asynchronous execution stays possible later);
* `fakeProvider` — a deterministic, purpose-aware fake (RFC 008 §8.1, §10) used by
  the deterministic handshake tests. The real HACL\*/EverCrypt provider wraps the
  C shim (RFC 009) and is wired in once HACL\* is vendored (Open Question 1).
-/

namespace Kroopt.Crypto

open Kroopt (CryptoError)
open Kroopt.Core (CipherSuite NamedGroup SignatureScheme HashAlgorithm
  CryptoOp CryptoResult OperationId SecretKeyHandle)

/-- Where the provider's randomness comes from. A provider with no usable entropy
source is fatal at startup — there is no recovery (RFC 008 §9). -/
inductive RandomSourceKind where
  | osCsprng
  | fakeDeterministic
  | none
  deriving DecidableEq, Repr, Inhabited

/-- What a provider can do (RFC 008 §3). Capability negotiation is by inclusion:
the configured crypto must be a subset of this. -/
structure CryptoCapabilities where
  suites            : List CipherSuite
  hashAlgorithms    : List HashAlgorithm
  groups            : List NamedGroup
  signatureSchemes  : List SignatureScheme
  randomSource      : RandomSourceKind
  supportsSecretHandles : Bool
  deriving Repr, Inhabited

/-- The crypto a validated configuration requires the provider to support. -/
structure RequiredCrypto where
  suites            : List CipherSuite
  groups            : List NamedGroup
  signatureSchemes  : List SignatureScheme
  hashAlgorithms    : List HashAlgorithm
  deriving Repr, Inhabited

/-- A capability-negotiation failure (RFC 008 §3, §7 — a *configuration* failure,
never a runtime fallback). -/
inductive CapabilityError where
  | unsupportedSuite (s : CipherSuite)
  | unsupportedGroup (g : NamedGroup)
  | unsupportedSignatureScheme (s : SignatureScheme)
  | unsupportedHash (h : HashAlgorithm)
  | noRandomSource
  deriving DecidableEq, Repr, Inhabited

/-- Find the first list element failing a membership predicate, as a typed error. -/
private def firstMissing {α : Type} [DecidableEq α]
    (required supported : List α) (err : α → CapabilityError) :
    Except CapabilityError Unit :=
  match required.find? (fun x => !supported.contains x) with
  | some x => .error (err x)
  | none   => .ok ()

/-- **Capability validation (RFC 008 §3).** Deterministic, total, no IO: every
required suite, group, signature scheme, and hash must be supported, and a usable
random source must exist. The first missing item is reported. Capability mismatch
aborts config validation — kroopt never silently downgrades (RFC 008 §9). -/
def validateCapabilities (caps : CryptoCapabilities) (req : RequiredCrypto) :
    Except CapabilityError Unit := do
  if caps.randomSource = .none then throw .noRandomSource
  firstMissing req.suites caps.suites .unsupportedSuite
  firstMissing req.groups caps.groups .unsupportedGroup
  firstMissing req.signatureSchemes caps.signatureSchemes .unsupportedSignatureScheme
  firstMissing req.hashAlgorithms caps.hashAlgorithms .unsupportedHash

/-- A synchronous crypto provider (RFC 008 §8.1, §8.2). `submit` answers a
`CryptoOp` deterministically (for the fake) or by calling the C shim (for the
real provider). It threads the `SecretArena` (RFC 008 §6): operations producing
secret material (ECDHE, HKDF) allocate a handle in the arena and return it, so
later operations can read the bytes back — something a pure, stateless `submit`
could not do. The operation id is echoed by the interpreter and matched against
the outstanding op in the core; `submit` itself performs no protocol logic. -/
structure CryptoProvider where
  capabilities : CryptoCapabilities
  submit       : SecretArena → OperationId → CryptoOp →
                   Except CryptoError (SecretArena × CryptoResult)

/-! ## The deterministic fake provider (RFC 008 §8.1, §10) -/

/-- Capabilities of the fake provider: the required initial TLS 1.3 set, with a
deterministic (non-entropy) random source so tests are reproducible. -/
def fakeCapabilities : CryptoCapabilities :=
  { suites := [.aes128GcmSha256, .aes256GcmSha384, .chacha20Poly1305Sha256]
    hashAlgorithms := [.sha256, .sha384]
    groups := [.x25519, .secp256r1]
    signatureSchemes := [.ed25519, .ecdsaSecp256r1Sha256, .rsaPssRsaeSha256]
    randomSource := .fakeDeterministic
    supportsSecretHandles := true }

/-- The **real** provider's honest capability profile (RFC 034 §2): exactly what
the vendored HACL\* / EverCrypt backend can serve **end-to-end**. As of 0.68.0-dev the interpreter
seal path is suite-aware, so this now includes `TLS_AES_128_GCM_SHA256` (bound + KAT'd via the Vale
verified assembly in 0.66.0-dev; it reuses the SHA-256 schedule) alongside
`TLS_CHACHA20_POLY1305_SHA256`, with X25519, Ed25519, SHA-256, OS CSPRNG. `TLS_AES_256_GCM_SHA384`
is withheld until the SHA-384 key schedule lands; a config requiring it is rejected at validation
rather than negotiated and then failed at the record layer. -/
def realCapabilities : CryptoCapabilities :=
  { suites := [.aes128GcmSha256, .aes256GcmSha384, .chacha20Poly1305Sha256]
    hashAlgorithms := [.sha256, .sha384]
    groups := [.x25519]
    signatureSchemes := [.ed25519]
    randomSource := .osCsprng
    supportsSecretHandles := true }

/-- A deterministic, purpose-aware answer for each operation kind (RFC 008 §8.1).
Now threads the arena: ECDHE and HKDF allocate a real handle backed by a
placeholder secret (the fake never uses real key material — its AEAD is the
identity envelope), so the existing handshake tests exercise arena allocation
end-to-end. AEAD wraps/unwraps a test envelope; sign and verify are scripted.
This is the same shape the real provider must satisfy — not a stand-in for real
cryptography, only a faithful interface. -/
def fakeSubmit (a : SecretArena) (_ : OperationId) :
    CryptoOp → Except CryptoError (SecretArena × CryptoResult)
  | .randomBytes _ => .ok (a, .randomBytes (ByteArray.mk #[]))
  | .ecdheX25519 _ => do
      let (h, a') ← a.store (ByteArray.mk (Array.mkArray 32 0))
      .ok (a', .ecdheComplete (ByteArray.mk (Array.mkArray 32 0)) h)
  | .ecdheP256 _ => do
      let (h, a') ← a.store (ByteArray.mk (Array.mkArray 32 0))
      .ok (a', .ecdheComplete (ByteArray.mk (Array.mkArray 65 0)) h)
  | .hkdfExtract _ _ _ => do
      let (h, a') ← a.store (ByteArray.mk (Array.mkArray 32 0)); .ok (a', .hkdfSecret h)
  | .hkdfExpandLabel _ _ _ _ _ => do
      let (h, a') ← a.store (ByteArray.mk (Array.mkArray 32 0)); .ok (a', .hkdfSecret h)
  | .installTrafficKeys _ _ _ _ => .ok (a, .keysInstalled)
  | .aeadSeal _ _ pt => .ok (a, .aeadSealed pt)
  | .aeadOpen _ _ ct => .ok (a, .aeadOpened ct)
  | .signCertificateVerify _ _ => .ok (a, .signature (ByteArray.mk (Array.mkArray 64 0xCD)))
  | .verifyFinished _ _ _ => .ok (a, .verified)
  | .computeServerFinished _ _ => .ok (a, .finishedMac (ByteArray.mk (Array.mkArray 32 0xEF)))

/-- The deterministic fake provider used by the model/handshake/e2e tests. -/
def fakeProvider : CryptoProvider :=
  { capabilities := fakeCapabilities, submit := fakeSubmit }

end Kroopt.Crypto
