import Kroopt.Crypto.NativeSecret
import Kroopt.Crypto.Hacl
import Kroopt.Crypto.RealProvider
import Kroopt.Error

/-!
# Connection provisioning — production entropy and certificate material

The real provider (`mkRealProvider`) closes over a `RealCryptoConfig` whose
ephemeral X25519 private key and certificate key pair were, until now, injected
by tests. Production wiring needs two things the test path stubbed:

* a **fresh ephemeral key pair per connection**, drawn from the OS CSPRNG, never
  reused and never injected; and
* **certificate material loaded from configuration**, with the public key
  *derived* from the private seed (a config lint), not trusted from input.

This module supplies both. It is interpreter-side glue (the `Crypto` zone, not
the pure core): it may draw entropy (`IO`) and call the HACL FFI. It performs no
DNS, no network access, no system-trust-store reads, and no peer validation —
deriving and presenting a server certificate, exactly the server-role scope.
-/

namespace Kroopt.Crypto

open Kroopt.Core (SignatureScheme)

/-- A server-certificate provisioning input: the Ed25519 signing-key seed, the
certificate chain (opaque DER, presented as-is), and the signature scheme it
presents with. The leaf public key is derived from the seed, never trusted from
input. -/
structure CertProvision where
  signingKeySeed : ByteArray
  chainDer       : ByteArray
  scheme         : SignatureScheme
  deriving Inhabited

/-- A provisioning error, kept distinct from protocol/crypto errors so a
misconfiguration fails closed at load rather than surfacing mid-handshake. -/
inductive ProvisionError where
  | badKeyLength (got : Nat)
  | unsupportedScheme (scheme : SignatureScheme)
  | keyMismatch
  | entropyFailure
  deriving Repr, DecidableEq

namespace Provision

/-- Signature schemes the vendored HACL subset can present a server certificate
with today. Ed25519 only until P-256 / RSA-PSS bindings land. -/
def supportedScheme : SignatureScheme → Bool
  | .ed25519 => true
  | _ => false

/-- Lint a provisioning input locally and deterministically (a config lint, **not**
peer validation): the seed is a 32-byte Ed25519 seed and the scheme is supported.
On success returns the derived leaf public key. No DNS, network, trust store, or
time. -/
def lint (p : CertProvision) : Except ProvisionError ByteArray :=
  if p.signingKeySeed.size != 32 then
    .error (.badKeyLength p.signingKeySeed.size)
  else if !supportedScheme p.scheme then
    .error (.unsupportedScheme p.scheme)
  else
    .ok (Hacl.ed25519Public p.signingKeySeed)

/-- Stricter lint: additionally require a caller-claimed leaf public key to equal
the key derived from the seed — catching a mis-paired certificate and private key
at config load (RFC 011 config-lint), before any connection is accepted. -/
def lintAgainstClaimed (p : CertProvision) (claimedPublic : ByteArray) :
    Except ProvisionError ByteArray :=
  match lint p with
  | .error e => .error e
  | .ok derived =>
      if derived.toList == claimedPublic.toList then .ok derived
      else .error .keyMismatch

end Provision

/-- Draw a fresh ephemeral X25519 key pair from the OS CSPRNG — one per
connection, never injected or reused. Fails closed: an entropy failure returns
`error`, never a zero or partial key. -/
def genEphemeralX25519 : IO (Except Hacl.EntropyError (ByteArray × ByteArray)) := do
  match ← Hacl.randomBytes 32 with
  | .bytes priv => pure (.ok (priv, Hacl.x25519Public priv))
  | .error e    => pure (.error e)

/-- Provision a real crypto config for one connection: lint the certificate
material (deriving the leaf public key from the seed), then draw a fresh ephemeral
key pair from OS entropy and combine them. Fails closed with the provisioning
error if the certificate material does not lint or entropy is unavailable. -/
def provisionRealConfig (p : CertProvision) :
    IO (Except ProvisionError RealCryptoConfig) := do
  match Provision.lint p with
  | .error e => pure (.error e)
  | .ok certPublic =>
      match ← genEphemeralX25519 with
      | .error _ => pure (.error .entropyFailure)
      | .ok (ephPriv, _ephPub) =>
          -- Move the Ed25519 signing key into the C-owned zeroizing arena and reference it by
          -- handle, so the durable config holds no key bytes on the Lean heap (RFC 037 §3).
          let kid ← NativeSecret.alloc p.signingKeySeed
          pure (.ok { ephemeralPrivate := ephPriv
                      certPrivate := ByteArray.empty
                      certKeyHandle := kid
                      certPublic := certPublic })

end Kroopt.Crypto
