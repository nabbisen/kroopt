import Kroopt.Core.CipherSuite
import Kroopt.Core.Id
import Kroopt.Core.Crypto
import Kroopt.Error

/-!
# Kroopt.Core.Cert

The server certificate-presentation model (RFC 012). kroopt **presents** a
configured chain and proves key possession via CertificateVerify; it does **not**
validate a peer chain in server mode (that is the client/mTLS RFC). The chain is
opaque DER; only minimal leaf metadata is modelled, for signature-scheme
selection and config lint.

Everything here is pure data and pure validation — no DER bytes are inspected and
no IO is performed. The actual DER parse and key load happen at the (impure)
config-loading boundary; this module is what the verified core and the proofs
reason over.
-/

namespace Kroopt.Core

open Kroopt (ConfigError)

/-- The public-key kind of a leaf certificate (what the chain presents). -/
inductive PublicKeyKind where
  | ed25519
  | ecdsaP256
  | rsa
  deriving DecidableEq, Repr, Inhabited

/-- The private-key kind held behind a secret handle. -/
inductive PrivateKeyKind where
  | ed25519
  | ecdsaP256
  | rsa
  deriving DecidableEq, Repr, Inhabited

/-- Whether a public-key kind and a private-key kind are the same algorithm. -/
def keyKindsMatch : PublicKeyKind → PrivateKeyKind → Bool
  | .ed25519,   .ed25519   => true
  | .ecdsaP256, .ecdsaP256 => true
  | .rsa,       .rsa       => true
  | _,          _          => false

/-- Which signature schemes a leaf public key of a given kind can produce. -/
def schemesForKey : PublicKeyKind → List SignatureScheme
  | .ed25519   => [.ed25519]
  | .ecdsaP256 => [.ecdsaSecp256r1Sha256]
  | .rsa       => [.rsaPssRsaeSha256]

/-- Minimal parsed leaf metadata (RFC 012 §4). Subject names are a redacted
preview only; expiry is optional lint, never peer validation. -/
structure LeafCertificateMeta where
  publicKeyKind     : PublicKeyKind
  /-- Number of redacted subject-name entries (the names themselves are not
  retained as attacker-relevant strings in the core model). -/
  subjectNameCount  : Nat
  notBeforeUnix     : Option Int
  notAfterUnix      : Option Int
  deriving Repr, Inhabited

/-- An opaque handle to a configured DER chain (RFC 012 §4). The DER stays
opaque; only `leafMeta` is modelled. -/
structure CertificateChainHandle where
  id         : UInt64
  generation : ConfigGeneration
  chainLen   : Nat
  derSize    : Nat
  leafMeta   : LeafCertificateMeta
  deriving Repr, Inhabited

/-- A private key behind a secret handle (RFC 012 §4). The bytes never appear in
a Lean value. -/
structure PrivateKeyHandle where
  secret     : SecretKeyHandle
  keyKind    : PrivateKeyKind
  generation : ConfigGeneration
  deriving Inhabited

/-- The result of validating an endpoint's cert/key pair (RFC 012 §7). -/
structure EndpointCertInfo where
  chain            : CertificateChainHandle
  key              : PrivateKeyHandle
  compatibleSchemes : List SignatureScheme
  deriving Inhabited

/-- The configured maximum DER size for a chain (config lint, RFC 012 §5). -/
def maxCertChainDerBytes : Nat := 65536

/-- Select a signature scheme for CertificateVerify (RFC 012 §6): a scheme the
client offered, the endpoint configured, **and** the leaf key can produce. The
result is therefore never a downgrade to an uncompatible/unoffered scheme. The
client's order is honoured (first acceptable wins). -/
def selectSignatureScheme
    (clientOffered : List SignatureScheme)
    (endpointConfigured : List SignatureScheme)
    (leaf : PublicKeyKind) : Option SignatureScheme :=
  let keyCapable := schemesForKey leaf
  clientOffered.find? (fun s => endpointConfigured.contains s && keyCapable.contains s)

/-- Validate an endpoint's certificate/private-key compatibility at config load
(RFC 012 §5). A pure config *lint*, not peer path validation: it checks the leaf
key kind matches the private key kind, the chain is non-empty and within size
bounds, and at least one configured signature scheme is usable. -/
def validateEndpointCertKey
    (chain : CertificateChainHandle)
    (key : PrivateKeyHandle)
    (configuredSchemes : List SignatureScheme) : Except ConfigError EndpointCertInfo :=
  if chain.chainLen = 0 then
    .error .emptyChain
  else if chain.derSize > maxCertChainDerBytes then
    .error .oversizedDer
  else if ¬ keyKindsMatch chain.leafMeta.publicKeyKind key.keyKind then
    .error .certKeyMismatch
  else
    let capable := schemesForKey chain.leafMeta.publicKeyKind
    let usable := configuredSchemes.filter (fun s => capable.contains s)
    match usable with
    | [] => .error .certKeyMismatch
    | _  => .ok { chain := chain, key := key, compatibleSchemes := usable }

end Kroopt.Core
