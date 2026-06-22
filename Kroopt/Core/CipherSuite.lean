/-!
# Kroopt.Core.CipherSuite

TLS 1.3 negotiation primitives: cipher suites, named groups, signature schemes,
and hash algorithms (RFC 006 §5, requirements §9). M0 fixes the initial
supported set; breadth (P-256, AES-256-GCM, SHA-384, RSA-PSS) arrives at v0.4
without changing this shape.
-/

namespace Kroopt.Core

/-- Hash algorithms used by the transcript and key schedule. -/
inductive HashAlgorithm where
  | sha256
  | sha384
  deriving DecidableEq, Repr, Inhabited

namespace HashAlgorithm

/-- Output length in bytes of the transcript/HKDF hash: 32 for SHA-256, 48 for
SHA-384. The pure-core counterpart of `KeySchedule.hashLen` (which lives in the
FFI zone), so the verified core can size HKDF-Expand-Label ops without depending
on the crypto provider. -/
def digestLen : HashAlgorithm → Nat
  | sha256 => 32
  | sha384 => 48

end HashAlgorithm

/-- TLS 1.3 AEAD cipher suites. AES-128-GCM and ChaCha20-Poly1305 are the
required initial set; AES-256-GCM is optional (requirements §9.3). -/
inductive CipherSuite where
  | aes128GcmSha256
  | aes256GcmSha384
  | chacha20Poly1305Sha256
  deriving DecidableEq, Repr, Inhabited

namespace CipherSuite

/-- The transcript/HKDF hash bound to a suite. The transcript hash algorithm
must match the selected suite (RFC 007 §8). -/
def hashAlg : CipherSuite → HashAlgorithm
  | aes128GcmSha256        => .sha256
  | aes256GcmSha384        => .sha384
  | chacha20Poly1305Sha256 => .sha256

end CipherSuite

/-- Key-exchange groups. X25519 is required; P-256 is recommended at v0.4
(requirements §9.2). -/
inductive NamedGroup where
  | x25519
  | secp256r1
  deriving DecidableEq, Repr, Inhabited

/-- Server-authentication signature schemes. Ed25519 and ECDSA-P256 are
required; RSA-PSS as EverCrypt allows (requirements §9.5). -/
inductive SignatureScheme where
  | ed25519
  | ecdsaSecp256r1Sha256
  | rsaPssRsaeSha256
  deriving DecidableEq, BEq, Repr, Inhabited

end Kroopt.Core
