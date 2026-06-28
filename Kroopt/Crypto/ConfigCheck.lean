import Kroopt.Crypto.Provider
import Kroopt.Core.Config

/-!
# Kroopt.Crypto.ConfigCheck

Capability validation between a `ServerConfig` and a `CryptoProvider` (RFC 034 §2,
RFC 008 §3). This is the **startup** check: a configuration that requires a cipher
suite or signature scheme the provider cannot perform is rejected here, with a typed
`CapabilityError`, rather than accepted and failed mid-handshake. kroopt never
silently downgrades. `realCapabilities` advertises the AES-128/256-GCM and
ChaCha20-Poly1305 suites, X25519 and P-256 groups, and SHA-256/384 — but
**Ed25519 signatures only**, so this rejects a config requiring an ECDSA-P256 or
RSA-PSS signature scheme (those are bound but not advertised). AES-GCM is accepted
at validation (its live-wire interop is the constrained-profile follow-up; the
live wire negotiates ChaCha20-Poly1305).
-/

namespace Kroopt.Crypto

open Kroopt.Core (ServerConfig EndpointConfig CipherSuite NamedGroup HashAlgorithm)

/-- Order-preserving de-duplication using only `DecidableEq` (no `BEq`/Mathlib). -/
private def dedup {α : Type} [DecidableEq α] (xs : List α) : List α :=
  xs.foldr (fun x acc => if x ∈ acc then acc else x :: acc) []

/-- The hash algorithms the configured suites require (RFC 039 §4.4, derive-and-enforce).
In TLS 1.3 each suite pins its transcript/HKDF hash, so this is a total function of the
suite list; it is validated against provider capability like the other dimensions. -/
def deriveHashesFromSuites (ss : List CipherSuite) : List HashAlgorithm :=
  dedup (ss.map (·.hashAlg))

/-- Normalize an endpoint's named-group policy (RFC 039 §4.5): a group policy must be
non-empty and duplicate-free. Endpoint-policy faults are `CapabilityError` (a configuration
failure); client-side faults live in the TLS handshake taxonomy, not here. -/
def normalizeNamedGroups (gs : List NamedGroup) : Except CapabilityError (List NamedGroup) :=
  if gs.isEmpty then .error .emptyGroupPolicy
  else if (dedup gs).length != gs.length then .error .duplicateNamedGroup
  else .ok gs

/-- The crypto a `ServerConfig` requires (RFC 039 §4.2): the union over every endpoint
(`defaultEndpoint` plus every SNI route) of cipher suites, **named groups**, and signature
schemes, with hash algorithms **derived** from the suites. All four dimensions are now
load-bearing against provider capabilities. -/
def requiredCryptoOfServerConfig (cfg : ServerConfig) : RequiredCrypto :=
  let eps : List EndpointConfig :=
    cfg.defaultEndpoint.toList ++ cfg.sniRoutes.map (·.endpoint)
  let suites := eps.foldr (fun e acc => e.cipherSuites ++ acc) []
  { suites           := suites
    groups           := eps.foldr (fun e acc => e.namedGroups ++ acc) []
    signatureSchemes := eps.foldr (fun e acc => e.signatureSchemes ++ acc) []
    hashAlgorithms   := deriveHashesFromSuites suites }

/-- Reject, at config/listener startup, a configuration requiring crypto the provider
cannot perform, or an ill-formed endpoint group policy (RFC 034 §2, RFC 039 §4.2/§4.5).
Deterministic, total, no IO. -/
def validateServerConfigCapabilities
    (caps : CryptoCapabilities) (cfg : ServerConfig) : Except CapabilityError Unit := do
  let eps : List EndpointConfig :=
    cfg.defaultEndpoint.toList ++ cfg.sniRoutes.map (·.endpoint)
  -- per-endpoint group-policy well-formedness (empty / duplicate) first
  eps.forM (fun e => do let _ ← normalizeNamedGroups e.namedGroups; pure ())
  -- then capability subset check across all four dimensions
  validateCapabilities caps (requiredCryptoOfServerConfig cfg)

end Kroopt.Crypto
