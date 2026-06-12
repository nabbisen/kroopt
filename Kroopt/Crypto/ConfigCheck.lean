import Kroopt.Crypto.Provider
import Kroopt.Core.Config

/-!
# Kroopt.Crypto.ConfigCheck

Capability validation between a `ServerConfig` and a `CryptoProvider` (RFC 034 §2,
RFC 008 §3). This is the **startup** check: a configuration that requires a cipher
suite or signature scheme the provider cannot perform is rejected here, with a typed
`CapabilityError`, rather than accepted and failed mid-handshake. kroopt never
silently downgrades. With `realCapabilities`, this rejects any AES-GCM suite or
ECDSA/RSA signature scheme.
-/

namespace Kroopt.Crypto

open Kroopt.Core (ServerConfig EndpointConfig)

/-- The crypto a `ServerConfig` requires: the union of every endpoint's configured
cipher suites and signature schemes (`defaultEndpoint` plus every SNI route). In the
constrained TLS 1.3 profile, groups/hashes are implied by the suites, so only suites
and signature schemes are checked against provider capabilities. -/
def requiredCryptoOfServerConfig (cfg : ServerConfig) : RequiredCrypto :=
  let eps : List EndpointConfig :=
    cfg.defaultEndpoint.toList ++ cfg.sniRoutes.map (·.endpoint)
  { suites           := eps.foldr (fun e acc => e.cipherSuites ++ acc) []
    groups           := []
    signatureSchemes := eps.foldr (fun e acc => e.signatureSchemes ++ acc) []
    hashAlgorithms   := [] }

/-- Reject, at config/listener startup, a configuration requiring crypto the
provider cannot perform (RFC 034 §2). Deterministic, total, no IO. -/
def validateServerConfigCapabilities
    (caps : CryptoCapabilities) (cfg : ServerConfig) : Except CapabilityError Unit :=
  validateCapabilities caps (requiredCryptoOfServerConfig cfg)

end Kroopt.Crypto
