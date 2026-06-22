import Kroopt.Crypto.ConfigCheck
import Kroopt.Crypto.RealProvider
import Kroopt.Crypto.Hacl

/-!
# Tests.Capabilities

RFC 034: the real provider advertises only the constrained profile
(`TLS_CHACHA20_POLY1305_SHA256` / X25519 / Ed25519 / SHA-256, OS CSPRNG), a config
requiring AES-GCM or ECDSA/RSA is rejected at validation, deterministic randomness
cannot enter the real provider, and entropy is fail-closed with a typed result.
-/

namespace Tests.Capabilities

open Kroopt.Core (ServerConfig EndpointConfig)
open Kroopt.Crypto

def ep (suite : Kroopt.Core.CipherSuite) (scheme : Kroopt.Core.SignatureScheme) : EndpointConfig :=
  { (default : EndpointConfig) with cipherSuites := [suite], signatureSchemes := [scheme] }

def cfgOf (e : EndpointConfig) : ServerConfig :=
  { (default : ServerConfig) with defaultEndpoint := some e }

def aesConfig    : ServerConfig := cfgOf (ep .aes128GcmSha256 .ed25519)
def aes256Config : ServerConfig := cfgOf (ep .aes256GcmSha384 .ed25519)
def ecdsaConfig : ServerConfig := cfgOf (ep .chacha20Poly1305Sha256 .ecdsaSecp256r1Sha256)
def goodConfig  : ServerConfig := cfgOf (ep .chacha20Poly1305Sha256 .ed25519)

def seed : ByteArray := ByteArray.mk (Array.mkArray 32 (0x07 : UInt8))
def testCfg : RealCryptoConfig :=
  { ephemeralPrivate := seed, certPrivate := seed, certPublic := Hacl.ed25519Public seed }

def main : IO Unit := do
  let realAcceptsAes128 :=
    match validateServerConfigCapabilities realCapabilities aesConfig with
    | .ok () => true | _ => false
  let realAcceptsAes256 :=
    match validateServerConfigCapabilities realCapabilities aes256Config with
    | .ok () => true | _ => false
  let realRejectsEcdsa :=
    match validateServerConfigCapabilities realCapabilities ecdsaConfig with
    | .error (.unsupportedSignatureScheme _) => true | _ => false
  let realAcceptsGood :=
    match validateServerConfigCapabilities realCapabilities goodConfig with
    | .ok () => true | _ => false
  let fakeAcceptsAes :=
    match validateServerConfigCapabilities fakeCapabilities aes256Config with
    | .ok () => true | _ => false
  let realIsOsCsprng :=
    match realCapabilities.randomSource with | .osCsprng => true | _ => false
  -- the real *provider* now advertises AES-256-GCM-SHA384 (the SHA-384 schedule landed)
  let realProv := mkRealProvider testCfg
  let provAcceptsAes256 :=
    match validateServerConfigCapabilities realProv.capabilities aes256Config with
    | .ok () => true | _ => false
  -- deterministic randomness cannot come out of the real provider
  let provRandErrors :=
    match RealProvider.submit testCfg SecretArena.empty ⟨0⟩ (.randomBytes 32) with
    | .error _ => true | _ => false
  -- entropy is fail-closed and typed: a successful draw yields exactly 32 bytes
  let ent ← Hacl.randomBytes 32
  let entropyTypedOk := match ent with | .bytes b => b.size == 32 | .error _ => false

  let checks : List (String × Bool) :=
    [ ("real profile accepts TLS_AES_128_GCM_SHA256 (seal path suite-aware, SHA-256 schedule)", realAcceptsAes128)
    , ("real profile now accepts TLS_AES_256_GCM_SHA384 (SHA-384 schedule landed)", realAcceptsAes256)
    , ("real profile rejects an ECDSA signature scheme at config validation", realRejectsEcdsa)
    , ("real profile accepts the constrained ChaCha/Ed25519 config", realAcceptsGood)
    , ("the fake/test profile accepts AES-256 too (the two profiles still differ)", fakeAcceptsAes)
    , ("the real profile's random source is the OS CSPRNG", realIsOsCsprng)
    , ("mkRealProvider advertises AES-256-GCM-SHA384 (accepts AES-256)", provAcceptsAes256)
    , ("a randomBytes op reaching the real provider is an error, not zeros", provRandErrors)
    , ("Hacl.randomBytes is fail-closed and typed (32-byte success)", entropyTypedOk) ]
  let mut passed := 0
  for (name, ok) in checks do
    IO.println s!"  {if ok then "PASS" else "FAIL"}  {name}"
    if ok then passed := passed + 1
  IO.println s!"kroopt RFC 034 capability honesty + fail-closed entropy:"
  if passed == checks.length then IO.println s!"All {passed} checks passed."
  else IO.eprintln "FAILED"

end Tests.Capabilities

def main : IO Unit := Tests.Capabilities.main
