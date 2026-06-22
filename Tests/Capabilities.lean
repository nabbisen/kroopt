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

def aesConfig   : ServerConfig := cfgOf (ep .aes128GcmSha256 .ed25519)
def ecdsaConfig : ServerConfig := cfgOf (ep .chacha20Poly1305Sha256 .ecdsaSecp256r1Sha256)
def goodConfig  : ServerConfig := cfgOf (ep .chacha20Poly1305Sha256 .ed25519)

def seed : ByteArray := ByteArray.mk (Array.mkArray 32 (0x07 : UInt8))
def testCfg : RealCryptoConfig :=
  { ephemeralPrivate := seed, certPrivate := seed, certPublic := Hacl.ed25519Public seed }

def main : IO Unit := do
  let realRejectsAes :=
    match validateServerConfigCapabilities realCapabilities aesConfig with
    | .error (.unsupportedSuite _) => true | _ => false
  let realRejectsEcdsa :=
    match validateServerConfigCapabilities realCapabilities ecdsaConfig with
    | .error (.unsupportedSignatureScheme _) => true | _ => false
  let realAcceptsGood :=
    match validateServerConfigCapabilities realCapabilities goodConfig with
    | .ok () => true | _ => false
  let fakeAcceptsAes :=
    match validateServerConfigCapabilities fakeCapabilities aesConfig with
    | .ok () => true | _ => false
  let realIsOsCsprng :=
    match realCapabilities.randomSource with | .osCsprng => true | _ => false
  -- the real *provider* (not just the constant) advertises the constrained end-to-end profile
  let realProv := mkRealProvider testCfg
  let provRejectsAes :=
    match validateServerConfigCapabilities realProv.capabilities aesConfig with
    | .error (.unsupportedSuite _) => true | _ => false
  -- deterministic randomness cannot come out of the real provider
  let provRandErrors :=
    match RealProvider.submit testCfg SecretArena.empty ⟨0⟩ (.randomBytes 32) with
    | .error _ => true | _ => false
  -- entropy is fail-closed and typed: a successful draw yields exactly 32 bytes
  let ent ← Hacl.randomBytes 32
  let entropyTypedOk := match ent with | .bytes b => b.size == 32 | .error _ => false

  let checks : List (String × Bool) :=
    [ ("real profile rejects an AES-GCM suite at config validation (seal path not suite-aware yet)", realRejectsAes)
    , ("real profile rejects an ECDSA signature scheme at config validation", realRejectsEcdsa)
    , ("real profile accepts the constrained ChaCha/Ed25519 config", realAcceptsGood)
    , ("the fake/test profile still accepts AES (the two profiles differ)", fakeAcceptsAes)
    , ("the real profile's random source is the OS CSPRNG", realIsOsCsprng)
    , ("mkRealProvider advertises the constrained profile (rejects AES)", provRejectsAes)
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
