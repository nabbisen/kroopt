import Kroopt.Crypto.NativeSecret
import Kroopt.Crypto.Provision
import Kroopt.Crypto.Hacl
import Tests.Vectors.Ed25519Rfc8032

/-!
# Tests.Provision

Validates connection provisioning (`Kroopt.Crypto.Provision`): fresh ephemeral
keys drawn from the OS CSPRNG, certificate material derived (not trusted) from a
signing seed, and the config lint. Also carries the Ed25519 / SHA known-answer
tests against published vectors with explicit provenance
(`Tests.Vectors.Ed25519Rfc8032`).

HACL\* Ed25519 is RFC 8032 compliant: for the **RFC 8032 §7.1 Test 1** seed it
reproduces the published public key and signature byte-for-byte (verified here and
cross-checked against an independent RFC 8032 reference and OpenSSL). The local
`9d61…7e8f` seed is kept only as a labelled arbitrary-seed regression vector — it is
**not** an RFC vector, and was the source of a historical false alarm when it was
mistakenly paired with RFC Test 1's public key.
-/

namespace Tests.Provision

open Kroopt.Crypto
open Kroopt.Core (SignatureScheme)
open Tests.Vectors.Ed25519Rfc8032

def hexToBytes (s : String) : ByteArray := Id.run do
  let cs := s.toList.toArray
  let hv : Char → UInt8 := fun c =>
    if '0' ≤ c ∧ c ≤ '9' then (c.toNat - '0'.toNat).toUInt8
    else if 'a' ≤ c ∧ c ≤ 'f' then (c.toNat - 'a'.toNat + 10).toUInt8 else 0
  let mut out := ByteArray.empty
  let mut i := 0
  while i + 1 < cs.size do
    out := out.push (hv cs[i]! * 16 + hv cs[i+1]!); i := i + 2
  return out

def eqB (a b : ByteArray) : Bool := a.toList == b.toList

-- FIPS 180-4, "SHA-384 Example (One-Block)": message = ASCII "abc" (3 bytes).
def fips384abc : String :=
  "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"

-- The certificate signing key for provisioning checks is the RFC 8032 Test 1 seed.
def goodProvision : CertProvision :=
  { signingKeySeed := hexToBytes rfc8032Test1.seedHex
    chainDer := hexToBytes "3082"   -- opaque placeholder chain bytes
    scheme := .ed25519 }

def main : IO UInt32 := do
  let seed := hexToBytes rfc8032Test1.seedHex
  let derived := Hacl.ed25519Public seed

  -- Vector provenance discipline: lengths well-formed; the RFC seed and the
  -- local regression seed are distinct (guards against re-mixing them).
  let vectorsWellFormed :=
    wellFormed rfc8032Test1 && wellFormed localRegression && seedsDistinct

  -- Ed25519 RFC 8032 §7.1 Test 1 KAT (public key + empty-message signature)
  let rfcPubOk := eqB (Hacl.ed25519Public seed) (hexToBytes rfc8032Test1.pubHex)
  let rfcSigOk := eqB (Hacl.ed25519Sign seed ByteArray.empty) (hexToBytes rfc8032Test1.sigHex)
  -- Local arbitrary-seed regression KAT (NOT an RFC vector)
  let regSeed := hexToBytes localRegression.seedHex
  let regPubOk := eqB (Hacl.ed25519Public regSeed) (hexToBytes localRegression.pubHex)
  let regSigOk := eqB (Hacl.ed25519Sign regSeed ByteArray.empty) (hexToBytes localRegression.sigHex)

  -- SHA-384 value KAT (FIPS 180-4)
  let sha384Ok := eqB (Hacl.sha384 "abc".toUTF8) (hexToBytes fips384abc)

  -- lint derives a well-formed 32-byte leaf public from a valid seed
  let lintOk := match Provision.lint goodProvision with
    | .ok pub => pub.size == 32
    | .error _ => false
  -- lint rejects a wrong-length seed and an unsupported scheme
  let badLen := match Provision.lint { goodProvision with signingKeySeed := hexToBytes "00112233" } with
    | .error (.badKeyLength _) => true
    | _ => false
  let badScheme := match Provision.lint { goodProvision with scheme := .ecdsaSecp256r1Sha256 } with
    | .error (.unsupportedScheme .ecdsaSecp256r1Sha256) => true
    | _ => false
  -- lintAgainstClaimed: the derived public is accepted, a different one rejected
  let claimOk := match Provision.lintAgainstClaimed goodProvision derived with
    | .ok _ => true | .error _ => false
  let claimBad := match Provision.lintAgainstClaimed goodProvision (derived ++ hexToBytes "00") with
    | .error .keyMismatch => true | _ => false

  -- fresh ephemeral generation: well-formed and live (independent draws differ)
  let e1 ← genEphemeralX25519
  let e2 ← genEphemeralX25519
  let ⟨ephSizes, ephDistinctPriv, ephDistinctPub, ephDeterministic⟩ :=
    match e1, e2 with
    | .ok (e1priv, e1pub), .ok (e2priv, e2pub) =>
        (⟨ e1priv.size == 32 && e1pub.size == 32 && e2priv.size == 32 && e2pub.size == 32
         , !eqB e1priv e2priv
         , !eqB e1pub e2pub
         , eqB (Hacl.x25519Public e1priv) e1pub ⟩ : Bool × Bool × Bool × Bool)
    | _, _ => (⟨false, false, false, false⟩ : Bool × Bool × Bool × Bool)

  -- provisionRealConfig: derives the cert public, moves the seed into the C arena (not the Lean
  -- config), draws a fresh ephemeral
  let pr1 ← provisionRealConfig goodProvision
  let pr2 ← provisionRealConfig goodProvision
  let keyInArena ← match pr1 with
    | .ok cfg =>
        if cfg.certKeyHandle != 0 then do
          let k ← Kroopt.Crypto.NativeSecret.read cfg.certKeyHandle
          pure (eqB k seed)
        else pure false
    | .error _ => pure false
  let provOk := (match pr1 with
    | .ok cfg => eqB cfg.certPublic derived && cfg.certPrivate.size == 0 && cfg.certKeyHandle != 0
                 && cfg.ephemeralPrivate.size == 32 && !eqB cfg.ephemeralPrivate seed
    | .error _ => false) && keyInArena
  let provFreshEphemeral := match pr1, pr2 with
    | .ok c1, .ok c2 => !eqB c1.ephemeralPrivate c2.ephemeralPrivate
    | _, _ => false
  let provFailsClosed ← do
    let r ← provisionRealConfig { goodProvision with scheme := .rsaPssRsaeSha256 }
    pure (match r with | .error (.unsupportedScheme _) => true | _ => false)

  -- the provisioned certificate key signs and verifies against its derived public
  let msg := hexToBytes "0102030405060708"
  let sig := Hacl.ed25519Sign seed msg
  let signRoundTrips := Hacl.ed25519Verify derived msg sig
  let wrongPub := derived.set! 0 ((derived.get! 0) ^^^ 1)
  let wrongPubRejected := !Hacl.ed25519Verify wrongPub msg sig

  let checks : List (String × Bool) :=
    [ ("Ed25519 RFC 8032 §7.1 Test 1: public key matches", rfcPubOk)
    , ("Ed25519 RFC 8032 §7.1 Test 1: signature(\"\") matches", rfcSigOk)
    , ("Ed25519 local regression vector (non-RFC): public matches", regPubOk)
    , ("Ed25519 local regression vector (non-RFC): signature matches", regSigOk)
    , ("vector lengths well-formed and RFC/regression seeds distinct", vectorsWellFormed)
    , ("SHA-384(\"abc\") matches FIPS 180-4 vector", sha384Ok)
    , ("lint derives a 32-byte leaf public from a valid seed", lintOk)
    , ("lint rejects a wrong-length signing seed", badLen)
    , ("lint rejects an unsupported signature scheme", badScheme)
    , ("lintAgainstClaimed accepts the derived public", claimOk)
    , ("lintAgainstClaimed rejects a mismatched public", claimBad)
    , ("ephemeral key pairs are 32-byte well-formed", ephSizes)
    , ("independent ephemeral private draws differ (entropy live)", ephDistinctPriv)
    , ("independent ephemeral public draws differ", ephDistinctPub)
    , ("X25519 public derivation is deterministic", ephDeterministic)
    , ("provisionRealConfig derives cert public, moves seed into the C arena, fresh ephemeral", provOk)
    , ("each provisioning draws an independent ephemeral secret", provFreshEphemeral)
    , ("provisioning fails closed on unsupported scheme", provFailsClosed)
    , ("provisioned cert key signs and verifies against derived public", signRoundTrips)
    , ("a wrong public rejects the signature", wrongPubRejected)
    ]

  let mut failed := 0
  IO.println "kroopt connection provisioning (entropy + certificate material):"
  for (name, ok) in checks do
    IO.println s!"  {if ok then "PASS" else "FAIL"}  {name}"
    if !ok then failed := failed + 1
  IO.println ""
  if failed == 0 then
    IO.println s!"All {checks.length} checks passed."
    pure 0
  else
    IO.println s!"{failed} of {checks.length} checks FAILED."
    pure 1

end Tests.Provision

def main : IO UInt32 := Tests.Provision.main
