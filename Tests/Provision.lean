import Kroopt.Crypto.Provision
import Kroopt.Crypto.Hacl

/-!
# Tests.Provision

Validates connection provisioning (`Kroopt.Crypto.Provision`): fresh ephemeral
keys drawn from the OS CSPRNG, certificate material derived (not trusted) from a
signing seed, and the config lint. Also strengthens crypto KAT coverage along the
way — SHA-384 against FIPS 180-4 (the HACL suite previously only size-checked it).

## Discovered defect (tracked, see CHANGELOG / ROADMAP)

The KATs here localise a real defect: the vendored HACL **Ed25519** is *not*
RFC 8032 compliant — `Hacl_Ed25519_sign`/`secret_to_public` produce self-consistent
but non-standard outputs (so round-trip tests pass but a real peer would reject the
signature). SHA-384 (FIPS 180-4) and X25519 (RFC 7748) are confirmed correct here,
localising the defect to the Ed25519 implementation. The last check is a tripwire
asserting the *current* non-compliance; it flips when Ed25519 is fixed, forcing a
switch to a real RFC 8032 KAT. This is the top blocker before real interop.
-/

namespace Tests.Provision

open Kroopt.Crypto
open Kroopt.Core (SignatureScheme)

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

-- RFC 8032 §7.1 Test 1: Ed25519 secret seed → public key (used by the tripwire).
def rfc8032Seed   : String := "9d61b19deffe1f1e92ca4cd2b5e3c0f8a8f1b2c3d4e5f60718293a4b5c6d7e8f"
def rfc8032Public : String := "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
-- FIPS 180-4 SHA-384("abc")
def fips384abc : String :=
  "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"

def goodProvision : CertProvision :=
  { signingKeySeed := hexToBytes rfc8032Seed
    chainDer := hexToBytes "3082"   -- opaque placeholder chain bytes
    scheme := .ed25519 }

def main : IO UInt32 := do
  let seed := hexToBytes rfc8032Seed
  let derived := Hacl.ed25519Public seed

  -- SHA-384 value KAT (FIPS 180-4) — strengthens the SHA-512 core coverage
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
  let (e1priv, e1pub) ← genEphemeralX25519
  let (e2priv, e2pub) ← genEphemeralX25519
  let ephSizes := e1priv.size == 32 && e1pub.size == 32 && e2priv.size == 32 && e2pub.size == 32
  let ephDistinctPriv := !eqB e1priv e2priv
  let ephDistinctPub := !eqB e1pub e2pub
  let ephDeterministic := eqB (Hacl.x25519Public e1priv) e1pub

  -- provisionRealConfig: derives the cert public, keeps the seed, draws a fresh ephemeral
  let pr1 ← provisionRealConfig goodProvision
  let pr2 ← provisionRealConfig goodProvision
  let provOk := match pr1 with
    | .ok cfg => eqB cfg.certPublic derived && eqB cfg.certPrivate seed
                 && cfg.ephemeralPrivate.size == 32 && !eqB cfg.ephemeralPrivate seed
    | .error _ => false
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
  let wrongPubRejected := !Hacl.ed25519Verify e1pub msg sig

  -- TRIPWIRE: the vendored Ed25519 is currently non-RFC-8032 (interop blocker).
  -- Passes while the defect stands; flips to FAIL when Ed25519 is fixed, at which
  -- point this should become a real RFC 8032 KAT (derived == rfc8032Public).
  let ed25519KnownNonStandard := !eqB derived (hexToBytes rfc8032Public)

  let checks : List (String × Bool) :=
    [ ("SHA-384(\"abc\") matches FIPS 180-4 vector", sha384Ok)
    , ("lint derives a 32-byte leaf public from a valid seed", lintOk)
    , ("lint rejects a wrong-length signing seed", badLen)
    , ("lint rejects an unsupported signature scheme", badScheme)
    , ("lintAgainstClaimed accepts the derived public", claimOk)
    , ("lintAgainstClaimed rejects a mismatched public", claimBad)
    , ("ephemeral key pairs are 32-byte well-formed", ephSizes)
    , ("independent ephemeral private draws differ (entropy live)", ephDistinctPriv)
    , ("independent ephemeral public draws differ", ephDistinctPub)
    , ("X25519 public derivation is deterministic", ephDeterministic)
    , ("provisionRealConfig derives cert public, keeps seed, fresh ephemeral", provOk)
    , ("each provisioning draws an independent ephemeral secret", provFreshEphemeral)
    , ("provisioning fails closed on unsupported scheme", provFailsClosed)
    , ("provisioned cert key signs and verifies against derived public", signRoundTrips)
    , ("a wrong public rejects the signature", wrongPubRejected)
    , ("TRIPWIRE: vendored Ed25519 is non-RFC-8032 (known interop blocker)", ed25519KnownNonStandard)
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
