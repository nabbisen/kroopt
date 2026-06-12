import Kroopt.Crypto.Hacl

/-!
# Tests.Hacl

Known-answer tests for the v0.3 native crypto binding, run **through Lean** over
the FFI into the vendored HACL* primitives. Vectors are from the relevant RFCs
(FIPS 180-4, RFC 7748, RFC 5869, RFC 4231) plus AEAD/signature round-trips with
tamper rejection. A green run proves the native crypto path works end-to-end in
the Lean build, not just in standalone C.

Vector-provenance discipline (see docs/src/postmortem-ed25519.md): every published
KAT below carries a source + section comment; checks without a published vector are
labelled "round-trip"/"self-consistency" in their names so they are never mistaken
for standards conformance.
-/

namespace Tests.Hacl

open Kroopt.Crypto.Hacl

structure Check where
  name : String
  ok : Bool

def hexToBytes (s : String) : ByteArray := Id.run do
  let cs := s.toList.toArray
  let hexVal : Char → UInt8 := fun c =>
    if '0' ≤ c ∧ c ≤ '9' then (c.toNat - '0'.toNat).toUInt8
    else if 'a' ≤ c ∧ c ≤ 'f' then (c.toNat - 'a'.toNat + 10).toUInt8
    else if 'A' ≤ c ∧ c ≤ 'F' then (c.toNat - 'A'.toNat + 10).toUInt8
    else 0
  let mut out : ByteArray := ByteArray.empty
  let mut i := 0
  while i + 1 < cs.size do
    out := out.push (hexVal cs[i]! * 16 + hexVal cs[i+1]!)
    i := i + 2
  return out

def toHex (b : ByteArray) : String :=
  let digit : UInt8 → Char := fun n =>
    if n < 10 then Char.ofNat (n.toNat + '0'.toNat) else Char.ofNat (n.toNat - 10 + 'a'.toNat)
  b.toList.foldl (fun acc x => acc.push (digit (x / 16)) |>.push (digit (x % 16))) ""

def bytesEq (a b : ByteArray) : Bool := a.toList == b.toList
def rep (n : Nat) (v : UInt8) : ByteArray := ByteArray.mk (Array.mkArray n v)

-- Published known-answer vectors. Each carries its source, section, input, and the
-- expected-value origin, so a mistyped expected value is traceable to a citation
-- rather than localised into the primitive (see docs/src/postmortem-ed25519.md).
-- Round-trip / self-consistency checks (AEAD, the arbitrary-key Ed25519 sign/verify
-- below) are NOT published vectors and are labelled as such in the check names.

-- FIPS 180-4, "SHA-256 Example (One-Block)": message = ASCII "abc" (3 bytes).
def sha256_abc := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
-- FIPS 180-4, "SHA-384 Example (One-Block)": message = ASCII "abc" (3 bytes).
def sha384_abc := "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
-- FIPS 180-4, "SHA-512 Example (One-Block)": message = ASCII "abc" (3 bytes).
def sha512_abc := "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
-- RFC 7748 §6.1 (X25519 test vector): Alice private (32B) and Bob public (32B) →
-- shared secret (32B). Field names retained: priv = Alice scalar, peer = Bob u-coord.
def x25519_priv := "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"
def x25519_peer := "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"
def x25519_out  := "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
-- RFC 5869 §A.1 Test Case 1 (HKDF-SHA-256): IKM = 22×0x0b, salt = 0x000102…0c (13B),
-- info = 0xf0f1…f9 (10B), L = 42 → PRK (32B) and OKM (42B).
def hkdf_prk := "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
def hkdf_okm := "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
-- RFC 4231 §4.2 Test Case 1 (HMAC-SHA-256): key = 20×0x0b, data = ASCII "Hi There".
def hmac_tc1 := "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"

def main : IO UInt32 := do
  -- AEAD round-trip (self-consistency / tamper rejection — NOT a published vector;
  -- arbitrary key/nonce/aad/plaintext)
  let key := rep 32 0x2b
  let nonce := rep 12 0x07
  let aad := hexToBytes "01020304"
  let pt := hexToBytes "48656c6c6f2c20545453"   -- "Hello, TLS"
  let sealed := chachaPolySeal key nonce aad pt
  let opened := chachaPolyOpen key nonce aad sealed
  let tampered := chachaPolyOpen key nonce aad (sealed.set! 0 ((sealed.get! 0) ^^^ 1))
  -- Ed25519 round-trip (self-consistency — NOT a published vector; arbitrary key.
  -- The published RFC 8032 §7.1 Test 1 KAT lives in kroopt-provision-test via
  -- Tests/Vectors/Ed25519Rfc8032.lean.)
  let edPriv := rep 32 0x11
  let edPub := ed25519Public edPriv
  let msg := hexToBytes "deadbeef"
  let sig := ed25519Sign edPriv msg
  let edOk := ed25519Verify edPub msg sig
  let edBad := ed25519Verify edPub (hexToBytes "deadbe00") sig
  -- random
  let r1 ← (do match ← randomBytes 32 with | .bytes b => pure b | .error _ => pure ByteArray.empty)
  let r2 ← (do match ← randomBytes 32 with | .bytes b => pure b | .error _ => pure ByteArray.empty)

  let checks : List Check :=
    [ { name := "SHA-256(\"abc\") matches FIPS 180-4 vector"
      , ok := bytesEq (sha256 "abc".toUTF8) (hexToBytes sha256_abc) }
    , { name := "SHA-384(\"abc\") matches FIPS 180-4 vector"
      , ok := bytesEq (sha384 "abc".toUTF8) (hexToBytes sha384_abc) }
    , { name := "SHA-512(\"abc\") matches FIPS 180-4 vector"
      , ok := bytesEq (sha512 "abc".toUTF8) (hexToBytes sha512_abc) }
    , { name := "X25519 ECDH matches RFC 7748 vector"
      , ok := (match x25519Shared (hexToBytes x25519_priv) (hexToBytes x25519_peer) with
               | some s => bytesEq s (hexToBytes x25519_out) | none => false) }
    , { name := "X25519 public key is 32 bytes"
      , ok := (x25519Public (hexToBytes x25519_priv)).size == 32 }
    , { name := "ChaCha20-Poly1305 seal/open round-trips"
      , ok := (match opened with | some p => bytesEq p pt | none => false) }
    , { name := "ChaCha20-Poly1305 rejects a tampered ciphertext"
      , ok := tampered.isNone }
    , { name := "ChaCha20-Poly1305 output is plaintext+16 (tag) bytes"
      , ok := sealed.size == pt.size + 16 }
    , { name := "HKDF-Extract(SHA-256) matches RFC 5869 TC1"
      , ok := bytesEq (hkdfExtract256 (hexToBytes "000102030405060708090a0b0c") (rep 22 0x0b))
                      (hexToBytes hkdf_prk) }
    , { name := "HKDF-Expand(SHA-256) matches RFC 5869 TC1"
      , ok := bytesEq (hkdfExpand256 (hexToBytes hkdf_prk) (hexToBytes "f0f1f2f3f4f5f6f7f8f9") 42)
                      (hexToBytes hkdf_okm) }
    , { name := "HMAC-SHA256 matches RFC 4231 TC1"
      , ok := bytesEq (hmac256 (rep 20 0x0b) "Hi There".toUTF8) (hexToBytes hmac_tc1) }
    , { name := "Ed25519 sign/verify round-trips"
      , ok := edOk }
    , { name := "Ed25519 rejects a signature over a different message"
      , ok := !edBad }
    , { name := "OS CSPRNG returns the requested length"
      , ok := r1.size == 32 ∧ r2.size == 32 }
    , { name := "OS CSPRNG is non-constant across calls"
      , ok := !bytesEq r1 r2 }
    ]

  let mut failures := 0
  IO.println "kroopt v0.3 native HACL* crypto KATs (through Lean FFI):"
  for c in checks do
    if c.ok then IO.println s!"  PASS  {c.name}"
    else IO.println s!"  FAIL  {c.name}"; failures := failures + 1
  if failures == 0 then
    IO.println s!"\nAll {checks.length} checks passed."
    return 0
  else
    IO.println s!"\n{failures} of {checks.length} checks FAILED."
    return 1

end Tests.Hacl

def main : IO UInt32 := Tests.Hacl.main
