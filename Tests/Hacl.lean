import Kroopt.Crypto.Hacl

/-!
# Tests.Hacl

Known-answer tests for the v0.3 native crypto binding, run **through Lean** over
the FFI into the vendored HACL* primitives. Vectors are from the relevant RFCs
(FIPS 180-4, RFC 7748, RFC 5869, RFC 4231) plus AEAD/signature round-trips with
tamper rejection. A green run proves the native crypto path works end-to-end in
the Lean build, not just in standalone C.

Vector-provenance discipline (see docs/src/crypto/postmortem-ed25519.md): every published
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
-- rather than localised into the primitive (see docs/src/crypto/postmortem-ed25519.md).
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
def hmac384_tc1 := "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"

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
  -- RFC 037 §2: a malformed-length call must be rejected before the HACL call,
  -- never truncated. With a wrong-size key or nonce the open fails closed (none).
  let wrongKeyOpen := chachaPolyOpen (rep 31 0x2b) nonce aad sealed
  let wrongNonceOpen := chachaPolyOpen key (rep 11 0x07) aad sealed
  -- Ed25519 round-trip (self-consistency — NOT a published vector; arbitrary key.
  -- The published RFC 8032 §7.1 Test 1 KAT lives in kroopt-provision-test via
  -- Tests/Vectors/Ed25519Rfc8032.lean.)
  let edPriv := rep 32 0x11
  let edPub := ed25519Public edPriv
  let msg := hexToBytes "deadbeef"
  let sig := ed25519Sign edPriv msg
  let edOk := ed25519Verify edPub msg sig
  let edBad := ed25519Verify edPub (hexToBytes "deadbe00") sig
  -- RFC 037 §2 length contracts on the remaining failure-channel primitives:
  -- X25519 rejects a non-32-byte scalar (none); Ed25519 verify rejects a wrong-size
  -- public key or signature (invalid), all before the HACL call.
  let x25519BadPriv := x25519Shared (rep 31 0x01) (hexToBytes x25519_peer)
  let x25519BadPeer := x25519Shared (hexToBytes x25519_priv) (rep 33 0x02)
  let edBadPubLen := ed25519Verify (rep 31 0x11) msg sig
  let edBadSigLen := ed25519Verify edPub msg (rep 63 0x00)
  -- RFC 037 §2 on the no-failure-channel primitives: a length violation yields the empty
  -- (zero-length) fail-closed sentinel, consistent with the CSPRNG convention.
  let sealBadKey := chachaPolySeal (rep 31 0x2b) nonce aad pt
  let sealBadNonce := chachaPolySeal key (rep 11 0x07) aad pt
  let signBadPriv := ed25519Sign (rep 31 0x11) msg
  let edPubBadPriv := ed25519Public (rep 31 0x11)
  let x25519PubBadPriv := x25519Public (rep 33 0x01)
  -- random
  let r1 ← (do match ← randomBytes 32 with | .bytes b => pure b | .error _ => pure ByteArray.empty)
  let r2 ← (do match ← randomBytes 32 with | .bytes b => pure b | .error _ => pure ByteArray.empty)

  -- P-256 (secp256r1) ECDH — NIST CAVP KAS ECC-CDH primitive vector (curve P-256, first row).
  -- Our private d, peer public 0x04||QCAVSx||QCAVSy, expected shared X-coordinate Z.
  let p256_d    := "7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534"
  let p256_qx   := "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287"
  let p256_qy   := "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac"
  let p256_z    := "46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b"
  let p256Peer  := (hexToBytes "04") ++ hexToBytes p256_qx ++ hexToBytes p256_qy
  let p256Kat   := p256Shared (hexToBytes p256_d) p256Peer
  -- DH self-consistency: pubA = d·G, pubB = e·G, then d·pubB == e·pubA (e = scalar 2).
  let p256PrivB := rep 31 0x00 |>.push 0x02
  let p256PubA  := p256Public (hexToBytes p256_d)
  let p256PubB  := p256Public p256PrivB
  let p256ShAB  := p256Shared (hexToBytes p256_d) p256PubB
  let p256ShBA  := p256Shared p256PrivB p256PubA
  -- fail-closed (RFC 037 §2): wrong-size scalar / malformed peer point.
  let p256BadPriv := p256Shared (rep 31 0x01) p256Peer
  let p256BadPeer := p256Shared (hexToBytes p256_d) (rep 65 0x05)   -- first byte ≠ 0x04
  -- RFC 039 §8.12: a 65-byte, 0x04-prefixed, but off-curve point. Shape passes; the on-curve
  -- check inside Hacl_P256_ecp256dh_r must reject it (fail-closed `none`, no fabricated secret).
  let p256OffCurve := p256Shared (hexToBytes p256_d) ((ByteArray.mk #[0x04]) ++ rep 32 0x01 ++ rep 32 0x01)
  let p256PubBad  := p256Public (rep 31 0x01)

  -- ECDSA P-256 / SHA-256 — NIST CAVP 186-4 ECDSA SigGen, P-256/SHA-256, first vector
  -- (fixed nonce k, so the signature is a known answer).
  let ec_msg := hexToBytes ("5905238877c77421f73e43ee3da6f2d9e2ccad5fc942dcec0cbd25482935faaf" ++
    "416983fe165b1a045ee2bcd2e6dca3bdf46c4310a7461f9a37960ca672d3feb5" ++
    "473e253605fb1ddfd28065b53cb5858a8ad28175bf9bd386a5e471ea7a65c17c" ++
    "c934a9d791e91491eb3754d03799790fe2d308d16146d5c9b0d0debd97d79ce8")
  let ec_d  := "519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464"
  let ec_qx := "1ccbe91c075fc7f4f033bfa248db8fccd3565de94bbfb12f3c59ff46c271bf83"
  let ec_qy := "ce4014c68811f9a21a1fdb2c0e6113e06db7ca93b7404e78dc7ccd5ca89a4ca9"
  let ec_k  := "94a1bbb14b906a61a280f245f9e93c7f3b4a6247824f5d33b9670787642a68de"
  let ec_r  := "f3ac8061b514795b8843e3d6629527ed2afd6b1f6a555a7acabb5e6f79c8c2ac"
  let ec_s  := "8bf77819ca05a6b2786c76262bf7371cef97b218e96f175a3ccdda2acc058903"
  let ec_pub  := (hexToBytes "04") ++ hexToBytes ec_qx ++ hexToBytes ec_qy
  let ec_sigRaw := ecdsaP256SignRaw ec_msg (hexToBytes ec_d) (hexToBytes ec_k)
  let ec_expRaw := hexToBytes ec_r ++ hexToBytes ec_s
  let ec_der  := ecdsaP256SignDer ec_msg (hexToBytes ec_d) (hexToBytes ec_k)
  let ec_verifyOk := ecdsaP256Verify ec_msg ec_pub ec_expRaw
  let ec_verifyTampered := ecdsaP256Verify (ec_msg.push 0x00) ec_pub ec_expRaw
  let ec_signBadK := ecdsaP256SignRaw ec_msg (hexToBytes ec_d) (rep 31 0x01)
  -- DER well-formedness: SEQUENCE of two INTEGERs.
  let ec_derOk := match ec_der with
    | some d => d.size ≥ 8 ∧ d.get! 0 == 0x30 ∧ d.get! 2 == 0x02
    | none   => false

  -- RSA-PSS / SHA-256 sign→verify round-trip. PSS is randomized through the salt, so a self-
  -- consistency round-trip (HACL sign then HACL verify) is the known-answer for the binding; the
  -- key is a generated RSA-2048 keypair. TLS 1.3 uses saltLen = hashLen = 32 (RFC 8446 §4.2.3).
  let rsa_n := hexToBytes ("a3b6d19ae4dfaab4fecb2a0206d694dd6dcd9158481a3019460cecf4092af4f06" ++
    "f0f31ffc15c1fa2becd39e586ce04acc7ce9058ddf74a6a1c95608a6d36e04d6" ++
    "d2d5af937ab2911f5106d5a7be177ec273b61903493e7035ce93428d000f06c1" ++
    "06623b3839e109b9ba548c2381e86745cce660d25d7452c37445d947a0ff0a50" ++
    "c722e7c56439254258f19c12e696af1c603f2e51e947ffb05dcbf55391758a22" ++
    "02bc4e88168cc718f7ad41901acc1cc0d447fb3b5f9f1066036ec0bb6ec258a9" ++
    "8521e1a14a6beadb5f45a06d81e848e76d9853f2c925a3bd9898da47d6249160" ++
    "c8317936fc986f914a1e5a9f41c89837169cd5169a0f901b7abc223eb619f6d")
  let rsa_e := hexToBytes "010001"
  let rsa_d := hexToBytes ("0a3d2d42cbf015fa4b20641efeba7db8f9f645c53c19fd9750a9dbe32f5accd2" ++
    "e7f2755812bcffd8b7dbcb9ac887f79d485d035151ed5d07485190f2f0fdaed4" ++
    "02713823c0772792d123b0acc2db7c4dc9218e04200c18023e3c25f9c5def5f7" ++
    "390a8a4eab7b72e275585fcf5c38c2ea61c1eee0ce07dd0c0e7d9ee7e1f272dd" ++
    "ffaf7594ad4bc7cfdac41d9785a22c4869d766419349c99b64003eb4e56dd8bb" ++
    "98dcefb7f16f196322c8e2fd01e88fe327f093631afba73ac1cdeb7bb59929c2" ++
    "5a1662f199609763a6b21377a483e0cbcc88916e8dd11a1883b3ef2f935cdaaf" ++
    "021e17cd7f3eba28b254081a32083fe1ef45e48e1fd8b89e4cbbffb477b46ce9")
  let rsa_salt := rep 32 0x5a
  let rsa_msg := hexToBytes "deadbeefcafe"
  let rsa_sig := rsapssSign rsa_n rsa_e rsa_d rsa_salt rsa_msg
  let rsa_sigSized := match rsa_sig with | some s => s.size == 256 | none => false
  let rsa_verifyOk := match rsa_sig with
    | some s => rsapssVerify rsa_n rsa_e 32 s rsa_msg | none => false
  let rsa_verifyTampered := match rsa_sig with
    | some s => rsapssVerify rsa_n rsa_e 32 s (rsa_msg.push 0x00) | none => false
  let rsa_signBadKey := rsapssSignRaw ByteArray.empty rsa_e rsa_d rsa_salt rsa_msg

  -- AES-GCM (HACL*/EverCrypt Vale verified assembly), NIST GCM Test Case 4.
  let aes_iv   := hexToBytes "cafebabefacedbaddecaf888"
  let aes_aad  := hexToBytes "feedfacedeadbeeffeedfacedeadbeefabaddad2"
  let aes_pt   := hexToBytes ("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72" ++
                              "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
  let aes128_key := hexToBytes "feffe9928665731c6d6a8f9467308308"
  let aes128_exp := hexToBytes ("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e" ++
                                "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091" ++
                                "5bc94fbc3221a5db94fae95ae7121a47")           -- ciphertext ++ tag
  let aes128_sealed := aes128GcmSeal aes128_key aes_iv aes_aad aes_pt
  let aes128_opened := aes128GcmOpen aes128_key aes_iv aes_aad aes128_sealed
  let aes128_tamper := aes128GcmOpen aes128_key aes_iv aes_aad
                         (aes128_sealed.set! 0 ((aes128_sealed.get! 0) ^^^ 1))
  let aes128_badKey := aes128GcmOpen (rep 15 0x00) aes_iv aes_aad aes128_sealed
  let aes256_key := hexToBytes "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"
  let aes256_exp := hexToBytes ("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa" ++
                                "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662" ++
                                "76fc6ece0f4e1768cddf8853bb2d551b")           -- ciphertext ++ tag
  let aes256_sealed := aes256GcmSeal aes256_key aes_iv aes_aad aes_pt
  let aes256_opened := aes256GcmOpen aes256_key aes_iv aes_aad aes256_sealed
  let aes256_tamper := aes256GcmOpen aes256_key aes_iv aes_aad
                         (aes256_sealed.set! 0 ((aes256_sealed.get! 0) ^^^ 1))
  let aes256_badKey := aes256GcmOpen (rep 31 0x00) aes_iv aes_aad aes256_sealed

  -- SHA-384 HKDF/HMAC. RFC 4231 TC1 anchors the HMAC-SHA384 primitive; HACL ships no SHA-384 HKDF,
  -- so kroopt builds it on that primitive (RFC 5869) and we verify the construction against it:
  -- Extract is one HMAC; Expand is iterated HMAC with T(i) = HMAC(PRK, T(i-1) || info || i).
  let h384_salt := hexToBytes "000102030405060708090a0b0c"
  let h384_ikm  := rep 22 0x0b
  let h384_prk  := hkdfExtract384 h384_salt h384_ikm
  let h384_info := hexToBytes "f0f1f2f3f4f5f6f7f8f9"
  let h384_T1   := hmac384 h384_prk (h384_info ++ ByteArray.mk #[(0x01 : UInt8)])
  let h384_T2   := hmac384 h384_prk (h384_T1 ++ h384_info ++ ByteArray.mk #[(0x02 : UInt8)])
  let h384_exp48 := hkdfExpand384 h384_prk h384_info 48
  let h384_exp80 := hkdfExpand384 h384_prk h384_info 80

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
    , { name := "P-256 ECDH matches NIST CAVP ECC-CDH P-256 vector"
      , ok := (match p256Kat with | some s => bytesEq s (hexToBytes p256_z) | none => false) }
    , { name := "P-256 public key is the 65-byte uncompressed point 0x04||X||Y"
      , ok := p256PubA.size == 65 ∧ p256PubA.get! 0 == 0x04 }
    , { name := "P-256 ECDH is symmetric (d·(e·G) == e·(d·G)), self-consistency"
      , ok := (match p256ShAB, p256ShBA with
               | some a, some b => bytesEq a b | _, _ => false) }
    , { name := "P-256 ECDH rejects a wrong-size scalar, fails closed (RFC 037 §2)"
      , ok := p256BadPriv.isNone }
    , { name := "P-256 ECDH rejects a malformed peer point, fails closed (RFC 037 §2)"
      , ok := p256BadPeer.isNone }
    , { name := "P-256 ECDH rejects an off-curve 0x04-prefixed point, fails closed (RFC 039 §8.12)"
      , ok := p256OffCurve.isNone }
    , { name := "P-256 public derivation rejects a wrong-size scalar (RFC 037 §2)"
      , ok := p256PubBad.size == 0 }
    , { name := "ECDSA P-256/SHA-256 sign matches NIST CAVP 186-4 SigGen vector (fixed k)"
      , ok := ec_sigRaw.size == 65 ∧ ec_sigRaw.get! 0 == 0 ∧ bytesEq (ec_sigRaw.extract 1 65) ec_expRaw }
    , { name := "ECDSA P-256/SHA-256 verify accepts the NIST signature"
      , ok := ec_verifyOk }
    , { name := "ECDSA P-256/SHA-256 verify rejects a tampered message"
      , ok := !ec_verifyTampered }
    , { name := "ECDSA signature DER-encodes as SEQUENCE of two INTEGERs (RFC 8446 §4.4.3)"
      , ok := ec_derOk }
    , { name := "ECDSA P-256 sign rejects a wrong-size nonce, fails closed (RFC 037 §2)"
      , ok := ec_signBadK.size == 65 ∧ ec_signBadK.get! 0 == 1 }
    , { name := "RSA-PSS/SHA-256 sign produces a 256-byte signature (RSA-2048)"
      , ok := rsa_sigSized }
    , { name := "RSA-PSS/SHA-256 verify accepts the signature (sign→verify round-trip)"
      , ok := rsa_verifyOk }
    , { name := "RSA-PSS/SHA-256 verify rejects a tampered message"
      , ok := !rsa_verifyTampered }
    , { name := "RSA-PSS sign rejects empty key material, fails closed (RFC 037 §2)"
      , ok := rsa_signBadKey.size == 1 ∧ rsa_signBadKey.get! 0 == 1 }
    , { name := "ChaCha20-Poly1305 seal/open round-trips"
      , ok := (match opened with | some p => bytesEq p pt | none => false) }
    , { name := "ChaCha20-Poly1305 rejects a tampered ciphertext"
      , ok := tampered.isNone }
    , { name := "ChaCha20-Poly1305 open rejects a wrong-size key, fails closed (RFC 037 §2)"
      , ok := wrongKeyOpen.isNone }
    , { name := "ChaCha20-Poly1305 open rejects a wrong-size nonce, fails closed (RFC 037 §2)"
      , ok := wrongNonceOpen.isNone }
    , { name := "X25519 rejects a wrong-size private scalar, fails closed (RFC 037 §2)"
      , ok := x25519BadPriv.isNone }
    , { name := "X25519 rejects a wrong-size peer point, fails closed (RFC 037 §2)"
      , ok := x25519BadPeer.isNone }
    , { name := "Ed25519 verify rejects a wrong-size public key (RFC 037 §2)"
      , ok := !edBadPubLen }
    , { name := "Ed25519 verify rejects a wrong-size signature (RFC 037 §2)"
      , ok := !edBadSigLen }
    , { name := "ChaCha20-Poly1305 seal rejects a wrong-size key, empty result (RFC 037 §2)"
      , ok := sealBadKey.size == 0 }
    , { name := "ChaCha20-Poly1305 seal rejects a wrong-size nonce, empty result (RFC 037 §2)"
      , ok := sealBadNonce.size == 0 }
    , { name := "Ed25519 sign rejects a wrong-size private key, empty result (RFC 037 §2)"
      , ok := signBadPriv.size == 0 }
    , { name := "Ed25519 public derivation rejects a wrong-size private key (RFC 037 §2)"
      , ok := edPubBadPriv.size == 0 }
    , { name := "X25519 public derivation rejects a wrong-size private key (RFC 037 §2)"
      , ok := x25519PubBadPriv.size == 0 }
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
    , { name := "HMAC-SHA384 matches RFC 4231 TC1"
      , ok := bytesEq (hmac384 (rep 20 0x0b) "Hi There".toUTF8) (hexToBytes hmac384_tc1) }
    , { name := "HKDF-Extract-SHA384 is HMAC-SHA384(salt, IKM) (RFC 5869)"
      , ok := bytesEq h384_prk (hmac384 h384_salt h384_ikm) }
    , { name := "HKDF-Expand-SHA384 first block is HMAC(PRK, info || 0x01) (RFC 5869)"
      , ok := bytesEq h384_exp48 h384_T1 }
    , { name := "HKDF-Expand-SHA384 chains T(2) = HMAC(PRK, T1 || info || 0x02)"
      , ok := bytesEq (h384_exp80.extract 48 80) (h384_T2.extract 0 32) }
    , { name := "HKDF-Expand-SHA384 returns the requested output length"
      , ok := h384_exp48.size == 48 ∧ h384_exp80.size == 80 }
    , { name := "Ed25519 sign/verify round-trips"
      , ok := edOk }
    , { name := "Ed25519 rejects a signature over a different message"
      , ok := !edBad }
    , { name := "OS CSPRNG returns the requested length"
      , ok := r1.size == 32 ∧ r2.size == 32 }
    , { name := "OS CSPRNG is non-constant across calls"
      , ok := !bytesEq r1 r2 }
    , { name := "AES-128-GCM seal matches NIST GCM Test Case 4 (ciphertext ++ tag)"
      , ok := bytesEq aes128_sealed aes128_exp }
    , { name := "AES-128-GCM seal/open round-trips"
      , ok := (match aes128_opened with | some p => bytesEq p aes_pt | none => false) }
    , { name := "AES-128-GCM rejects a tampered ciphertext, fails closed"
      , ok := aes128_tamper.isNone }
    , { name := "AES-128-GCM open rejects a wrong-size key, fails closed (RFC 037 §2)"
      , ok := aes128_badKey.isNone }
    , { name := "AES-128-GCM output is plaintext+16 (tag) bytes"
      , ok := aes128_sealed.size == aes_pt.size + 16 }
    , { name := "AES-256-GCM seal matches NIST GCM Test Case 4 (ciphertext ++ tag)"
      , ok := bytesEq aes256_sealed aes256_exp }
    , { name := "AES-256-GCM seal/open round-trips"
      , ok := (match aes256_opened with | some p => bytesEq p aes_pt | none => false) }
    , { name := "AES-256-GCM rejects a tampered ciphertext, fails closed"
      , ok := aes256_tamper.isNone }
    , { name := "AES-256-GCM open rejects a wrong-size key, fails closed (RFC 037 §2)"
      , ok := aes256_badKey.isNone }
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
