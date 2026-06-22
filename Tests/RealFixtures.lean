import Kroopt.Parse.Wire
import Kroopt.Crypto.RealProvider
import Kroopt.Core.Config

/-! # Tests.RealFixtures

Shared, real (non-fake) handshake test fixtures: a valid x25519 client share, server ECDHE
private, a 32-byte ServerHello Random, an Ed25519 certificate key, an OpenSSL-parseable Ed25519
X.509 certificate, the matching `RealCryptoConfig`, and a custom ClientHello. Used by both the
production-interpreter correspondence tests and any remaining real-handshake checks, so the
fixtures live in exactly one place (RFC 031 §5 — no duplicated assembly). No driver, no `main`. -/

namespace Tests.RealFixtures

open Kroopt.Parse Kroopt.Crypto

def hx (s : String) : ByteArray := Id.run do
  let cs := (s.toList.filter (fun (c : Char) => c ≠ ' ')).toArray
  let hv : Char → UInt8 := fun (c : Char) =>
    if '0' ≤ c ∧ c ≤ '9' then (c.toNat - '0'.toNat).toUInt8
    else if 'a' ≤ c ∧ c ≤ 'f' then (c.toNat - 'a'.toNat + 10).toUInt8 else 0
  let mut out : ByteArray := ByteArray.empty
  let mut i : Nat := 0
  while i + 1 < cs.size do
    out := out.push (hv cs[i]! * 16 + hv cs[i+1]!); i := i + 2
  return out

-- Real, valid x25519 client public (provenance: RFC 8448 §3 client key share).
def clientShare : ByteArray := hx "99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c"
-- Chosen server values (server ephemeral private from RFC 8448 §3; any random for SH).
def serverPriv   : ByteArray := hx "b1580eeadf6dd589b8ef4f2d5652578cc810e9980191ec8d058308cea216a21e"
-- A 32-byte server Random (RFC 8446 §4.1.3 requires exactly 32). The first 28 bytes are the
-- RFC 8448 §3 example value; the final 4 are test padding — the Random is a nonce with no
-- known-answer dependence here, so its exact bytes are irrelevant to the derived secrets.
def serverRandom : ByteArray :=
  hx "a6af06a412186024" |>.append (hx "9cd34c95930c8ac5cb1434dac155772ed3e26928")
                        |>.append (hx "00000000")
-- kroopt's Ed25519 certificate key (provenance: RFC 8032 §7.1 Test 1).
def certSeed : ByteArray := hx "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
def certPub  : ByteArray := hx "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
-- A real, OpenSSL-parseable self-signed Ed25519 X.509 certificate whose subject
-- public key is kroopt's certificate key (CN=kroopt.test, 100-year validity).
-- Generated from the cert seed by `scripts/gen-test-cert.sh`.
def certDer : ByteArray := hx
  "3082015b3082010da003020102021409cf89b7545d532c3c9b338845e68dd9f2dd9208300506032b657030163114301206035504030c0b6b726f6f70742e746573743020170d3236303631323034323730335a180f32313236303531393034323730335a30163114301206035504030c0b6b726f6f70742e74657374302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511aa36b3069301d0603551d0e041604145b27aa5589179770e47575b162a1ded97b8bfc6d301f0603551d230418301680145b27aa5589179770e47575b162a1ded97b8bfc6d300f0603551d130101ff040530030101ff30160603551d11040f300d820b6b726f6f70742e74657374300506032b6570034100afb247f952fd77d308bb94d2b703b5ad82882f4a6a40dd2a4974c97cea7239de64fb60ad6bfc42d0a48101eea1bb921a1d7aa18081e6a1945935d60384501903"

def cfg : RealCryptoConfig :=
  { ephemeralPrivate := serverPriv, certPrivate := certSeed, certPublic := certPub }

/-- A custom ClientHello (offers x25519 key_share, ed25519 sig_alg, TLS 1.3). -/
def clientHelloMsg : ByteArray :=
  let random : ByteArray := ByteArray.mk (Array.mkArray 32 (0xAB : UInt8))
  let suites : ByteArray := hx "13 01 13 03"
  let supVer : ByteArray := hx "00 2b 00 03 02 03 04"
  let supGrp : ByteArray := hx "00 0a 00 04 00 02 00 1d"
  let sigAlg : ByteArray := hx "00 0d 00 04 00 02 08 07"
  let ks     : ByteArray := Wire.extension 0x0033 (Wire.u16Len (Wire.keyShareEntry 0x001d clientShare))
  let exts   : ByteArray := supVer ++ supGrp ++ sigAlg ++ ks
  let body   : ByteArray :=
    Wire.be16 0x0303 ++ random ++ Wire.u8Len ByteArray.empty
      ++ Wire.u16Len suites ++ Wire.u8Len (ByteArray.mk #[(0x00 : UInt8)])
      ++ Wire.u16Len exts
  Wire.handshake 0x01 body

/-- Wrap a handshake message in a TLS plaintext record (outer type 22). -/
def recordWrap (b : ByteArray) : ByteArray :=
  hx "16 03 01" ++ Wire.be16 b.size.toUInt16 ++ b

/-- A validated server config presenting the fixture Ed25519 leaf certificate (RFC 012). Its public
DER (`certDer`) goes on the wire and into the transcript; the matching private key is `certSeed`,
which the provider signs CertificateVerify with. With no SNI routes, every ClientHello resolves to
this default endpoint. -/
def realServerConfig : Kroopt.Core.ValidatedServerConfig :=
  { (default : Kroopt.Core.ValidatedServerConfig) with
    defaultEndpoint := some
      { (default : Kroopt.Core.EndpointConfig) with
        der := certDer, signatureSchemes := [.ed25519] } }

/-! ## Real-handshake driver -/

/-- ECDSA-P256 leaf certificate (self-signed, CN=localhost) and its matching 32-byte private
scalar. Generated with `openssl ecparam -name prime256v1`; the public point in `ecdsaCertDer`
corresponds to `ecdsaCertPriv`, so a CertificateVerify signed with the scalar verifies against the
presented certificate. Used to exercise the `ecdsa_secp256r1_sha256` server-auth path (RFC 8446
§4.4.3) on a live handshake. -/
def ecdsaCertDer : ByteArray := hx
  "3082017c30820123a00302010202142b751004ada14f953a316aee989a9c35dfeefe2b300a06082a8648ce3d04030230143112301006035504030c096c6f63616c686f7374301e170d3236303631333233333934375a170d3336303631303233333934375a30143112301006035504030c096c6f63616c686f73743059301306072a8648ce3d020106082a8648ce3d03010703420004491ec5a776a32887a9818fe9c3c20e92a91761bd55c12044af2bda154806b474e1bf87d1674931e412bb5ed7b27b15e20dd0954191e408c1b14b04a4257a5ab3a3533051301d0603551d0e041604148e173513e35fbba213fbb3778c72e70a36d6533f301f0603551d230418301680148e173513e35fbba213fbb3778c72e70a36d6533f300f0603551d130101ff040530030101ff300a06082a8648ce3d040302034700304402206affdcf883c80ab467667cec409dd8e269a697b8524c452a1751af7242fb7a0d022018bce5b678d658246c0cdf0942258d844fb689648f355fade906838b36506657"

def ecdsaCertPriv : ByteArray := hx
  "f08236ae80a9ab48cf2fdb6c3b85d4d9b106f7d484e0b0d2bb606b7354cd528d"

/-- Base crypto config for the ECDSA endpoint. `signNonce` is injected fresh per connection at the
IO layer; `ephemeralPrivate` is overridden per connection. -/
def ecdsaCfg : RealCryptoConfig :=
  { ephemeralPrivate := serverPriv, certPrivate := ecdsaCertPriv, certPublic := ByteArray.empty }

/-- A validated server config presenting the ECDSA-P256 leaf. The endpoint advertises
`ecdsaSecp256r1Sha256` only, so the core selects ECDSA when the client offers it (RFC 8446 §4.2.3). -/
def ecdsaServerConfig : Kroopt.Core.ValidatedServerConfig :=
  { (default : Kroopt.Core.ValidatedServerConfig) with
    defaultEndpoint := some
      { (default : Kroopt.Core.EndpointConfig) with
        der := ecdsaCertDer, signatureSchemes := [.ecdsaSecp256r1Sha256] } }

/-- RSA-2048 leaf certificate (self-signed, CN=localhost) and its matching private key components
`(n, e, d)`. The public modulus in `rsaCertDer` equals `rsaN`, so a CertificateVerify signed with
`(rsaN, rsaE, rsaD)` verifies against the presented certificate. Exercises the `rsa_pss_rsae_sha256`
server-auth path (RFC 8446 §4.2.3). -/
def rsaN : ByteArray := hx
  "a3b6d19ae4dfaab4fecb2a0206d694dd6dcd9158481a3019460cecf4092af4f06f0f31ffc15c1fa2becd39e586ce04acc7ce9058ddf74a6a1c95608a6d36e04d6d2d5af937ab2911f5106d5a7be177ec273b61903493e7035ce93428d000f06c106623b3839e109b9ba548c2381e86745cce660d25d7452c37445d947a0ff0a50c722e7c56439254258f19c12e696af1c603f2e51e947ffb05dcbf55391758a2202bc4e88168cc718f7ad41901acc1cc0d447fb3b5f9f1066036ec0bb6ec258a98521e1a14a6beadb5f45a06d81e848e76d9853f2c925a3bd9898da47d6249160c8317936fc986f914a1e5a9f41c89837169cd5169a0f901b7abc223eb619f6d"
def rsaE : ByteArray := hx "010001"
def rsaD : ByteArray := hx
  "0a3d2d42cbf015fa4b20641efeba7db8f9f645c53c19fd9750a9dbe32f5accd2e7f2755812bcffd8b7dbcb9ac887f79d485d035151ed5d07485190f2f0fdaed402713823c0772792d123b0acc2db7c4dc9218e04200c18023e3c25f9c5def5f7390a8a4eab7b72e275585fcf5c38c2ea61c1eee0ce07dd0c0e7d9ee7e1f272ddffaf7594ad4bc7cfdac41d9785a22c4869d766419349c99b64003eb4e56dd8bb98dcefb7f16f196322c8e2fd01e88fe327f093631afba73ac1cdeb7bb59929c25a1662f199609763a6b21377a483e0cbcc88916e8dd11a1883b3ef2f935cdaaf021e17cd7f3eba28b254081a32083fe1ef45e48e1fd8b89e4cbbffb477b46ce9"
def rsaCertDer : ByteArray := hx
  "30820309308201f1a00302010202143966910821d5b1c9757c91384fe47156e7f9aa38300d06092a864886f70d01010b050030143112301006035504030c096c6f63616c686f7374301e170d3236303631343030323130325a170d3336303631313030323130325a30143112301006035504030c096c6f63616c686f737430820122300d06092a864886f70d01010105000382010f003082010a0282010100a3b6d19ae4dfaab4fecb2a0206d694dd6dcd9158481a3019460cecf4092af4f06f0f31ffc15c1fa2becd39e586ce04acc7ce9058ddf74a6a1c95608a6d36e04d6d2d5af937ab2911f5106d5a7be177ec273b61903493e7035ce93428d000f06c106623b3839e109b9ba548c2381e86745cce660d25d7452c37445d947a0ff0a50c722e7c56439254258f19c12e696af1c603f2e51e947ffb05dcbf55391758a2202bc4e88168cc718f7ad41901acc1cc0d447fb3b5f9f1066036ec0bb6ec258a98521e1a14a6beadb5f45a06d81e848e76d9853f2c925a3bd9898da47d6249160c8317936fc986f914a1e5a9f41c89837169cd5169a0f901b7abc223eb619f6d0203010001a3533051301d0603551d0e04160414e4b1bcc18e6a322c97ba4b8e463e76eb2c6780b5301f0603551d23041830168014e4b1bcc18e6a322c97ba4b8e463e76eb2c6780b5300f0603551d130101ff040530030101ff300d06092a864886f70d01010b0500038201010079b5634fc50693f9598a725eb22c8b9a861667302b343f42c8789c29370576766b0add125d1653ab50140fa26b9c6d827d5e56439d5f6caa1f6c3f8161381690d5546287f5c3117a3e043d3cc2a815e315351a966172176cf3b40c6a556f1724ae09b42679e72a92151937ed7d3fcad7975d49d05397f42dcfbd668d80c3f958b66e315d59f0cf7c97768a19c561fcfa410d0c0bfe6e47427fdbf792bfe0b5bb77d418c78b931859cc92d56bf4bf5ba4108880067f9480d1565073856a8e7531ca976ed344f27d3b9d7d1943302529ea417d034ebb975276cee622abcf4ee77954e257270824df6ba585ae8a94cfa70e53c8a8614a941b888d98157933959d33"

/-- Base crypto config for the RSA endpoint; `signNonce` (the per-connection PSS salt) is injected
fresh at the IO layer. -/
def rsaCfg : RealCryptoConfig :=
  { ephemeralPrivate := serverPriv, certPrivate := ByteArray.empty, certPublic := ByteArray.empty
    rsaN := rsaN, rsaE := rsaE, rsaD := rsaD }

end Tests.RealFixtures
