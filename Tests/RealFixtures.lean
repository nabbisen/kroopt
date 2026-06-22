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

end Tests.RealFixtures
