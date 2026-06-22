import Kroopt.Crypto.Hacl

/-!
# Kroopt.Crypto.CertLint

Certificate / private-key **compatibility lint** (RFC 011 §11.2, RFC 012). At config load a server
should catch a leaf certificate whose public key does not match the configured private key — a common
deployment slip (the wrong key file) that would otherwise surface only mid-handshake as a
CertificateVerify the peer rejects, or worse, silently present a certificate the server cannot prove
possession of. This is a config **lint**, not peer-certificate path validation: no trust anchors,
expiry, name, or revocation checks (those belong to the deferred client/mTLS RFC).

The check extracts the leaf SubjectPublicKeyInfo key directly from the DER by anchoring on the
algorithm's fixed SPKI header (Ed25519 per RFC 8410 §10.1; EC P-256 per RFC 5480), then compares it
to the public key derived from the private key via HACL*. It is **TESTED, not PROVEN**: it lives in
the crypto trusted zone and calls FFI derivation, so it carries no proof obligation and the verified
core never depends on it.
-/

namespace Kroopt.Crypto.CertLint

private def baEq (a b : ByteArray) : Bool := a.toList == b.toList

/-- Does `needle` occur in `hay` exactly at `off`? Bounded byte compare; callers guarantee the
window is in bounds, and `get!` is in any case total. -/
private def matchAt (hay needle : ByteArray) (off : Nat) : Bool :=
  (List.range needle.size).all (fun k => hay.get! (off + k) == needle.get! k)

private def findSubAux (hay needle : ByteArray) (off fuel : Nat) : Option Nat :=
  match fuel with
  | 0 => none
  | fuel + 1 =>
    if off + needle.size > hay.size then none
    else if matchAt hay needle off then some off
    else findSubAux hay needle (off + 1) fuel

/-- First index at which `needle` occurs in `hay`, if any. Bounded linear scan; the fuel
(`hay.size + 1`) bounds the walk regardless of input. -/
def findSub (hay needle : ByteArray) : Option Nat := findSubAux hay needle 0 (hay.size + 1)

/-- Ed25519 SPKI header (RFC 8410 §10.1): `SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING }` up
to and including the `00` unused-bits octet. The raw 32-byte public key follows. -/
def ed25519SpkiHeader : ByteArray :=
  ByteArray.mk #[0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x03,0x21,0x00]

/-- EC P-256 namedCurve OID (`1.2.840.10045.3.1.7`) + BIT STRING header (RFC 5480): the 65-byte
uncompressed point `04‖X‖Y` follows. -/
def ecP256PointHeader : ByteArray :=
  ByteArray.mk #[0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07,0x03,0x42,0x00]

/-- The leaf's Ed25519 public key (32 bytes), extracted from its DER SubjectPublicKeyInfo. -/
def leafEd25519Pub (certDer : ByteArray) : Option ByteArray :=
  (findSub certDer ed25519SpkiHeader).bind fun i =>
    let start := i + ed25519SpkiHeader.size
    if start + 32 ≤ certDer.size then some (certDer.extract start (start + 32)) else none

/-- The leaf's EC P-256 public point (65 bytes, uncompressed), extracted from its DER SPKI. -/
def leafEcP256Pub (certDer : ByteArray) : Option ByteArray :=
  (findSub certDer ecP256PointHeader).bind fun i =>
    let start := i + ecP256PointHeader.size
    if start + 65 ≤ certDer.size then some (certDer.extract start (start + 65)) else none

/-- Lint: the leaf Ed25519 certificate's public key matches the key derived from `seed`. `false` if
the leaf is not an Ed25519 certificate or the keys differ. -/
def ed25519KeyMatches (certDer seed : ByteArray) : Bool :=
  match leafEd25519Pub certDer with
  | some pub => baEq pub (Kroopt.Crypto.Hacl.ed25519Public seed)
  | none     => false

/-- Lint: the leaf EC P-256 certificate's public point matches the point derived from `scalar`.
`false` if the leaf is not an EC P-256 certificate or the points differ. -/
def ecP256KeyMatches (certDer scalar : ByteArray) : Bool :=
  match leafEcP256Pub certDer with
  | some pt => baEq pt (Kroopt.Crypto.Hacl.p256Public scalar)
  | none    => false

/-! ## RSA leaf lint

Unlike Ed25519/EC P-256, an RSA SubjectPublicKeyInfo wraps a `RSAPublicKey ::= SEQUENCE { modulus
INTEGER, publicExponent INTEGER }` whose modulus length varies with key size, so a fixed-header
anchor isn't enough — the modulus and exponent INTEGERs need real DER length decoding. -/

private def expectTag (b : ByteArray) (pos : Nat) (tag : UInt8) : Bool :=
  decide (pos < b.size) && b.get! pos == tag

/-- Read a DER length octet group at `pos`: returns `(length, nextPos)` where `nextPos` is just past
the length octets. Short form (`< 0x80`) and long form up to four length octets; `none` otherwise. -/
def readLen (b : ByteArray) (pos : Nat) : Option (Nat × Nat) :=
  if decide (pos < b.size) then
    let first := (b.get! pos).toNat
    if first < 0x80 then some (first, pos + 1)
    else
      let nbytes := first - 0x80
      if nbytes == 0 || nbytes > 4 || decide (pos + 1 + nbytes > b.size) then none
      else some ((List.range nbytes).foldl (fun acc k => acc * 256 + (b.get! (pos + 1 + k)).toNat) 0,
                 pos + 1 + nbytes)
  else none

/-- Read a DER INTEGER at `pos` (tag `0x02`): returns its raw content bytes and the next position.
Leading-zero normalization is left to the caller. -/
def readInteger (b : ByteArray) (pos : Nat) : Option (ByteArray × Nat) :=
  if expectTag b pos 0x02 then
    (readLen b (pos + 1)).bind fun (len, vstart) =>
      if decide (vstart + len ≤ b.size) then some (b.extract vstart (vstart + len), vstart + len)
      else none
  else none

private def stripZerosAux (b : ByteArray) (i fuel : Nat) : ByteArray :=
  match fuel with
  | 0 => b.extract i b.size
  | fuel + 1 => if decide (i < b.size) && b.get! i == 0 then stripZerosAux b (i + 1) fuel
                else b.extract i b.size

/-- Drop leading `0x00` octets — normalizes the DER positive-integer padding so a stored raw modulus
and the cert's `00`-prefixed modulus INTEGER compare equal. -/
def stripZeros (b : ByteArray) : ByteArray := stripZerosAux b 0 b.size

/-- rsaEncryption AlgorithmIdentifier (OID 1.2.840.113549.1.1.1 + NULL params), RFC 8017; the
BIT STRING wrapping the `RSAPublicKey` SEQUENCE follows. -/
def rsaAlgIdHeader : ByteArray :=
  ByteArray.mk #[0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,0x05,0x00]

/-- The leaf's RSA `(modulus, publicExponent)`, extracted from its DER SPKI by anchoring on the
rsaEncryption AlgId, stepping over the BIT STRING and `RSAPublicKey` SEQUENCE, then reading the two
INTEGERs. Bytes are returned raw (callers normalize leading zeros). -/
def leafRsaPub (certDer : ByteArray) : Option (ByteArray × ByteArray) :=
  (findSub certDer rsaAlgIdHeader).bind fun i =>
    let p0 := i + rsaAlgIdHeader.size                 -- BIT STRING tag
    if expectTag certDer p0 0x03 then
      (readLen certDer (p0 + 1)).bind fun (_, p1) =>
        let p2 := p1 + 1                              -- skip the unused-bits octet (00)
        if expectTag certDer p2 0x30 then             -- RSAPublicKey SEQUENCE
          (readLen certDer (p2 + 1)).bind fun (_, p3) =>
            (readInteger certDer p3).bind fun (modulus, p4) =>
              (readInteger certDer p4).bind fun (exponent, _) =>
                some (modulus, exponent)
        else none
    else none

/-- Lint: the leaf RSA certificate's `(modulus, exponent)` match the configured `(n, e)`. `false` if
the leaf is not an RSA certificate or either component differs. Leading-zero–normalized so DER
padding doesn't cause a spurious mismatch. -/
def rsaKeyMatches (certDer n e : ByteArray) : Bool :=
  match leafRsaPub certDer with
  | some (modulus, exponent) =>
      baEq (stripZeros modulus) (stripZeros n) && baEq (stripZeros exponent) (stripZeros e)
  | none => false

end Kroopt.Crypto.CertLint
