import Kroopt.Crypto.Hacl
import Kroopt.Crypto.Real
import Kroopt.Crypto.KeySchedule
import Kroopt.Core.Record
import Kroopt.Parse.Wire
import Kroopt.Error

/-!
# Kroopt.Conn.Record13 — real TLS 1.3 record protection (interpreter zone)

Turns a plaintext message plus its content type into a real `TLSCiphertext` record
on the wire, and back, using ChaCha20-Poly1305 (RFC 8446 §5.2). This is the framing
the AEAD primitives (`Kroopt.Crypto.Real`, `Hacl`) sit under: the inner plaintext
(`content || content_type || zero padding`), the additional_data (the TLSCiphertext
header `opaque_type(23) || legacy_version(0x0303) || length`), the per-record nonce
(`IV XOR seq`), and the outer record wrapping.

It lives in the impure `Conn` zone because it calls FFI crypto; the verified core
imports none of it. No plaintext escapes a failed open.
-/

namespace Kroopt.Conn.Record13

open Kroopt.Crypto
open Kroopt.Core (ContentType CipherSuite)
open Kroopt.Parse

/-- TLSInnerPlaintext (RFC 8446 §5.2): `content || content_type || zero*`. -/
def innerPlaintext (content : ByteArray) (ctype : ContentType) (pad : Nat) : ByteArray :=
  content ++ ByteArray.mk #[ctype.toByte] ++ ByteArray.mk (Array.mkArray pad (0x00 : UInt8))

/-- TLS 1.3 record additional_data (RFC 8446 §5.2): the TLSCiphertext header —
`opaque_type(23) || legacy_record_version(0x0303) || ciphertext_length`. -/
def recordAAD (ciphertextLen : Nat) : ByteArray :=
  ByteArray.mk #[(0x17 : UInt8), 0x03, 0x03] ++ Wire.be16 ciphertextLen.toUInt16

/-- The TLS 1.3 maximum `TLSPlaintext.fragment` length (RFC 8446 §5.1): 2^14 octets. -/
def maxRecordPlaintext : Nat := 16384

/-- Seal one record. RFC 037 §5: enforce the 2^14 content bound *before* sealing, rather
than letting an oversize length silently truncate through the `UInt16` record-length cast —
oversize input is rejected with a typed `resourceLimit` error so no caller (now or later) can
emit a malformed or truncated record. -/
def sealRecord (key iv : ByteArray) (seq : UInt64) (content : ByteArray)
    (ctype : ContentType) (pad : Nat := 0)
    (suite : CipherSuite := .chacha20Poly1305Sha256) : Except Kroopt.ResourceLimitError ByteArray :=
  if content.size > maxRecordPlaintext then .error .recordSize
  else
    let inner := innerPlaintext content ctype pad
    let ctLen := inner.size + 16                       -- + 16-byte AEAD tag (uniform across TLS 1.3 suites)
    let sealed := Real.aeadSealBySuite suite key (Real.nonce iv seq) (recordAAD ctLen) inner
    .ok (ByteArray.mk #[(0x17 : UInt8), 0x03, 0x03] ++ Wire.be16 ctLen.toUInt16 ++ sealed)

/-- Test/diagnostic convenience: seal a record whose content is known to be within the
2^14 bound, returning the bytes directly. Panics on oversize, so it is only for known-small
fixtures in tests — never the production path, which uses `sealRecord` and handles the error. -/
def sealRecord! (key iv : ByteArray) (seq : UInt64) (content : ByteArray)
    (ctype : ContentType) (pad : Nat := 0)
    (suite : CipherSuite := .chacha20Poly1305Sha256) : ByteArray :=
  (sealRecord key iv seq content ctype pad suite).toOption.get!

/-- Strip TLSInnerPlaintext zero padding: the last non-zero octet is the inner
content type; everything before it is the content. -/
def stripInner (inner : ByteArray) : Option (ByteArray × ContentType) := Id.run do
  let mut i := inner.size
  while i > 0 && inner.get! (i - 1) == 0 do
    i := i - 1
  if i == 0 then return none
  return some (inner.extract 0 (i - 1), ContentType.ofByte (inner.get! (i - 1)))

/-- Open a TLS 1.3 protected record: recompute the AAD from the header,
ChaCha20-Poly1305-open, then strip padding to recover `(content, inner type)`.
Returns `none` on any framing or authentication failure — no plaintext escapes. -/
def openRecord (key iv : ByteArray) (seq : UInt64) (record : ByteArray)
    (suite : CipherSuite := .chacha20Poly1305Sha256)
    : Option (ByteArray × ContentType) :=
  if record.size < 5 then none
  else if record.get! 0 != 0x17 then none
  else
    let ctLen := (record.get! 3).toNat * 256 + (record.get! 4).toNat
    if record.size != 5 + ctLen then none
    else
      match Real.aeadOpenBySuite suite key (Real.nonce iv seq) (record.extract 0 5) (record.extract 5 record.size) with
      | none => none
      | some inner => stripInner inner

end Kroopt.Conn.Record13
