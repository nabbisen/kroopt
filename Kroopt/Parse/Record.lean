import Kroopt.Parse.Reader
import Kroopt.Core.Record

/-!
# Kroopt.Parse.Record

Record-layer framing built on the bounds-safe `Reader` (RFC 004 §11). Pure: it
turns transport bytes into a validated record header and a protected-record
byte slice, and turns a decrypted buffer into a `TLSInnerPlaintext`. It performs
no crypto — sealing/opening are core actions (RFC 004 §6).

Everything here either succeeds with a validated value or fails with a typed
`ParseError`; oversize records are rejected at the header before any large
allocation (RFC 004 §12).
-/

namespace Kroopt.Parse

open Kroopt.Core
  (ContentType TLSInnerPlaintext maxCiphertextFragment maxPlaintextFragment)

/-- A validated record header: a five-byte prefix whose declared `length` has
already been checked against the maximum protected-record size (RFC 004 §5).
Holding one is evidence the length is in range. -/
structure ValidRecordHeader where
  outerType : ContentType
  legacyVersion : UInt16
  length : Nat
  lengthOk : length ≤ maxCiphertextFragment
  deriving Repr

/-- Parse a record header (RFC 8446 §5.1): one content-type byte, a two-byte
legacy version, and a two-byte length. The length is rejected if it exceeds the
maximum protected-record size, so an attacker cannot announce an oversize record
(RFC 004 §12). -/
def Reader.takeRecordHeader (r : Reader) :
    Except ParseError (ValidRecordHeader × Reader) :=
  match r.takeU8 with
  | .error e => .error e
  | .ok (tb, r1) =>
    match r1.takeU16 with
    | .error e => .error e
    | .ok (ver, r2) =>
      match r2.takeU16 with
      | .error e => .error e
      | .ok (len, r3) =>
        let lenNat := len.toNat
        if h : lenNat ≤ maxCiphertextFragment then
          .ok ({ outerType := ContentType.ofByte tb
                 legacyVersion := ver
                 length := lenNat
                 lengthOk := h }, r3)
        else
          .error (.lengthExceedsMax lenNat maxCiphertextFragment)

/-- Try to take a complete record (header + body) from the reader. Returns:
* `ok (none, r)` — not enough bytes are buffered yet; keep reading (RFC 004 §5.3);
* `ok (some (hdr, body), r')` — a full record was available and consumed;
* `error` — a malformed or oversize header.

The body is only read once its full declared length is present, so a partial
record never yields a partial value (RFC 004 §10). -/
def Reader.tryTakeRecord (r : Reader) :
    Except ParseError (Option (ValidRecordHeader × ByteArray) × Reader) :=
  -- A header needs 5 bytes; if fewer remain, we need more input.
  if r.remaining < 5 then
    .ok (none, r)
  else
    match r.takeRecordHeader with
    | .error e => .error e
    | .ok (hdr, r1) =>
      if r1.remaining < hdr.length then
        -- Header parsed but body not fully buffered: signal "need more" without
        -- consuming, by reporting against the original reader.
        .ok (none, r)
      else
        match r1.takeBytes hdr.length with
        | .error e => .error e
        | .ok (body, r2) => .ok (some (hdr, body), r2)

/-- Parse a `TLSInnerPlaintext` from a decrypted record buffer (RFC 8446 §5.2,
RFC 004 §5.6). The structure is `content ‖ content_type ‖ zeros*`: strip trailing
zero padding to the single content-type byte; everything before it is the
content. A buffer that is all zeros (no content-type byte) is malformed. The
inner content type is validated by the caller before any emission. Implemented
with list operations only — no unchecked indexing (RFC 003 §10). -/
def parseInnerPlaintext (buf : ByteArray) : Except ParseError TLSInnerPlaintext :=
  let revBytes := buf.toList.reverse
  match revBytes.dropWhile (· == 0) with
  | [] => .error .malformedInnerPlaintext
  | ct :: contentRev =>
      let content := ByteArray.mk contentRev.reverse.toArray
      let paddingZeros := buf.size - (contentRev.length + 1)
      .ok { content := content
            ctype := ContentType.ofByte ct
            paddingZeros := paddingZeros }

/-- Classify a `change_cipher_spec` record: TLS 1.3 permits a single
compatibility CCS with body `0x01`, accepted-and-ignored only in early states.
Any other CCS body is rejected (RFC 004 §8). The classification is returned to
the core, which decides acceptance — it is never hidden in the interpreter. -/
inductive CcsClassification where
  | allowedCompat
  | rejected
  deriving DecidableEq, Repr, Inhabited

def classifyCcs (body : ByteArray) : CcsClassification :=
  match body.toList with
  | [b] => if b == 1 then .allowedCompat else .rejected
  | _   => .rejected

end Kroopt.Parse
