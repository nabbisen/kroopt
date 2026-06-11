import Kroopt.Error

/-!
# Kroopt.Parse.Reader

The bounds-safe parsing foundation (RFC 003).

The core idea is *bounds-safety by construction*: a `Reader` carries a proof
that its `offset` never exceeds `input.size`. Every primitive read either fails
with a typed `ParseError` or returns a new `Reader` whose offset has advanced
monotonically and still satisfies the bound — so "the parser never reads past
the buffer" is a structural fact, reinforced by the proofs in
`Kroopt.Proofs.ParserBounds`.

## M1 scope

This is the foundation: the `Reader`, the fixed-width integer reads, the
length-prefixed byte-vector framer, and a fuel-bounded item combinator. The
validated *protocol* value types sketched in RFC 003 §5 (`ValidClientHello`,
`ClientHelloExtensions`, …) and the extension/version-specific error
constructors depend on the record and handshake models and arrive at M2/M4.
This module deliberately depends only on `Kroopt.Error`, keeping the parser a
pure sibling of the verified core.

No unchecked indexing is used: bytes are read only behind a checked bound, and
multi-byte values are decoded from an `extract`ed slice.
-/

namespace Kroopt.Parse

/-- 24-bit big-endian value. TLS handshake lengths are 24-bit; representing them
with a dedicated wrapper avoids the RFC 003 §9.2 anti-pattern of carrying a
handshake length in an unchecked `UInt32` and truncating later. `toNat` is the
decoded value; downstream length-budget checks bound it. -/
structure UInt24 where
  toNat : Nat
  deriving Repr, DecidableEq, Inhabited

/-- Width of a TLS vector / field length prefix. -/
inductive LenPrefix where
  | len8
  | len16
  | len24
  deriving Repr, DecidableEq, Inhabited

/-- Internal, typed parse errors (RFC 003 §4). Richer than the public
`Kroopt.ParseError`: it keeps positions/sizes for deterministic alert mapping
and metrics, but never raw attacker bytes (RFC 003 §10, RFC 010 §13.3). The
extension/version-specific constructors are added with the handshake parser at
M4. -/
inductive ParseError where
  | unexpectedEof
  | trailingBytes
  | lengthOverflow
  | lengthExceedsMax (len : Nat) (maxLen : Nat)
  | valueOutOfRange
  | malformedDer
  | malformedInnerPlaintext
  | budgetExceeded
  deriving Repr, DecidableEq, Inhabited

namespace ParseError

/-- Project an internal parse error onto the public, redacted category
(RFC 013 §13.4). The public type carries no positions or sizes. -/
def toPublic : ParseError → Kroopt.ParseError
  | unexpectedEof        => .truncated
  | trailingBytes        => .trailingBytes
  | lengthOverflow       => .lengthOverflow
  | lengthExceedsMax _ _ => .oversizedRecord
  | valueOutOfRange      => .valueOutOfRange
  | malformedDer         => .invalidDer
  | malformedInnerPlaintext => .invalidContentType
  | budgetExceeded       => .oversizedRecord

end ParseError

/-- A bounds-checked cursor over an immutable byte buffer (RFC 003 §4, §9.1).
`inBounds` is the construction-time evidence that the cursor is valid; it is the
data-level form of "the parser never points past the buffer". -/
structure Reader where
  input : ByteArray
  offset : Nat
  inBounds : offset ≤ input.size

namespace Reader

/-- Start reading a buffer from the beginning. -/
def ofBytes (b : ByteArray) : Reader :=
  { input := b, offset := 0, inBounds := Nat.zero_le _ }

/-- Bytes not yet consumed. -/
def remaining (r : Reader) : Nat :=
  r.input.size - r.offset

/-- Is the cursor exactly at end of input? -/
def atEnd (r : Reader) : Bool :=
  r.offset == r.input.size

/-- Succeed iff all input has been consumed; otherwise `trailingBytes`
(RFC 003 §9.1 `expectEnd`). kroopt is strict: leftover bytes are an error, never
ignored. -/
def expectEnd (r : Reader) : Except ParseError Unit :=
  if r.offset = r.input.size then .ok () else .error .trailingBytes

/-- **The single primitive read.** Consume exactly `n` bytes, returning the
exact wire slice (for transcript binding, RFC 003 §4) and an advanced reader.
Fails with `unexpectedEof` if fewer than `n` bytes remain. The advanced reader's
`inBounds` field is discharged by the success condition `h`, so it is impossible
to construct an out-of-range reader on this path. -/
def takeBytes (r : Reader) (n : Nat) : Except ParseError (ByteArray × Reader) :=
  if h : r.offset + n ≤ r.input.size then
    .ok (r.input.extract r.offset (r.offset + n),
         { input := r.input, offset := r.offset + n, inBounds := h })
  else
    .error .unexpectedEof

/-- Decode a big-endian unsigned value from a byte slice. -/
def beNat (bs : ByteArray) : Nat :=
  bs.foldl (fun acc b => acc * 256 + b.toNat) 0

/-- Read a single byte. -/
def takeU8 (r : Reader) : Except ParseError (UInt8 × Reader) :=
  match r.takeBytes 1 with
  | .ok (bs, r') => .ok ((beNat bs).toUInt8, r')
  | .error e     => .error e

/-- Read a 16-bit big-endian value (RFC 003 §9.1). -/
def takeU16 (r : Reader) : Except ParseError (UInt16 × Reader) :=
  match r.takeBytes 2 with
  | .ok (bs, r') => .ok ((beNat bs).toUInt16, r')
  | .error e     => .error e

/-- Read a 24-bit big-endian value as `UInt24` (RFC 003 §9.2). -/
def takeU24 (r : Reader) : Except ParseError (UInt24 × Reader) :=
  match r.takeBytes 3 with
  | .ok (bs, r') => .ok (⟨beNat bs⟩, r')
  | .error e     => .error e

/-- Read a 32-bit big-endian value (RFC 003 §9.1). -/
def takeU32 (r : Reader) : Except ParseError (UInt32 × Reader) :=
  match r.takeBytes 4 with
  | .ok (bs, r') => .ok ((beNat bs).toUInt32, r')
  | .error e     => .error e

/-- Read a length prefix of the given width as a `Nat`. -/
def takeLen (r : Reader) : LenPrefix → Except ParseError (Nat × Reader)
  | .len8  => match r.takeU8 with  | .ok (v, r') => .ok (v.toNat, r') | .error e => .error e
  | .len16 => match r.takeU16 with | .ok (v, r') => .ok (v.toNat, r') | .error e => .error e
  | .len24 => match r.takeU24 with | .ok (v, r') => .ok (v.toNat, r') | .error e => .error e

/-- **Length-prefixed byte vector** (RFC 003 §6, §8). Read a length of the given
prefix width, reject it if it exceeds `maxLen` (the configured budget), then
consume exactly that many bytes. The two checks — `≤ maxLen` (budget) and the
`takeBytes` bound (remaining input) — are why no attacker-controlled length can
drive an over-read or an over-large allocation (RFC 003 §10). -/
def takeVectorBytes (r : Reader) (lp : LenPrefix) (maxLen : Nat) :
    Except ParseError (ByteArray × Reader) :=
  match r.takeLen lp with
  | .error e => .error e
  | .ok (len, r1) =>
      if len ≤ maxLen then
        r1.takeBytes len
      else
        .error (.lengthExceedsMax len maxLen)

/-- Parse up to `maxItems` items with `item`, stopping at end of input
(RFC 003 §9.1 / §10 — *no unbounded recursion over attacker-controlled lists*).
The recursion is structural on the explicit `maxItems` fuel, so it always
terminates regardless of the input. -/
def takeCountedItems (r : Reader) {α : Type} (maxItems : Nat)
    (item : Reader → Except ParseError (α × Reader)) :
    Except ParseError (List α × Reader) :=
  match maxItems with
  | 0 =>
      if r.atEnd then .ok ([], r) else .error .budgetExceeded
  | maxItems' + 1 =>
      if r.atEnd then
        .ok ([], r)
      else
        match item r with
        | .error e => .error e
        | .ok (a, r1) =>
            match r1.takeCountedItems maxItems' item with
            | .error e => .error e
            | .ok (rest, r2) => .ok (a :: rest, r2)

end Reader

end Kroopt.Parse
