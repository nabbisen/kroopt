# Parser foundation

The parser (RFC 003) turns attacker-controlled bytes into validated values or
typed errors. It never hands a partially-checked byte slice to protocol logic as
if it were structured data.

## Bounds-safety by construction

The cursor type carries its own invariant:

```lean
structure Reader where
  input : ByteArray
  offset : Nat
  inBounds : offset ≤ input.size
```

Because `inBounds` is a field, it is impossible to *hold* a reader that points
past its buffer — the bound travels with the data. Every primitive read either
returns a typed `ParseError` or produces a new `Reader` whose `inBounds` is
discharged by the success condition of a length check. "The parser never reads
past the buffer" is therefore a structural fact, and the proofs in
`Kroopt.Proofs.ParserBounds` additionally establish that the cursor only ever
moves *forward* and never swaps the underlying buffer (which transcript binding
depends on).

## Primitives (M1)

- `takeBytes n` — the single primitive: consume exactly `n` bytes, returning the
  exact wire slice (for transcript binding) and an advanced reader, or
  `unexpectedEof`.
- `takeU8`, `takeU16`, `takeU24`, `takeU32` — big-endian fixed-width reads; 24-bit
  handshake lengths get a dedicated `UInt24` rather than a truncated `UInt32`.
- `takeLen` — a length prefix of 8/16/24 bits as a `Nat`.
- `takeVectorBytes prefix maxLen` — a length-prefixed byte vector, rejected if the
  declared length exceeds the configured budget *or* the remaining input. This is
  the framer the record and extension parsers build on.
- `takeCountedItems maxItems item` — a fuel-bounded item list, so there is never
  unbounded recursion over an attacker-controlled count.
- `remaining`, `atEnd`, `expectEnd` — cursor queries; `expectEnd` makes leftover
  bytes an error (kroopt is strict, never lenient).

## Error discipline

Internal `Kroopt.Parse.ParseError` keeps positions and sizes for deterministic
alert mapping and metrics, but never raw attacker bytes. `ParseError.toPublic`
projects it onto the coarse, redacted `Kroopt.ParseError` returned across the
boundary (RFC 013 §13.4).

## What is deferred

The validated *protocol* value types (`ValidClientHello`, the extension set) and
the version/extension-specific error constructors depend on the record and
handshake models and arrive at M2/M4. The fuel combinator's bounds lemma is
scheduled for M4 with the extension-list parser that first uses it.
