import Kroopt.Parse.Reader
import Kroopt.Parse.Record
import Kroopt.Parse.Handshake

/-!
# Tests.Fuzz

A small, deterministic fuzz harness for the parser foundation (RFC 003 §11
"fuzz target … even if long-running fuzzing is not yet enabled", RFC 023).

It feeds many pseudo-random byte buffers through the reader primitives and the
vector framer and asserts the safety invariant that the bounds proofs promise:
**no panic, and every returned reader satisfies `offset ≤ input.size` with
`offset` having advanced monotonically.** Because the `Reader.inBounds` field
makes the bound structural, the fuzzer's real job is to exercise the decode and
framing paths on adversarial lengths and confirm they always terminate in a
typed result rather than crashing or looping.

This is a CI-tier smoke fuzzer (bounded iterations). The corpus-driven,
long-running mutation fuzzing lives in RFC 023's harness and is wired in later.
-/

namespace Tests.Fuzz

open Kroopt.Parse
open Kroopt.Parse.Reader

/-- A tiny deterministic LCG so runs are reproducible (no real entropy). -/
structure Rng where
  state : UInt64

def Rng.next (g : Rng) : UInt8 × Rng :=
  -- Numerical Recipes LCG constants.
  let s := g.state * 6364136223846793005 + 1442695040888963407
  (((s >>> 33).toNat % 256).toUInt8, { state := s })

partial def Rng.bytes (g : Rng) (n : Nat) : ByteArray × Rng :=
  let rec go (g : Rng) (k : Nat) (acc : ByteArray) : ByteArray × Rng :=
    match k with
    | 0 => (acc, g)
    | k+1 => let (b, g') := g.next; go g' k (acc.push b)
  go g n (ByteArray.mk #[])

/-- The invariant a returned reader must satisfy: cursor within buffer and at or
past where it started. (`inBounds` guarantees the first; we check anyway as a
runtime cross-check of the proof.) -/
def readerOk (start : Nat) (r : Reader) : Bool :=
  r.offset ≤ r.input.size && start ≤ r.offset

/-- Run one fuzz iteration over a buffer: try each primitive and the vector
framer; every outcome must be a typed result with (on success) a valid reader. -/
def stepOk (buf : ByteArray) : Bool :=
  let r := Reader.ofBytes buf
  let check {α : Type} (res : Except ParseError (α × Reader)) : Bool :=
    match res with
    | .ok (_, r') => readerOk r.offset r'
    | .error _    => true
  check r.takeU8
    && check r.takeU16
    && check r.takeU24
    && check r.takeU32
    && check (r.takeVectorBytes .len8 65536)
    && check (r.takeVectorBytes .len16 65536)
    && check (r.takeVectorBytes .len24 16777216)
    && check (r.takeCountedItems 64 (fun rr => rr.takeU8))

/-- Handshake-surface fuzz targets (RFC 014 §7): the ClientHello parser, the
extension list (reached through it), and the record reassembly framer. All are
total, budget-bounded functions, so the invariant is that any buffer yields a
typed result with no panic, non-termination, or unbounded work. -/
def hsStepOk (buf : ByteArray) : Bool :=
  (match Kroopt.Parse.parseClientHello buf with | .ok _ => true | .error _ => true)
    && (match (Reader.ofBytes buf).tryTakeRecord with
        | .ok (some (_, body), r') => readerOk (Reader.ofBytes buf).offset r' && body.size ≤ buf.size
        | .ok (none, _) => true
        | .error _ => true)

def run (iterations : Nat) : IO UInt32 := do
  let mut g : Rng := { state := 0x123456789ABCDEF0 }
  let mut failures := 0
  for i in [0:iterations] do
    -- vary buffer length 0..255 pseudo-randomly (larger buffers exercise the
    -- ClientHello extension/cipher-suite lists)
    let (lenByte, g1) := g.next
    g := g1
    let (buf, g2) := g.bytes (lenByte.toNat % 256)
    g := g2
    if !(stepOk buf && hsStepOk buf) then
      IO.println s!"  FAIL  iteration {i}: invariant violated on a {buf.size}-byte buffer"
      failures := failures + 1
  if failures == 0 then
    IO.println s!"parser fuzz: {iterations} iterations, no invariant violations."
    return 0
  else
    IO.println s!"parser fuzz: {failures} violations across {iterations} iterations."
    return 1

end Tests.Fuzz

/-- Entry point. Iteration count can be overridden by the first CLI arg. -/
def main (args : List String) : IO UInt32 := do
  let iters := (args.head?.bind (·.toNat?)).getD 5000
  Tests.Fuzz.run iters
