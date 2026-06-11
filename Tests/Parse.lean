import Kroopt.Parse.Reader

/-!
# Tests.Parse

Unit and negative tests for the parser foundation (RFC 003 §11). Pure: no
sockets, no crypto. These pin down the concrete decode behaviour and the
deterministic failure modes (truncation, over-budget length, trailing bytes)
that the bounds proofs guarantee are *safe* but do not pin to specific values.
-/

namespace Tests.Parse

open Kroopt.Parse
open Kroopt.Parse.Reader

structure Check where
  name : String
  ok : Bool

def bytes (l : List UInt8) : ByteArray := ByteArray.mk l.toArray

/-- Helper: does a parse step succeed with a reader advanced to `expectedOffset`? -/
def okAt {α : Type} (res : Except ParseError (α × Reader)) (expectedOffset : Nat) : Bool :=
  match res with
  | .ok (_, r') => r'.offset == expectedOffset
  | .error _    => false

def isError {α : Type} (res : Except ParseError (α × Reader)) : Bool :=
  match res with
  | .ok _    => false
  | .error _ => true

/-- Extract a decoded Nat value (for integer-read checks). -/
def valNat {α : Type} (res : Except ParseError (α × Reader)) (f : α → Nat) : Option Nat :=
  match res with
  | .ok (v, _) => some (f v)
  | .error _   => none

def checks : List Check :=
  -- takeU8
  [ { name := "takeU8 reads one byte, advances by 1"
    , ok := okAt ((Reader.ofBytes (bytes [0xAB, 0xCD])).takeU8) 1
            && valNat ((Reader.ofBytes (bytes [0xAB])).takeU8) (·.toNat) == some 0xAB }
  , { name := "takeU8 on empty input fails (unexpectedEof)"
    , ok := isError ((Reader.ofBytes (bytes [])).takeU8) }
  -- takeU16 big-endian
  , { name := "takeU16 decodes big-endian, advances by 2"
    , ok := valNat ((Reader.ofBytes (bytes [0x01, 0x02])).takeU16) (·.toNat) == some 0x0102
            && okAt ((Reader.ofBytes (bytes [0x01, 0x02, 0x03])).takeU16) 2 }
  , { name := "takeU16 on 1 byte fails"
    , ok := isError ((Reader.ofBytes (bytes [0x01])).takeU16) }
  -- takeU24 big-endian
  , { name := "takeU24 decodes 3-byte big-endian"
    , ok := valNat ((Reader.ofBytes (bytes [0x01, 0x00, 0x00])).takeU24) (·.toNat) == some 0x010000
            && okAt ((Reader.ofBytes (bytes [0xFF, 0xFF, 0xFF])).takeU24) 3 }
  , { name := "takeU24 max value is 0xFFFFFF"
    , ok := valNat ((Reader.ofBytes (bytes [0xFF, 0xFF, 0xFF])).takeU24) (·.toNat) == some 16777215 }
  -- takeU32 big-endian
  , { name := "takeU32 decodes 4-byte big-endian"
    , ok := valNat ((Reader.ofBytes (bytes [0x00, 0x00, 0x01, 0x00])).takeU32) (·.toNat) == some 256 }
  , { name := "takeU32 on 3 bytes fails"
    , ok := isError ((Reader.ofBytes (bytes [0x00, 0x00, 0x01])).takeU32) }
  -- takeBytes
  , { name := "takeBytes n returns exactly n bytes"
    , ok := (match (Reader.ofBytes (bytes [1,2,3,4,5])).takeBytes 3 with
             | .ok (bs, r') => bs.size == 3 && r'.offset == 3
             | .error _     => false) }
  , { name := "takeBytes past end fails"
    , ok := isError ((Reader.ofBytes (bytes [1,2])).takeBytes 5) }
  -- takeVectorBytes: u8-prefixed
  , { name := "takeVectorBytes reads a u8-length-prefixed vector"
    , ok := (match (Reader.ofBytes (bytes [0x03, 0xAA, 0xBB, 0xCC, 0xDD])).takeVectorBytes .len8 16 with
             | .ok (payload, r') => payload.size == 3 && r'.offset == 4
             | .error _          => false) }
  , { name := "takeVectorBytes rejects length over budget (maxLen)"
    , ok := isError ((Reader.ofBytes (bytes [0x05, 1,2,3,4,5])).takeVectorBytes .len8 4) }
  , { name := "takeVectorBytes rejects length exceeding remaining input"
    , ok := isError ((Reader.ofBytes (bytes [0x05, 1, 2])).takeVectorBytes .len8 16) }
  , { name := "takeVectorBytes u16 prefix reads correctly"
    , ok := (match (Reader.ofBytes (bytes [0x00, 0x02, 0x11, 0x22, 0x33])).takeVectorBytes .len16 64 with
             | .ok (payload, r') => payload.size == 2 && r'.offset == 4
             | .error _          => false) }
  -- expectEnd
  , { name := "expectEnd succeeds when fully consumed"
    , ok := (match (Reader.ofBytes (bytes [0x01])).takeU8 with
             | .ok (_, r') => (match r'.expectEnd with | .ok _ => true | .error _ => false)
             | .error _    => false) }
  , { name := "expectEnd fails with trailing bytes"
    , ok := (match (Reader.ofBytes (bytes [0x01, 0x99])).takeU8 with
             | .ok (_, r') => (match r'.expectEnd with | .ok _ => false | .error _ => true)
             | .error _    => false) }
  -- takeCountedItems: fuel-bounded list of u8s
  , { name := "takeCountedItems parses a bounded item list to end"
    , ok := (match (Reader.ofBytes (bytes [1,2,3])).takeCountedItems 8 (fun r => r.takeU8) with
             | .ok (xs, r') => xs.length == 3 && r'.atEnd
             | .error _     => false) }
  , { name := "takeCountedItems with too little fuel fails (budgetExceeded)"
    , ok := isError ((Reader.ofBytes (bytes [1,2,3,4,5])).takeCountedItems 2 (fun r => r.takeU8)) }
  ]

def main : IO UInt32 := do
  let mut failures := 0
  IO.println "kroopt M1 parser tests (Kroopt.Parse.Reader):"
  for c in checks do
    if c.ok then
      IO.println s!"  PASS  {c.name}"
    else
      IO.println s!"  FAIL  {c.name}"
      failures := failures + 1
  if failures == 0 then
    IO.println s!"\nAll {checks.length} checks passed."
    return 0
  else
    IO.println s!"\n{failures} of {checks.length} checks FAILED."
    return 1

end Tests.Parse

def main : IO UInt32 := Tests.Parse.main
