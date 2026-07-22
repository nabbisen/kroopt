import Kroopt.Parse.Reader
import Kroopt.Parse.Handshake

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
def u16be (n : Nat) : List UInt8 := [(n / 256).toUInt8, (n % 256).toUInt8]

def failsWith {α : Type} (res : Except ParseError α) (expected : ParseError) : Bool :=
  match res with
  | .error e => e == expected
  | .ok _ => false

def succeedsWith {α : Type} [BEq α] (res : Except ParseError α) (expected : α) : Bool :=
  match res with
  | .ok value => value == expected
  | .error _ => false

def greaseShare : List UInt8 := [0x0A, 0x0A, 0, 1, 0xAA]
def x25519Share : List UInt8 := [0, 0x1D, 0, 32] ++ List.replicate 32 0x07
def keyShareData (entries : List UInt8) : ByteArray := bytes (u16be entries.length ++ entries)

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
  -- LenPrefix.byteWidth / takeVectorExact
  , { name := "LenPrefix.byteWidth reports each wire prefix width"
    , ok := LenPrefix.byteWidth .len8 == 1
            && LenPrefix.byteWidth .len16 == 2
            && LenPrefix.byteWidth .len24 == 3 }
  , { name := "takeVectorExact returns a value and advances the outer reader exactly"
    , ok := (match (Reader.ofBytes (bytes [0x02, 0x11, 0x22, 0x99])).takeVectorExact .len8 8
                    (fun inner => inner.takeU16) with
             | .ok (v, outer) => v == 0x1122 && outer.offset == 3
                                  && outer.remaining == 1
             | .error _ => false) }
  , { name := "takeVectorExact supports len16 and len24 prefixes"
    , ok := (match (Reader.ofBytes (bytes [0x00, 0x01, 0xAA, 0x99])).takeVectorExact .len16 8
                    (fun inner => inner.takeU8) with
             | .ok (v, outer) => v == 0xAA && outer.offset == 3 && outer.remaining == 1
             | .error _ => false)
            && (match (Reader.ofBytes (bytes [0x00, 0x00, 0x01, 0xBB, 0x99])).takeVectorExact .len24 8
                        (fun inner => inner.takeU8) with
                | .ok (v, outer) => v == 0xBB && outer.offset == 4 && outer.remaining == 1
                | .error _ => false) }
  , { name := "takeVectorExact rejects nested trailing bytes"
    , ok := (match (Reader.ofBytes (bytes [0x03, 0x11, 0x22, 0x33])).takeVectorExact .len8 8
                    (fun inner => inner.takeU16) with
             | .error .trailingBytes => true
             | _ => false) }
  , { name := "takeVectorExact rejects a nested parser over-read"
    , ok := (match (Reader.ofBytes (bytes [0x01, 0x11, 0x99])).takeVectorExact .len8 8
                    (fun inner => inner.takeU16) with
             | .error .unexpectedEof => true
             | _ => false) }
  , { name := "takeVectorExact preserves vector maximum enforcement"
    , ok := (match (Reader.ofBytes (bytes [0x02, 0x11, 0x22])).takeVectorExact .len8 1
                    (fun inner => inner.takeU16) with
             | .error (.lengthExceedsMax 2 1) => true
             | _ => false) }
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
  -- RFC 046 Slice 2: exact UInt16 extension vectors
  , { name := "supported_versions exact parser retains GREASE beside TLS 1.3"
    , ok := succeedsWith (parseSupportedVersions (bytes [4, 0x0A, 0x0A, 0x03, 0x04]))
              [0x0A0A, 0x0304] }
  , { name := "supported_versions GREASE-only is structurally valid but not TLS 1.3"
    , ok := succeedsWith (parseSupportedVersions (bytes [2, 0x0A, 0x0A])) [0x0A0A]
            && succeedsWith (offersTls13 [(43, bytes [2, 0x0A, 0x0A])]) false }
  , { name := "supported_versions rejects odd and trailing bytes deterministically"
    , ok := failsWith (parseSupportedVersions (bytes [3, 0x03, 0x04, 0x03])) .unexpectedEof
            && failsWith (parseSupportedVersions (bytes [4, 0x03, 0x04])) .unexpectedEof
            && failsWith (parseSupportedVersions (bytes [2, 0x03, 0x04, 0x99])) .trailingBytes }
  , { name := "supported_versions rejects an empty present vector"
    , ok := failsWith (parseSupportedVersions (bytes [0])) .valueOutOfRange }
  , { name := "supported_groups exact parser retains GREASE and known groups"
    , ok := succeedsWith (parseSupportedGroups (bytes [0, 4, 0x0A, 0x0A, 0, 0x1D]))
              [0x0A0A, 0x001D] }
  , { name := "supported_groups rejects odd framing and outer residue"
    , ok := failsWith (parseSupportedGroups (bytes [0, 3, 0, 0x1D, 0])) .unexpectedEof
            && failsWith (parseSupportedGroups (bytes [0, 4, 0, 0x1D])) .unexpectedEof
            && failsWith (parseSupportedGroups (bytes [0, 2, 0, 0x1D, 0x99])) .trailingBytes }
  , { name := "signature_algorithms retains unknown codes and rejects empty/odd vectors"
    , ok := succeedsWith (parseSignatureAlgorithms (bytes [0, 4, 0x0A, 0x0A, 0x08, 0x07]))
              [0x0A0A, 0x0807]
            && succeedsWith (parseSignatureAlgorithms (bytes [0, 2, 0x0A, 0x0A])) [0x0A0A]
            && (recognizedSigSchemes [0x0A0A]).isEmpty
            && failsWith (parseSignatureAlgorithms (bytes [0, 0])) .valueOutOfRange
            && failsWith (parseSignatureAlgorithms (bytes [0, 1, 0x08])) .unexpectedEof
            && failsWith (parseSignatureAlgorithms (bytes [0, 4, 0x08, 0x07])) .unexpectedEof }
  -- RFC 046 Slice 2: exact key_share lists
  , { name := "key_share exact parser retains well-framed GREASE beside x25519"
    , ok := (match parseKeyShareEntries (keyShareData (greaseShare ++ x25519Share)) with
             | .ok entries => entries.length == 2
                              && entries.map (·.fst) == [0x0A0A, 0x001D]
             | .error _ => false) }
  , { name := "key_share rejects zero-length key_exchange for an unknown group"
    , ok := failsWith (parseKeyShareEntries (bytes [0, 4, 0x0A, 0x0A, 0, 0]))
              .valueOutOfRange }
  , { name := "key_share rejects vector residue and too many entries"
    , ok := failsWith (parseKeyShareEntries (bytes ([0, 5] ++ greaseShare ++ [0x99]))) .trailingBytes
            && failsWith (parseKeyShareEntries (bytes ([0, 6] ++ greaseShare))) .unexpectedEof
            && (let entries := (List.replicate (maxKeyShares + 1) greaseShare).flatten
                failsWith (parseKeyShareEntries (keyShareData entries)) .budgetExceeded) }
  , { name := "key_share GREASE beside supported x25519 survives framing and selects x25519"
    , ok := (let groups : RawExtension := (10, bytes [0, 4, 0x0A, 0x0A, 0, 0x1D])
             let shares : RawExtension := (51, keyShareData (greaseShare ++ x25519Share))
             match findOfferedKeyShares [groups, shares] with
             | .ok [(.x25519, share)] => share.size == 32
             | _ => false) }
  , { name := "key_share GREASE-only is structurally valid then fails semantic overlap"
    , ok := (let groups : RawExtension := (10, bytes [0, 2, 0x0A, 0x0A])
             let shares : RawExtension := (51, keyShareData greaseShare)
             failsWith (findOfferedKeyShares [groups, shares]) .valueOutOfRange) }
  , { name := "parseSni extracts the bare hostname from a server_name extension (RFC 6066)"
    , ok := (match parseSni (ByteArray.mk #[0,13,0,0,10] ++ (String.toUTF8 "ECDSA.TEST")) with
             | .ok (.hostName n) => n.bytes.toList == (String.toUTF8 "ecdsa.test").toList
             | _ => false) }
  , { name := "parseSni rejects a truncated server_name body (bounds-checked)"
    , ok := failsWith (parseSni (ByteArray.mk #[0,13,0,0,10])) .unexpectedEof }
  , { name := "parseSni preserves unsupported-only presence"
    , ok := (match parseSni (ByteArray.mk #[0,13,1,0,10] ++ (String.toUTF8 "ecdsa.test")) with
             | .ok .presentWithoutSupportedName => true | _ => false) }
  , { name := "parseSni rejects duplicate name types, including unknown types"
    , ok := failsWith (parseSni (bytes [0,8,1,0,1,65,1,0,1,66])) .valueOutOfRange }
  , { name := "parseSni rejects invalid, address-literal, and reserved-LDH host names"
    , ok := failsWith (parseSni (ByteArray.mk #[0,6,0,0,3] ++ String.toUTF8 "a..")) .valueOutOfRange
            && failsWith (parseSni (ByteArray.mk #[0,12,0,0,9] ++ String.toUTF8 "127.0.0.1")) .valueOutOfRange
            && failsWith (parseSni (ByteArray.mk #[0,10,0,0,7] ++ String.toUTF8 "xn--bad")) .valueOutOfRange }
  , { name := "parseAlpnStrict extracts one protocol name from an ALPN extension (RFC 7301)"
    , ok := succeedsWith
              ((parseAlpnStrict (ByteArray.mk #[0,9,8] ++ (String.toUTF8 "http/1.1"))).map
                (·.map (·.toList)))
              [(String.toUTF8 "http/1.1").toList] }
  , { name := "parseAlpnStrict extracts two protocol names in offer order"
    , ok := succeedsWith
              ((parseAlpnStrict (ByteArray.mk #[0,12,2] ++ (String.toUTF8 "h2")
                ++ ByteArray.mk #[8] ++ (String.toUTF8 "http/1.1"))).map (·.map (·.toList)))
              [(String.toUTF8 "h2").toList, (String.toUTF8 "http/1.1").toList] }
  , { name := "parseAlpnStrict on a too-short body is rejected (bounds-checked)"
    , ok := failsWith (parseAlpnStrict (ByteArray.mk #[0])) .unexpectedEof }
  , { name := "alpnMalformedEmptyListRejected: an empty ALPN list is malformed"
    , ok := failsWith (parseAlpnStrict (ByteArray.mk #[0,0])) .valueOutOfRange }
  , { name := "alpnMalformedEmptyProtocolRejected: a zero-length protocol name is malformed"
    , ok := failsWith (parseAlpnStrict (ByteArray.mk #[0,1,0])) .valueOutOfRange }
  , { name := "alpnMalformedListLenMismatchRejected: an inner length that misframes is malformed"
    , ok := failsWith (parseAlpnStrict (ByteArray.mk #[0,5,2] ++ (String.toUTF8 "h2")))
              .unexpectedEof }
  , { name := "ALPN rejects residue after an otherwise exact ProtocolNameList"
    , ok := failsWith (parseAlpnStrict (ByteArray.mk #[0,3,2] ++ (String.toUTF8 "h2")
              ++ ByteArray.mk #[0x99])) .trailingBytes }
  , { name := "ALPN rejects residue inside the declared ProtocolNameList"
    , ok := failsWith (parseAlpnStrict (ByteArray.mk #[0,4,2] ++ (String.toUTF8 "h2")
              ++ ByteArray.mk #[0x99])) .unexpectedEof }
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
