import Kroopt.Parse.Reader
import Kroopt.Core.Handshake

/-!
# Kroopt.Parse.Handshake

The TLS 1.3 ClientHello parser and policy checker (RFC 006 §5). Built entirely on
the bounds-safe `Reader` primitives (M1) — every length prefix and list is
budget-bounded, so no attacker-controlled ClientHello can drive an over-read or
unbounded work. The list combinators reuse `takeCountedItems`, whose
bounds-safety is proved (`Kroopt.Parse.Proofs.takeCountedItems_bounds`).

On success it returns a `WireBound ValidClientHello`: the validated negotiated
parameters plus the **exact consumed bytes**, which are what enter the transcript
(RFC 007 §6). The mandatory checks: a handshake msg_type of `client_hello`, TLS
1.3 offered in `supported_versions`, an X25519 `key_share` present, an acceptable
cipher suite, and no duplicate extensions.
-/

namespace Kroopt.Parse

open Kroopt.Core (ValidClientHello CipherSuite NamedGroup SignatureScheme)

/-- Conservative parse budgets (RFC 019). -/
def maxExtensions : Nat := 64
def maxCipherSuites : Nat := 128
def maxKeyShares : Nat := 32
def maxVectorLen : Nat := 65535

/-- Map a cipher-suite code to a suite kroopt can *perform*. The constrained profile
performs `TLS_CHACHA20_POLY1305_SHA256` (0x1303) only; the AES-GCM suites are not in
the vendored provider, so they map to `none` and are skipped by the overlap selection
(this map widens when a real AES provider lands — RFC 035). This binds suite
*negotiation* to suite *capability*: kroopt will not select a suite it cannot perform,
even if the client lists it first. -/
def suiteOfU16 : UInt16 → Option CipherSuite
  | 0x1303 => some .chacha20Poly1305Sha256
  | _      => none

/-- Parse a length-prefixed list of `UInt16` values from a byte slice, reusing
the bounds-safe fuel combinator. -/
def u16sOfBytes (b : ByteArray) : List UInt16 :=
  match (Reader.ofBytes b).takeCountedItems b.size (fun r => r.takeU16) with
  | .ok (xs, _) => xs
  | .error _    => []

/-- A parsed extension: its type and exact data bytes. -/
abbrev RawExtension := UInt16 × ByteArray

/-- Parse one extension: `extension_type` (u16) + `extension_data` (vector,
len16, budgeted). -/
def parseExtension (r : Reader) : Except ParseError (RawExtension × Reader) :=
  match r.takeU16 with
  | .error e => .error e
  | .ok (ty, r1) =>
      match r1.takeVectorBytes .len16 maxVectorLen with
      | .error e => .error e
      | .ok (data, r2) => .ok ((ty, data), r2)

/-- Parse one `KeyShareEntry`: `group` (u16) + `key_exchange` (vector, len16). -/
def parseKeyShareEntry (r : Reader) : Except ParseError ((UInt16 × ByteArray) × Reader) :=
  match r.takeU16 with
  | .error e => .error e
  | .ok (group, r1) =>
      match r1.takeVectorBytes .len16 maxVectorLen with
      | .error e => .error e
      | .ok (ke, r2) => .ok ((group, ke), r2)

/-- Does the extension list contain a duplicate type? -/
def hasDuplicateExt (exts : List RawExtension) : Bool :=
  let types := exts.map Prod.fst
  let rec go : List UInt16 → Bool
    | [] => false
    | t :: rest => rest.contains t || go rest
  go types

/-- Find an extension's data by type. -/
def findExt (exts : List RawExtension) (ty : UInt16) : Option ByteArray :=
  (exts.find? (fun e => e.fst == ty)).map Prod.snd

/-- `supported_versions` (type 43) must offer TLS 1.3 (0x0304). The extension
data is a u8-length-prefixed list of u16 versions. -/
def offersTls13 (exts : List RawExtension) : Bool :=
  match findExt exts 43 with
  | none => false
  | some d =>
      -- drop the 1-byte list length, then scan u16 versions
      let body := d.extract 1 d.size
      (u16sOfBytes body).contains 0x0304

/-- Extract the client's X25519 (group 0x001d) `key_share`, if present. The
`key_share` extension data is a u16-length-prefixed list of `KeyShareEntry`. -/
def findX25519Share (exts : List RawExtension) : Option ByteArray :=
  match findExt exts 51 with
  | none => none
  | some d =>
      match (Reader.ofBytes d).takeVectorBytes .len16 maxVectorLen with
      | .error _ => none
      | .ok (entriesBytes, _) =>
          match (Reader.ofBytes entriesBytes).takeCountedItems maxKeyShares parseKeyShareEntry with
          | .error _ => none
          | .ok (entries, _) =>
              (entries.find? (fun e => e.fst == 0x001d)).map Prod.snd

/-- Pick the first offered cipher suite kroopt supports. -/
def selectSuite (offered : List UInt16) : Option CipherSuite :=
  offered.foldl (fun acc c => acc.orElse (fun _ => suiteOfU16 c)) none

/-- Map a `signature_algorithms` code to a scheme kroopt can *present*. The
constrained profile presents Ed25519 (0x0807) only; ECDSA/RSA offers are not
presentable, so they map to `none` and are skipped by the overlap selection
(RFC 033 §3, RFC 8446 §4.2.3). -/
def sigSchemeOfU16 : UInt16 → Option SignatureScheme
  | 0x0807 => some .ed25519
  | _      => none

/-- Pick the first offered signature scheme kroopt can present (overlap selection). -/
def selectSigScheme (offered : List UInt16) : Option SignatureScheme :=
  offered.foldl (fun acc c => acc.orElse (fun _ => sigSchemeOfU16 c)) none

/-- The client's offered `signature_algorithms` (extension 0x000d): the extension
data is a u16-length-prefixed list of u16 scheme codes, so drop the 2-byte list
length and read the codes. Absent extension ⇒ empty list (a server that
authenticates with a certificate then has no acceptable scheme and aborts). -/
def offeredSigSchemes (exts : List RawExtension) : List UInt16 :=
  match findExt exts 0x000d with
  | none   => []
  | some d => u16sOfBytes (d.extract 2 d.size)

/-- Parse and validate a ClientHello handshake message (RFC 006 §5). Returns the
validated parameters bound to the exact consumed bytes. -/
def parseClientHello (input : ByteArray) : Except ParseError (Kroopt.Core.WireBound ValidClientHello) := do
  let r := Reader.ofBytes input
  -- handshake header: msg_type = 1 (client_hello), 3-byte length
  let (msgType, r) ← r.takeU8
  if msgType != 1 then throw .valueOutOfRange
  let (_len, r) ← r.takeLen .len24
  -- ClientHello body
  let (legacyVersion, r) ← r.takeU16
  -- RFC 8446 §4.1.2: a TLS 1.3 ClientHello MUST set legacy_version to 0x0303;
  -- version preference is carried only in supported_versions.
  if legacyVersion != 0x0303 then throw .valueOutOfRange
  let (_random, r) ← r.takeBytes 32
  let (_sessionId, r) ← r.takeVectorBytes .len8 32
  let (suitesBytes, r) ← r.takeVectorBytes .len16 (2 * maxCipherSuites)
  let (compression, r) ← r.takeVectorBytes .len8 maxVectorLen
  -- RFC 8446 §4.1.2: legacy_compression_methods MUST be exactly one byte set to zero
  -- (compression is forbidden in TLS 1.3).
  if !(compression.size == 1 && compression.get! 0 == 0) then throw .valueOutOfRange
  let (extBytes, _r) ← r.takeVectorBytes .len16 maxVectorLen
  -- extensions
  let exts ← match (Reader.ofBytes extBytes).takeCountedItems maxExtensions parseExtension with
             | .error e => throw e
             | .ok (exts, _) => pure exts
  if hasDuplicateExt exts then throw .valueOutOfRange
  if !offersTls13 exts then throw .valueOutOfRange
  let some share := findX25519Share exts | throw .valueOutOfRange
  let some suite := selectSuite (u16sOfBytes suitesBytes) | throw .valueOutOfRange
  let some sigScheme := selectSigScheme (offeredSigSchemes exts) | throw .valueOutOfRange
  let vch : ValidClientHello :=
    { selectedSuite := suite
      selectedGroup := .x25519
      clientShare := share
      selectedSigScheme := sigScheme
      sni := findExt exts 0
      alpn := match findExt exts 16 with | some d => [d] | none => [] }
  pure { value := vch, wireBytes := input }

end Kroopt.Parse
