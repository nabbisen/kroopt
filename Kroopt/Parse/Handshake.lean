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

open Kroopt.Core (ValidClientHello CipherSuite NamedGroup SignatureScheme ValidatedServerName)

/-- Conservative parse budgets (RFC 019). -/
def maxExtensions : Nat := 64
def maxCipherSuites : Nat := 128
def maxKeyShares : Nat := 32
def maxVectorLen : Nat := 65535

/-- Map each supported TLS 1.3 cipher-suite code to its model value. Provider capability
validation ensures the selected suite can be performed; RFC 045 separately owns endpoint
allow-list authorization, which this parser-level mapping must not be mistaken for. -/
def suiteOfU16 : UInt16 → Option CipherSuite
  | 0x1301 => some .aes128GcmSha256
  | 0x1302 => some .aes256GcmSha384
  | 0x1303 => some .chacha20Poly1305Sha256
  | _      => none
  -- All three TLS 1.3 suites are servable end-to-end: AES-128-GCM / ChaCha20-Poly1305 (SHA-256)
  -- and AES-256-GCM-SHA384 (the SHA-384 key schedule + transcript landed; the interpreter seal
  -- path is suite-aware as of 0.68.0-dev, the schedule hash-parameterized as of 0.71.0-dev).

/-- Parse UInt16 items to the end of an isolated reader. Fuel is the remaining
byte count, so the walk is bounded without imposing a new TLS policy ceiling. -/
def parseU16Items (r : Reader) : Except ParseError (List UInt16 × Reader) :=
  r.takeCountedItems r.remaining (fun rr => rr.takeU16)

/-- Parse one complete, non-empty, length-prefixed UInt16 vector from extension
data. Exact framing rejects an odd inner length, an over/under-declared vector,
or trailing bytes after the declared vector. Unknown values remain in the list. -/
def parseNonemptyU16Vector (data : ByteArray) (lp : LenPrefix) :
    Except ParseError (List UInt16) := do
  let (items, outer) ← (Reader.ofBytes data).takeVectorExact lp maxVectorLen parseU16Items
  outer.expectEnd
  if items.isEmpty then throw .valueOutOfRange
  pure items

def parseSupportedVersions (data : ByteArray) : Except ParseError (List UInt16) :=
  parseNonemptyU16Vector data .len8

def parseSupportedGroups (data : ByteArray) : Except ParseError (List UInt16) :=
  parseNonemptyU16Vector data .len16

def parseSignatureAlgorithms (data : ByteArray) : Except ParseError (List UInt16) :=
  parseNonemptyU16Vector data .len16

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
      | .ok (ke, r2) =>
          if ke.isEmpty then .error .valueOutOfRange
          else .ok ((group, ke), r2)

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

/-- Structural outcome of the RFC 6066 server-name extension. Presence without
a supported name is kept distinct from absence so it cannot reach default-route
selection. -/
inductive SniOffer where
  | absent
  | hostName (name : ValidatedServerName)
  | presentWithoutSupportedName

abbrev RawServerName := UInt8 × ByteArray

def parseServerNameEntry (r : Reader) : Except ParseError (RawServerName × Reader) :=
  match r.takeU8 with
  | .error e => .error e
  | .ok (nameType, r1) =>
      match r1.takeVectorBytes .len16 maxVectorLen with
      | .error e => .error e
      | .ok (name, r2) =>
          if name.isEmpty then .error .valueOutOfRange
          else .ok ((nameType, name), r2)

def parseServerNameItems (r : Reader) : Except ParseError (List RawServerName × Reader) :=
  r.takeCountedItems r.remaining parseServerNameEntry

def hasDuplicateServerNameTypes (names : List RawServerName) : Bool :=
  let types := names.map Prod.fst
  types.any (fun ty => (types.filter (· == ty)).length > 1)

/-- Strict, exactly framed `server_name` parsing. Unknown name types are
retained for duplicate detection and otherwise skipped. Host names pass through
the shared constrained ASCII canonicalizer used by server configuration. -/
def parseSni (ext : ByteArray) : Except ParseError SniOffer := do
  let (names, outer) ←
    (Reader.ofBytes ext).takeVectorExact .len16 maxVectorLen parseServerNameItems
  outer.expectEnd
  if names.isEmpty || hasDuplicateServerNameTypes names then throw .valueOutOfRange
  match names.find? (fun n => n.fst == 0) with
  | none => pure .presentWithoutSupportedName
  | some (_, raw) =>
      match ValidatedServerName.ofBytes raw with
      | .error _ => throw .valueOutOfRange
      | .ok name => pure (.hostName name)

/-- Parse one non-empty ALPN ProtocolName (`uint8` opaque vector). -/
def parseAlpnProtocol (r : Reader) : Except ParseError (ByteArray × Reader) := do
  match r.takeVectorBytes .len8 255 with
  | .error e => .error e
  | .ok (name, outer) =>
      if name.isEmpty then .error .valueOutOfRange
      else .ok (name, outer)

/-- Parse ALPN names to the end of an isolated ProtocolNameList reader. -/
def parseAlpnItems (r : Reader) : Except ParseError (List ByteArray × Reader) :=
  r.takeCountedItems r.remaining parseAlpnProtocol

/-- Strict ALPN extension-body parse (RFC 7301 §3.1). The extension contains one
exact `uint16` ProtocolNameList, with a non-empty list of non-empty names and no
residue inside or after the declared vector. -/
def parseAlpnStrict (ext : ByteArray) : Except ParseError (List ByteArray) := do
  let (names, outer) ←
    (Reader.ofBytes ext).takeVectorExact .len16 maxVectorLen parseAlpnItems
  outer.expectEnd
  if names.isEmpty then throw .valueOutOfRange
  pure names

/-- `supported_versions` (type 43) must offer TLS 1.3 (0x0304). The extension
data is a u8-length-prefixed list of u16 versions. -/
def offersTls13 (exts : List RawExtension) : Except ParseError Bool :=
  match findExt exts 43 with
  | none => .ok false
  | some d => (parseSupportedVersions d).map (·.contains 0x0304)

/-- Does any `key_share` group id appear more than once? RFC 8446 §4.2.8 forbids a client
from sending two `KeyShareEntry`s for the same group; such a ClientHello is malformed and the
parser rejects it (rather than silently taking the first), so the core only ever sees a
duplicate-free offer (RFC 039 §4.5). -/
def hasDupGroupIds (entries : List (UInt16 × ByteArray)) : Bool :=
  let ids := entries.map (·.fst)
  ids.any (fun x => (ids.filter (· == x)).length > 1)

/-- The exactly framed group ids in `supported_groups`, preserving unknown/GREASE
codes. `none` means the extension is absent; malformed or empty presence is an error. -/
def supportedGroupIds (exts : List RawExtension) :
    Except ParseError (Option (List UInt16)) :=
  match findExt exts 0x000a with
  | none => .ok none
  | some d => (parseSupportedGroups d).map some

/-- Parse the complete non-empty key-share entry vector. Every entry consumes a
non-empty key_exchange; unknown/GREASE group ids remain available for duplicate
and supported_groups consistency checks. -/
def parseKeyShareEntries (data : ByteArray) :
    Except ParseError (List (UInt16 × ByteArray)) := do
  let (entries, outer) ← (Reader.ofBytes data).takeVectorExact .len16 maxVectorLen
    (fun inner => inner.takeCountedItems maxKeyShares parseKeyShareEntry)
  outer.expectEnd
  if entries.isEmpty then throw .valueOutOfRange
  pure entries

/-- The client's recognized ECDHE `key_share` offers, **in client order**, surfaced for the
core to choose among (RFC 039 §4.3 — selection is the core's job, not the parser's). kroopt
recognizes x25519 (group 0x001d, 32-byte share) and secp256r1 (group 0x0017, 65-byte
uncompressed point `0x04 || X || Y`); each share's wire length (and the P-256 0x04 prefix) is
validated here so a malformed share is rejected before negotiation (RFC 8446 §4.2.8).

Consistency with `supported_groups` (RFC 039 §4.6 / RFC 8446 §4.2.8): if `supported_groups`
is present, **every** offered `key_share` group id must appear in it — a `key_share` for an
omitted group is a contradiction and the ClientHello is rejected. If `supported_groups` is
**absent**, the ClientHello is **rejected** (strict constrained-profile policy, review HIGH-3):
RFC 8446 §4.2.8 requires each `KeyShareEntry` to correspond to a `supported_groups` entry, so a
`key_share` with no `supported_groups` is non-conformant; the constrained no-HRR profile fails
closed rather than treating the `key_share` as authoritative. A group listed in
`supported_groups` with no `key_share` is simply not selectable (no HRR); that surfaces as a
clean selection failure downstream, not here.

Fails with a typed parse error when the extension is absent or malformed, carries
a duplicate/empty/invalid recognized share, contradicts `supported_groups`, or
offers no recognized group; otherwise returns a non-empty recognized list. -/
def findOfferedKeyShares (exts : List RawExtension) :
    Except ParseError (List (NamedGroup × ByteArray)) := do
  let some data := findExt exts 51 | throw .valueOutOfRange
  let entries ← parseKeyShareEntries data
  let some groups ← supportedGroupIds exts | throw .valueOutOfRange
  if hasDupGroupIds entries then throw .valueOutOfRange
  if entries.any (fun e => !(groups.contains e.fst)) then throw .valueOutOfRange
  let malformedRecognized := entries.any (fun e =>
    if e.fst == 0x001d then e.snd.size != 32
    else if e.fst == 0x0017 then !(e.snd.size == 65 && e.snd.get! 0 == 0x04)
    else false)
  if malformedRecognized then throw .valueOutOfRange
  let recognized : List (NamedGroup × ByteArray) := entries.filterMap (fun e =>
    if e.fst == 0x001d then some (.x25519, e.snd)
    else if e.fst == 0x0017 then some (.secp256r1, e.snd)
    else none)
  if recognized.isEmpty then throw .valueOutOfRange
  pure recognized

/-- Pick the first offered cipher suite kroopt supports. -/
def selectSuite (offered : List UInt16) : Option CipherSuite :=
  offered.foldl (fun acc c => acc.orElse (fun _ => suiteOfU16 c)) none

/-- Map a `signature_algorithms` code to a scheme kroopt can *present*. The current profile can
present Ed25519 (0x0807), ECDSA-P256/SHA-256 (0x0403), and RSA-PSS/SHA-256 (rsa_pss_rsae_sha256,
0x0804); other RSA variants are not presentable yet and map to `none` (skipped by overlap
selection). The *actual* scheme is chosen in the core against the selected certificate (RFC 033 §3,
RFC 8446 §4.2.3). -/
def sigSchemeOfU16 : UInt16 → Option SignatureScheme
  | 0x0807 => some .ed25519
  | 0x0403 => some .ecdsaSecp256r1Sha256
  | 0x0804 => some .rsaPssRsaeSha256
  | _      => none

/-- The recognized signature schemes the client offered, in client order (overlap candidates). -/
def recognizedSigSchemes (offered : List UInt16) : List SignatureScheme :=
  offered.filterMap sigSchemeOfU16

/-- The client's exactly framed `signature_algorithms` codes. Absence is an
empty semantic offer; malformed or empty presence remains a parse error. -/
def clientSigSchemeCodes (exts : List RawExtension) : Except ParseError (List UInt16) :=
  match findExt exts 0x000d with
  | none   => .ok []
  | some d => parseSignatureAlgorithms d

/-- Parse a TLS extension list to the end of its isolated reader. RFC 8446's
ClientHello extension vector is non-empty in this profile and every extension
occupies at least four bytes; the required TLS 1.3 extensions make eight bytes
the minimum accepted top-level vector. -/
def parseExtensionItems (r : Reader) : Except ParseError (List RawExtension × Reader) :=
  if r.input.size < 8 then .error .valueOutOfRange
  else r.takeCountedItems maxExtensions parseExtension

/-- Decode the uint24 declared body length when a four-byte handshake header is
available. This is intentionally only a header decoder; `parseClientHello`
establishes equality with the complete input on success. -/
def clientHelloDeclaredLength (input : ByteArray) : Option Nat :=
  match (Reader.ofBytes input).takeU8 with
  | .error _ => none
  | .ok (_, r) =>
      match r.takeLen .len24 with
      | .error _ => none
      | .ok (n, _) => some n

/-- Exactly framed top-level ClientHello fields, before semantic negotiation. -/
structure FramedClientHello where
  sessionId : ByteArray
  offeredSuites : List UInt16
  extensions : List RawExtension

def frameClientHelloBody (r : Reader) : Except ParseError (FramedClientHello × Reader) :=
  match r.takeU16 with
  | .error e => .error e
  | .ok (legacyVersion, r1) =>
    if legacyVersion != 0x0303 then .error .valueOutOfRange else
    match r1.takeBytes 32 with
    | .error e => .error e
    | .ok (_, r2) =>
      match r2.takeVectorBytes .len8 32 with
      | .error e => .error e
      | .ok (sessionId, r3) =>
        match r3.takeVectorExact .len16 (2 * maxCipherSuites) parseU16Items with
        | .error e => .error e
        | .ok (offeredSuites, r4) =>
          if offeredSuites.isEmpty then .error .valueOutOfRange else
          match r4.takeVectorBytes .len8 maxVectorLen with
          | .error e => .error e
          | .ok (compression, r5) =>
            if !(compression.size == 1 && compression.get! 0 == 0) then
              .error .valueOutOfRange
            else
              match r5.takeVectorExact .len16 maxVectorLen parseExtensionItems with
              | .error e => .error e
              | .ok (exts, r6) =>
                  .ok ({ sessionId := sessionId, offeredSuites := offeredSuites,
                         extensions := exts }, r6)

/-- Perform ClientHello semantic validation after exact top-level framing. -/
def validateFramedClientHello (framed : FramedClientHello) : Except ParseError ValidClientHello := do
  let exts := framed.extensions
  if hasDuplicateExt exts then throw .valueOutOfRange
  if !(← offersTls13 exts) then throw .valueOutOfRange
  let offeredShares ← findOfferedKeyShares exts
  let some suite := selectSuite framed.offeredSuites | throw .valueOutOfRange
  let offeredSchemes := recognizedSigSchemes (← clientSigSchemeCodes exts)
  if offeredSchemes.isEmpty then throw .valueOutOfRange
  let alpnField ← match findExt exts 16 with
    | none   => pure (none : Option (List ByteArray))
    | some d => pure (some (← parseAlpnStrict d))
  let sniField ← match findExt exts 0 with
    | none => pure (none : Option ByteArray)
    | some d =>
        match ← parseSni d with
        | .hostName name => pure (some name.bytes)
        | .presentWithoutSupportedName => throw .valueOutOfRange
        | .absent => throw .valueOutOfRange
  pure
    ({ selectedSuite := suite
       offeredShares := offeredShares
       offeredSigSchemes := offeredSchemes
       sni := sniField
       alpn := alpnField
       sessionId := framed.sessionId })

/-- Parse the exactly isolated ClientHello body and return the final reader.
Semantic validation happens only after all top-level vectors have been framed. -/
def parseClientHelloBody (r : Reader) : Except ParseError (ValidClientHello × Reader) :=
  match frameClientHelloBody r with
  | .error e => .error e
  | .ok (framed, outer) =>
      match validateFramedClientHello framed with
      | .error e => .error e
      | .ok vch => .ok (vch, outer)

/-- Parse and validate a ClientHello handshake message (RFC 006 §5). Returns the
validated parameters bound to the exact consumed bytes. -/
def parseClientHello (input : ByteArray) : Except ParseError (Kroopt.Core.WireBound ValidClientHello) :=
  let r := Reader.ofBytes input
  match r.takeU8 with
  | .error e => .error e
  | .ok (msgType, r1) =>
    if msgType != 1 then .error .valueOutOfRange else
    match r1.takeVectorExact .len24 r1.remaining parseClientHelloBody with
    | .error e => .error e
    | .ok (vch, outer) =>
      match outer.expectEnd with
      | .error e => .error e
      | .ok _ => .ok { value := vch, wireBytes := input }

end Kroopt.Parse
