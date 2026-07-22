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

Before the bounded smoke loop, the executable checks RFC 046's committed hostile
corpus against a fail-closed manifest. The two layers share the canonical `fuzz`
gate: deterministic classifications catch semantic drift, while pseudorandom
inputs retain the broad termination/no-panic pressure.
-/

namespace Tests.Fuzz

open Kroopt.Parse
open Kroopt.Parse.Reader

def corpusDir : System.FilePath := "testdata/fuzz/clienthello"
def corpusManifest : System.FilePath := corpusDir / "manifest.tsv"
def maxCorpusSeedBytes : Nat := 65536

structure CorpusRow where
  file : String
  target : String
  outcome : String
  internalError : String
  publicError : String

inductive CorpusResult where
  | accept
  | reject (internalError : String) (publicError : String)
  deriving BEq

def internalErrorName : ParseError → String
  | .unexpectedEof => "unexpectedEof"
  | .trailingBytes => "trailingBytes"
  | .lengthOverflow => "lengthOverflow"
  | .lengthExceedsMax _ _ => "lengthExceedsMax"
  | .valueOutOfRange => "valueOutOfRange"
  | .malformedDer => "malformedDer"
  | .malformedInnerPlaintext => "malformedInnerPlaintext"
  | .budgetExceeded => "budgetExceeded"

def publicErrorName : Kroopt.ParseError → String
  | .truncated => "truncated"
  | .trailingBytes => "trailingBytes"
  | .lengthOverflow => "lengthOverflow"
  | .valueOutOfRange => "valueOutOfRange"
  | .oversizedRecord => "oversizedRecord"
  | .malformedVector => "malformedVector"
  | .malformedExtension => "malformedExtension"
  | .invalidContentType => "invalidContentType"
  | .invalidDer => "invalidDer"

def classifyExcept {α : Type} (result : Except ParseError α) : CorpusResult :=
  match result with
  | .ok _ => .accept
  | .error e => .reject (internalErrorName e) (publicErrorName e.toPublic)

/-- Stable manifest target wrappers. Keeping nested parsers as separate targets
lets the corpus distinguish structural GREASE acceptance from a complete
ClientHello's later semantic no-overlap rejection. -/
def classifyCorpusTarget (target : String) (data : ByteArray) : Except String CorpusResult :=
  match target with
  | "clienthello" =>
      match parseClientHello data with
      | .ok wb =>
          if wb.wireBytes.toList == data.toList then .ok .accept
          else .error "successful ClientHello did not preserve its exact input"
      | .error e => .ok (.reject (internalErrorName e) (publicErrorName e.toPublic))
  | "supported_versions" => .ok (classifyExcept (parseSupportedVersions data))
  | "supported_groups" => .ok (classifyExcept (parseSupportedGroups data))
  | "signature_algorithms" => .ok (classifyExcept (parseSignatureAlgorithms data))
  | "key_share" => .ok (classifyExcept (parseKeyShareEntries data))
  | "sni" => .ok (classifyExcept (parseSni data))
  | "alpn" => .ok (classifyExcept (parseAlpnStrict data))
  | _ => .error s!"unknown target '{target}'"

def parseCorpusRow (line : String) : Except String CorpusRow :=
  match line.splitOn "\t" with
  | [file, target, outcome, internalError, publicError] =>
      if file.isEmpty || !file.endsWith ".bin" || file.contains '/' then
        .error "invalid corpus filename"
      else if outcome != "accept" && outcome != "reject" then
        .error s!"invalid outcome for '{file}'"
      else if outcome == "accept" && (internalError != "-" || publicError != "-") then
        .error s!"accepted row '{file}' must use '-' error fields"
      else if outcome == "reject" && (internalError == "-" || publicError == "-") then
        .error s!"rejected row '{file}' must name both error classes"
      else .ok { file, target, outcome, internalError, publicError }
  | _ => .error "manifest row does not have five tab-separated fields"

def rowExpected (row : CorpusRow) : CorpusResult :=
  if row.outcome == "accept" then .accept
  else .reject row.internalError row.publicError

def hasDuplicateStrings (values : List String) : Bool :=
  values.any (fun value => (values.filter (· == value)).length > 1)

def corpusClassIs (target : String) (data : ByteArray) (expected : CorpusResult) : Bool :=
  match classifyCorpusTarget target data with
  | .ok actual => actual == expected
  | .error _ => false

def replaceRange (data : ByteArray) (start stop : Nat) (replacement : ByteArray) : ByteArray :=
  data.extract 0 start ++ replacement ++ data.extract stop data.size

def withDeclaredClientHelloLength (data : ByteArray) (n : Nat) : ByteArray :=
  let header := ByteArray.mk #[data.get! 0, (n / 65536).toUInt8,
    ((n / 256) % 256).toUInt8, (n % 256).toUInt8]
  header ++ data.extract 4 data.size

/-- One bounded generated representative for each RFC 046 mutation family:
classification-preserving GREASE insertion/reordering, structural framing
damage, and exactly framed semantic no-overlap. -/
def generatedMutationFamiliesOk (valid : ByteArray) : Bool :=
  let acceptVersions := ByteArray.mk #[4, 0x03, 0x04, 0x0a, 0x0a]
  let acceptGroups := ByteArray.mk #[0, 4, 0x00, 0x1d, 0x0a, 0x0a]
  let bodyLen := valid.size - 4
  let under := withDeclaredClientHelloLength valid (bodyLen - 1)
  let over := withDeclaredClientHelloLength valid (bodyLen + 1)
  -- The canonical minimal seed's sole two-byte suite begins at offsets 41..42.
  let semanticUnknownSuite := replaceRange valid 41 43 (ByteArray.mk #[0x0a, 0x0a])
  corpusClassIs "supported_versions" acceptVersions .accept
    && corpusClassIs "supported_groups" acceptGroups .accept
    && corpusClassIs "clienthello" under (.reject "unexpectedEof" "truncated")
    && corpusClassIs "clienthello" over (.reject "unexpectedEof" "truncated")
    && corpusClassIs "clienthello" (valid.extract 0 (valid.size - 1))
         (.reject "unexpectedEof" "truncated")
    && corpusClassIs "clienthello" (valid ++ ByteArray.mk #[0x99])
         (.reject "trailingBytes" "trailingBytes")
    && corpusClassIs "clienthello" semanticUnknownSuite
         (.reject "valueOutOfRange" "valueOutOfRange")

/-- Load and check every committed corpus row. Missing, extra, duplicate,
oversized, unknown-target, or reclassified inputs fail the same normal-CI fuzz
gate. Failure output names only the fixture; hostile bytes are never printed. -/
def checkCorpus : IO Bool := do
  unless (← corpusManifest.pathExists) do
    IO.println s!"  FAIL  corpus manifest missing: {corpusManifest}"
    return false
  let text ← IO.FS.readFile corpusManifest
  let lines := (text.splitOn "\n").filter (fun line => !line.isEmpty)
  match lines with
  | [] =>
      IO.println "  FAIL  corpus manifest is empty"
      return false
  | header :: body =>
    if header != "file\ttarget\toutcome\tinternal_error\tpublic_error" then
      IO.println "  FAIL  corpus manifest header mismatch"
      return false
    let mut rows : List CorpusRow := []
    for line in body do
      match parseCorpusRow line with
      | .error detail =>
          IO.println s!"  FAIL  corpus manifest: {detail}"
          return false
      | .ok row => rows := row :: rows
    rows := rows.reverse
    if rows.isEmpty then
      IO.println "  FAIL  corpus manifest has no rows"
      return false
    let names := rows.map (·.file)
    if hasDuplicateStrings names then
      IO.println "  FAIL  corpus manifest contains a duplicate filename"
      return false
    let entries ← corpusDir.readDir
    let binNames := entries.toList.filterMap (fun entry =>
      if entry.fileName.endsWith ".bin" then some entry.fileName else none)
    if hasDuplicateStrings binNames ||
        names.any (fun name => !binNames.contains name) ||
        binNames.any (fun name => !names.contains name) then
      IO.println "  FAIL  corpus manifest and .bin file set differ"
      return false
    let mut failures := 0
    for row in rows do
      let path := corpusDir / row.file
      let data ← IO.FS.readBinFile path
      if data.size > maxCorpusSeedBytes then
        IO.println s!"  FAIL  {row.file}: seed exceeds {maxCorpusSeedBytes} bytes"
        failures := failures + 1
      else
        match classifyCorpusTarget row.target data with
        | .error detail =>
            IO.println s!"  FAIL  {row.file}: {detail}"
            failures := failures + 1
        | .ok actual =>
            if actual != rowExpected row then
              IO.println s!"  FAIL  {row.file}: classification changed"
              failures := failures + 1
    let valid ← IO.FS.readBinFile (corpusDir / "accept-valid-clienthello.bin")
    if !generatedMutationFamiliesOk valid then
      IO.println "  FAIL  generated mutation-family classifications changed"
      failures := failures + 1
    if failures == 0 then
      IO.println s!"parser corpus: {rows.length} classifications passed."
      return true
    else
      IO.println s!"parser corpus: {failures} classification failures."
      return false

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
  (match Kroopt.Parse.parseClientHello buf with
   | .ok wb => wb.wireBytes.toList == buf.toList
       && clientHelloDeclaredLength buf == some (buf.size - 4)
   | .error _ => true)
    && (match (Reader.ofBytes buf).tryTakeRecord with
        | .ok (some (_, body), r') => readerOk (Reader.ofBytes buf).offset r' && body.size ≤ buf.size
        | .ok (none, _) => true
        | .error _ => true)

def run (iterations : Nat) : IO UInt32 := do
  if !(← checkCorpus) then return 1
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
