# RFC 046 — Strict ClientHello and Extension Framing

**Project.** kroopt
**Status.** Implemented (AR1 B2; implementation `ebae8f8`; final architecture review accepted 2026-07-22)
**Type.** Blocking parser/security fix
**Target milestone.** AR1 first protocol slice; provisional release `0.127.0`
**Requires completion of.** [RFC 003](../done/003-bounds-safe-parser-and-framer.md) (bounded parser), [RFC 023](../done/023-parser-fuzzing-corpus-and-mutation-policy.md) (fuzzing), [RFC 033](../done/033-real-client-handshake-processing.md) (real-client processing)
**Coordinates with.** [RFC 045](../proposed/045-endpoint-negotiation-policy-authorization.md) (selection authority), [RFC 039](../done/039-named-group-policy-and-enforcement.md) (group selection)
**Touches.** `Kroopt/Parse/{Reader,Handshake}.lean`, SNI validation in `Kroopt/Core/Config.lean`, the
`WireBound` bridge in `Kroopt/Core/RecordPath.lean`, parser/config proofs, deterministic parser/hardening
tests, `testdata/fuzz/clienthello/`, the existing canonical fuzz executable, parser/security documentation

## 1. Review finding and present behavior

Architecture review B2 found that bounds-safe parsing is not strict TLS framing. The current parser cannot
read beyond its input, but it does not consistently prove that a successful parse consumed exactly the bytes
declared by each enclosing TLS vector:

- `parseClientHello` reads and discards the handshake `uint24` length, parses against the original reader,
  and discards the final outer reader;
- `u16sOfBytes` converts malformed or odd-length vectors into `[]`, conflating invalid presence with a valid
  empty/unsupported offer;
- several extension parsers discard their length prefix and do not require the inner reader to reach its end;
- key-share entry/list residue can be ignored;
- `parseSni` returns `none` for absence, truncation, unsupported name type, empty host, and trailing bytes.

This is a protocol-validity defect, not a memory-safety defect. RFC 003's bounds proofs remain valid and are
the foundation for this correction.

## 2. Decision and invariants

Every complete TLS structure consumes exactly its declared region. The parser may tolerate an unknown value
only at an RFC-defined extensibility point and only when its surrounding framing is valid. It never repairs,
truncates, defaults, or treats malformed presence as absence.

The implementation must preserve these invariants:

1. **Declared-region isolation.** A nested parser receives only the bytes declared by its immediate prefix.
2. **Exact success.** A complete nested parser succeeds only after `Reader.expectEnd` succeeds for that region.
3. **Outer continuity.** Parsing a nested region returns the outer reader positioned immediately after the
   declared bytes; inner reads cannot consume outer bytes.
4. **Whole-message success.** A successful `parseClientHello input` has an exact four-byte header/body size
   equation and consumes one ClientHello handshake message with no trailing input.
5. **Presence is not validity.** Absent, well-formed known, well-formed unknown/unsupported, and malformed
   inputs remain distinct until the applicable policy decision.
6. **Exact transcript bytes.** Successful output remains `WireBound` to the original complete `input`; the
   record-to-handshake bridge consumes `wb.wireBytes`, and no structure is reserialized for transcript hashing.
7. **Validated SNI routing.** Client and configured names share one strict ASCII DNS-host canonicalization;
   invalid-present or unsupported-present SNI fails before endpoint selection and cannot reach the default.
8. **Redaction.** Internal errors contain only fixed constructors and numeric lengths/type codes; public error
   projection contains no attacker-controlled bytes.

## 3. Reader primitive design

Add one generic exact-delimited primitive in `Kroopt.Parse.Reader` (the final name may change mechanically):

```lean
def Reader.takeVectorExact
    (r : Reader) (lp : LenPrefix) (maxLen : Nat)
    (parse : Reader → Except ParseError (α × Reader)) :
    Except ParseError (α × Reader) := do
  let (bytes, outer) ← r.takeVectorBytes lp maxLen
  let (value, inner) ← parse (Reader.ofBytes bytes)
  inner.expectEnd
  pure (value, outer)
```

`takeVectorBytes` remains the byte-slice primitive. `takeVectorExact` is used for structured vector bodies;
it is not used where raw opaque bytes are the value. This avoids adding a second cursor-limit representation
to `Reader` and makes region isolation explicit through the exact `ByteArray` slice.

Add or retain a small exact whole-reader helper for unprefixed structured slices. Both helpers are fuel-safe:
item lists continue to use `takeCountedItems`, with their existing explicit maximum.

### 3.1 Proof obligations

Extend `Kroopt.Proofs.ParserBounds` with lemmas showing that successful exact-vector parsing:

- leaves the returned outer reader in bounds and monotonically advanced;
- advances it by prefix width plus the declared length;
- can return only after the nested reader is at end;
- preserves the existing `takeVectorBytes_bounds` result.

Fix the generic theorem propositions before implementation. With `LenPrefix.byteWidth` exposing `1/2/3`, a
successful `takeVectorExact` must provide a declared length `n` and the successful inner reader such that:

```text
outer.offset = r.offset + lp.byteWidth + n
inner.offset = inner.input.size
n <= maxLen
outer.input = r.input
```

The generic theorem binds every witness explicitly. Its proposition has this shape (with `r1` also exposed
if needed by the implementation proof):

```text
r.takeVectorExact lp maxLen parse = ok (value, outer) ->
  exists n r1 bytes inner,
    r.takeLen lp = ok (n, r1) /\
    r1.takeBytes n = ok (bytes, outer) /\
    parse (Reader.ofBytes bytes) = ok (value, inner) /\
    outer.offset = r.offset + lp.byteWidth + n /\
    outer.input = r.input /\
    inner.offset = inner.input.size /\
    n <= maxLen
```

The body parser returns its final reader so its success theorem states that the reader is at end. Define a
small header decoder, for example `clientHelloDeclaredLength : ByteArray → Option Nat`, and prove the
non-vacuous public proposition with an existentially bound decoded value:

```text
parseClientHello input = ok wb ->
  wb.wireBytes = input /\
  exists declared,
    clientHelloDeclaredLength input = some declared /\
    input.size = 4 + declared
```

This differs from merely restating `wireBytes := input`: it links success to the encoded `uint24` field. The
theorem does not claim semantic validity of unknown TLS values. Update the theorem inventory without
inflating the trusted/axiom set.

## 4. Error model and alert projection

Keep the existing error constructors; RFC 046 adds no alternative constructor. Missing bytes use
`unexpectedEof`, exact-region residue uses `trailingBytes`, vector/count ceilings use
`lengthExceedsMax`/`budgetExceeded`, and malformed or unsupported values use `valueOutOfRange`. The
implementation must not add raw bytes, hostnames, protocol names, or key-share contents to an error.

Deterministic precedence is outside-in:

1. prefix/read or declared-region failure;
2. nested framing/exact-end failure;
3. duplicate/required-field structural checks;
4. semantic support and overlap checks.

Tests assert the internal error class where stable and otherwise assert deterministic rejection plus the
public projection. RFC 046 does not redesign alert policy.

Representative fixed expectations are:

| Condition | Internal class | Existing public projection / alert |
|---|---|---|
| missing prefix or declared bytes unavailable | `unexpectedEof` | `truncated` / `decode_error` |
| exact region parsed but leaves residue | `trailingBytes` | `trailingBytes` / `decode_error` |
| configured parser count/vector ceiling exceeded | `budgetExceeded` or `lengthExceedsMax` | existing `oversizedRecord` mapping |
| empty/odd/duplicate/invalid SNI or required-value violation | `valueOutOfRange` | `valueOutOfRange` / `illegal_parameter` |

The nested-vector use of `oversizedRecord` is existing coarse behavior, not a claim that the nested field is
a TLS record and not an invitation to change alerts in this RFC.

## 5. Exact ClientHello grammar

`parseClientHello` performs these steps:

1. read `msg_type` and require `client_hello` (`1`);
2. use the handshake `uint24` length as an exact body region, with the available body capacity
   (`r.remaining - LenPrefix.len24.byteWidth` at the reader positioned after `msg_type`) as the helper's
   structural maximum;
3. parse the complete ClientHello body inside that region;
4. require the body reader and then the original outer reader to be at end;
5. construct `WireBound ValidClientHello` with `wireBytes := input` only after all checks pass.

The pure parser does **not** own connection resource admission and therefore does not call this top-level
operation budgeted. Its input is already materialized, and the available body capacity prevents a declared
body from exceeding it. The retained live order is explicit:

1. `RecordPath` charges cumulative `maxHandshakeBytes` for each inbound handshake record body before buffer
   append, reassembly, framing, or ClientHello parsing;
2. `RecordPath.maxHandshakeReasmBytes` bounds the accumulated reassembly buffer at 65536 wire bytes;
3. framing extracts one exact handshake message and `parseClientHello` checks its structural/semantic form;
4. after exact parse and before negotiation, `onClientHello` charges the complete exact wire message against
   `ResourceLimits.maxClientHelloBytes` (default 16384).

RFC 046 does not reorder or merge those charges. Direct callers of the pure parser receive structural
exactness and the parser's nested count/vector ceilings, not per-connection admission policy. A future
configurable pre-parse admission change belongs to the resource-limit RFCs, not RFC 046.

The body parser requires:

| Field | Structural rule |
|---|---|
| `legacy_version` | exact `0x0303` |
| `random` | exactly 32 bytes |
| `legacy_session_id` | `uint8` vector, at most 32 bytes |
| `cipher_suites` | exact `uint16` vector; non-empty, even byte count, at most `maxCipherSuites` entries |
| `legacy_compression_methods` | exact `uint8` vector containing the single byte `0x00` |
| `extensions` | exact `uint16` vector; TLS wire length at least 8 bytes; at most `maxExtensions` entries; each entry consumes type plus its exact data vector |

An under-declared handshake body cannot borrow bytes from the outer reader. An over-declared body fails when
the declared slice cannot be taken. A correctly declared body followed by any byte fails outer
`expectEnd`. Empty and odd cipher-suite vectors are malformed rather than unsupported overlap.
`maxCipherSuites`, `maxExtensions`, and `maxKeyShares` are constrained-profile resource ceilings, not TLS
wire maxima; exceeding one is a deterministic resource rejection even when the bytes are otherwise framed.

## 6. Extension framing matrix

Raw extension collection first validates every extension's outer `extension_data` framing and rejects every
duplicate type, including unknown/GREASE types. Known extensions then parse as follows:

| Extension | Exact internal grammar and semantic minimum |
|---|---|
| `supported_versions` (43) | `uint8` exact vector of `uint16`; non-empty/even; must contain TLS 1.3 |
| `supported_groups` (10) | `uint16` exact vector of `uint16`; non-empty/even; unknown/GREASE group IDs retained for consistency checks but skipped for supported selection |
| `signature_algorithms` (13) | `uint16` exact vector of `uint16`; non-empty/even; unknown schemes skipped only after framing succeeds |
| `key_share` (51) | `uint16` exact vector of complete entries; non-empty; at most `maxKeyShares`; each entry is group plus an exact, **non-empty** `uint16` opaque key-exchange vector (`1..65535` bytes) for recognized, unknown, and GREASE group IDs |
| `server_name` (0) | exact `uint16` ServerNameList; non-empty; every entry is type plus exact `uint16` name; typed handling in §7 |
| ALPN (16) | exact `uint16` ProtocolNameList; non-empty; every protocol is a non-empty exact `uint8` vector |

Key-share group IDs remain duplicate-free. Every offered key-share group must occur in the well-formed
`supported_groups` vector under the existing constrained no-HRR policy. Recognized x25519/P-256 share length
and P-256 point-prefix checks remain semantic checks after structural parsing. Residue after an entry or list
is always fatal.

Unknown extension types, cipher suites, groups, signature schemes, and versions are accepted when their
containing structure is exact. They are not selected unless separately recognized and supported. GREASE is
therefore tolerated alongside a usable offer, but GREASE never excuses a bad length or duplicate extension.

Structural and whole-ClientHello expectations are deliberately separate:

| Input class | Framing result | Whole ClientHello result |
|---|---|---|
| unknown extension plus all required usable offers | accepted; extension skipped after exact framing | accepted |
| unknown/GREASE value beside a supported value in a known vector | accepted | supported value remains available for later selection |
| unknown/GREASE-only cipher suite | accepted | deterministic no-suite-overlap failure |
| unknown/GREASE-only supported version | accepted | deterministic required-TLS-1.3 failure |
| unknown/GREASE-only group/key-share | accepted only when both vectors are consistent and every key exchange is non-empty | deterministic no-recognized-share/group failure |
| unknown/GREASE-only signature scheme | accepted | deterministic no-supported-signature failure |
| bad length, empty key exchange, or duplicate around any unknown/GREASE value | structural failure | semantic selection is not reached |

## 7. SNI presence and result design

Replace the lossy `ByteArray → Option ByteArray` parser with an internal typed result:

```lean
opaque ValidatedServerName : Type

inductive ServerNameError where
  | invalidLength
  | invalidCharacter
  | invalidLabel
  | addressLiteral
  | reservedLdhLabel

def ValidatedServerName.ofBytes : ByteArray → Except ServerNameError ValidatedServerName
def ValidatedServerName.bytes : ValidatedServerName → ByteArray

inductive SniOffer where
  | absent
  | hostName (name : ValidatedServerName)
  | presentWithoutSupportedName
```

The extension-body parser itself returns `Except ParseError SniOffer`; only the ClientHello coordinator can
produce `.absent`. It parses the entire ServerNameList, rejects an empty list, empty host name, any duplicate
`name_type` (including unknown types), truncation, length mismatch, and trailing bytes. Unknown name types
must be exactly framed and are skipped. If no `host_name` remains, `.presentWithoutSupportedName` reaches the
semantic policy and is rejected as unsupported for the current server profile; it is never converted to
absence.

`ValidatedServerName` is opaque outside its defining module: there is no exported unchecked constructor.
`ofBytes` is the single construction/normalization boundary used by both ClientHello parsing and
server-config validation, while `bytes` exposes only the already-validated canonical form. It applies this
constrained RFC 6066/DNS-host policy before routing:

- total encoded name length is `1..253` bytes (the DNS presentation limit without a trailing root dot; this
  is a constrained-profile ceiling within the TLS `HostName<1..2^16-1>` wire range);
- input is ASCII only; accepted characters are `A-Z`, `a-z`, `0-9`, `-`, and `.`;
- ASCII letters are canonicalized to lower case;
- there is no leading or trailing dot and no empty label;
- every label is `1..63` bytes and begins and ends with an ASCII letter or digit; hyphen is allowed only
  inside a label;
- IPv4 address literals are rejected: four decimal-only labels whose values are each `0..255` are not a
  server DNS hostname. IPv6 text is already rejected because `:` is outside the character set;
- this is a deliberate **no-IDNA** profile: every label of at least four bytes with `--` in positions 3 and
  4 is rejected. That rejects `xn--` A-labels plus every other RFC 5890 reserved/fake A-label form rather than
  attempting partial Punycode/IDNA validation. Unicode/U-label bytes and IDNA conversion are not performed.

Public raw `ServerNamePattern` input remains source-compatible. `validateServerConfig` canonicalizes every
exact name and wildcard suffix into internal validated routes, rejects an invalid pattern with a fixed
`ConfigError.invalidSniPattern`, and performs ambiguity detection **after** canonicalization so `Example.COM` and
`example.com` cannot become distinct routes. Wildcard behavior remains one leftmost label; its suffix passes
the same label validator. Endpoint selection compares only canonical validated names. The validated client
name is projected to the existing `ValidClientHello.sni : Option ByteArray` as canonical bytes, so the public
connection API need not widen.

An invalid client name produces a deterministic fixed parse error before `ValidClientHello` construction;
an unsupported-present SNI also fails before `selectEndpoint`. Neither can use `defaultEndpoint`. A valid,
canonicalized but unmatched hostname may still use the configured default under RFC 011; that is a routing
policy outcome and is distinct from invalid or absent input.

`ServerNameError` contains no input bytes. Every client-side case maps to the fixed existing
`ParseError.valueOutOfRange`; config validation maps it to `ConfigError.invalidSniPattern`. These mappings are
part of the classification tests and do not widen the public TLS alert taxonomy.

This makes absence, malformed presence, and well-framed unsupported presence distinct while preserving the
current endpoint-routing type. Tests cover mixed known/unknown name types, duplicate unknown types, control
and non-ASCII bytes, leading/trailing dot, empty/overlong labels and names, hyphen boundaries, case-equivalent
config/client routing, post-normalization config ambiguity, and invalid-present SNI with a configured default
endpoint proving selection is never reached.
The fixed invalid-name matrix includes IPv4 literals, fake `xn--` labels, non-`xn--` reserved `??--` labels,
and the same cases in raw config routes; each invalid client case is also exercised with a configured default
endpoint to prove routing is not reached. Normal ASCII names used by the OpenSSL/Python/curl fixtures remain
valid.

## 8. Compatibility and ownership boundaries

- The public `parseClientHello` type and `ValidClientHello` fields remain unchanged.
- `WireBound.wireBytes` remains the exact original complete handshake bytes. `RecordPath` passes
  `wb.wireBytes` (or the complete `WireBound`) into `onClientHello`, rather than discarding it and passing a
  parallel local byte value, so the live transcript bridge structurally consumes the parser binding.
- Public raw SNI route patterns remain byte inputs, while validated config stores canonical internal names;
  newly rejected invalid/ambiguous-after-case-folding patterns are intentional validation corrections.
- RFC 045, not this parser, moves suite authorization into endpoint policy. RFC 046 may produce a strict
  offered-code list internally, but must not broaden or relocate selection authority as an incidental fix.
- RFC 039's supported-group/key-share consistency and core-owned group choice remain unchanged.
- No iotakt, jemmet, socket, deadline, certificate-chain, or protected-record behavior changes here.

The main compatibility risk is that previously accepted malformed ClientHellos become deterministic errors;
that is the intended security behavior. Well-formed OpenSSL, Python, curl, and existing constrained GREASE
offers must remain accepted.

## 9. Implementation slices and review points

1. **Exact reader regions.** Add `LenPrefix.byteWidth`, `takeVectorExact`, the fixed theorem propositions,
   focused reader tests, and theorem-inventory wording. Stop for a focused API/proof architecture review
   before migrating a protocol parser.
2. **Strict list parsers.** Replace lossy `u16sOfBytes` use and make versions/groups/signatures/key-share/ALPN
   exact, retaining unknown-value tolerance after framing. Land the complete focused deterministic tests for
   every migrated list in this slice.
3. **Top-level, SNI, and live binding.** Enforce the handshake body/outer end, add shared client/config SNI
   validation and canonicalization, consume `WireBound` at the live transcript bridge, and land all focused
   top-level/SNI/config/default-route tests in the same slice.
4. **Corpus and assembled evidence.** Add minimized hostile corpus seeds and their classification oracle,
   cross-layer GREASE/resource tests, real-client regressions, final documentation, and exact assembled gate
   evidence. This slice does not defer unit tests required to make slices 2 or 3 safe and reviewable.

Architecture review is required now on this detailed design and again after all implementation slices are
assembled with their evidence. Small intermediate commits are allowed; none constitutes RFC completion or a
`0.127.0` candidate by itself.

## 10. Test and fuzz matrix

For the handshake body and every nested vector in §6, add cases for:

- missing/truncated prefix;
- declared length greater than remaining bytes;
- declared length smaller than the encoded structure, leaving residue;
- valid inner structure plus trailing byte;
- empty list where prohibited;
- odd byte count for `uint16` lists;
- zero-length `key_exchange` for recognized, unknown, and GREASE group IDs;
- item-count budget exhaustion;
- duplicate extension, key-share group, and SNI `name_type`;
- explicit TLS minimum and constrained-profile maximum boundaries;
- the per-layer unknown/GREASE outcomes in §6, both alone and alongside supported values;
- malformed and semantic-invalid SNI proving it cannot fall back to a configured default endpoint.

### 10.1 Committed corpus and normal-CI oracle

RFC 046 creates the previously missing concrete RFC 023 mechanism:

```text
testdata/fuzz/clienthello/
  manifest.tsv
  accept-valid-captured.bin
  reject-handshake-underdeclared.bin
  reject-keyshare-empty-unknown.bin
  reject-sni-control-default-route.bin
  ... minimized behavior-named seeds ...
```

`manifest.tsv` is tracked and has fixed columns `file`, `target`, `outcome`, `internal_error`, and
`public_error`. `target` selects a stable test wrapper (`clienthello`, `supported_versions`,
`supported_groups`, `signature_algorithms`, `key_share`, `sni`, or `alpn`); this lets the oracle prove that a
GREASE-only vector is structurally accepted even when the complete ClientHello later fails semantically.
`outcome` is `accept` or `reject`; error columns use fixed constructor/category names and `-` when not
applicable. The loader fails on a missing/extra/duplicate file, unknown target/class, changed classification,
or an oversized seed. Binary contents are never printed on failure.

The existing `kroopt-parse-fuzz` executable loads and checks every manifest row before running its bounded
pseudorandom smoke loop. It prints the existing `no invariant violations` success marker only after both the
classification corpus and smoke mutations pass. Therefore the existing canonical `fuzz` gate
(`lake exe kroopt-parse-fuzz 20000`) becomes the normal-PR/release corpus oracle without a new gate id.
`Tests.Replay` remains the positive captured/live/GREASE-alongside-valid bridge; minimized hostile and
cross-layer classification inputs live under `testdata/fuzz/clienthello/`. Add `docs/src/fuzzing.md` to state
this contract and reconcile RFC 023's previously aspirational paths with the implemented tree.

### 10.2 Mutation and resource policy

Classification-preserving accepted mutations reorder distinct unknown extensions, replace one unknown code
with a GREASE code, or insert a well-framed unknown/GREASE value while retaining every required usable
offer. Structural-rejection mutations change each length by ±1, truncate at every prefix/body boundary, add
residue, force odd UInt16 vectors, duplicate types/IDs, or zero a key-exchange/name/protocol length.
Semantic-rejection mutations preserve framing while replacing **all** usable suites, versions, groups/shares,
or signature schemes with unknown/GREASE values. Each family has at least one minimized committed oracle
seed; bounded generated cases assert the same family result.

The harness rejects corpus files or generated ClientHello buffers above the live 65536-byte reassembly
ceiling, caps generated item counts at the parser ceilings, and asserts returned readers remain in bounds,
every successful public parse has `wb.wireBytes = input`, and budget-ceiling cases return the expected fixed
resource class. This augments rather than replaces the existing termination/no-crash invariant. Positive
regression includes RFC 8448/captured ClientHello cases plus live OpenSSL, Python, and curl interop in the exact
candidate's canonical release profile.

## 11. Documentation and evidence updates

Update parser architecture documentation to distinguish:

- **PROVEN:** cursor bounds, monotonic advance, exact consumption of accepted declared regions;
- **TESTED:** the TLS grammar/error matrix and real-client/GREASE compatibility;
- **not claimed:** general browser-grade extension coverage or semantic correctness for unsupported values.

Update the theorem inventory, current-security B2 status, trust matrix if its parser claim changes, RFC index,
ROADMAP, CHANGELOG, and the `0.127.0` release evidence only when the corresponding gate has actually passed.

## 12. Acceptance criteria

1. Every complete structure in §§5–7 succeeds only on exact declared-byte consumption, with parser proofs for
   the fixed generic region proposition and public header/body size equation.
2. Every review-listed malformed framing class fails deterministically; invalid or unsupported-present SNI
   cannot select the absent/default-SNI path, while case-equivalent validated client/config names route
   identically. The only construction path for the opaque validated-name type rejects IP literals, Unicode,
   and every reserved `??--` label in the no-IDNA profile.
3. Well-framed unknown/GREASE values remain tolerated at RFC extensibility points, while duplicates and bad
   framing fail; zero-length key exchange fails for every group ID and GREASE-only cases match §6's
   structural-versus-semantic oracle.
4. Existing RFC 8448/captured cases and real OpenSSL/Python/curl constrained ClientHellos pass unchanged.
5. Public parser error projection remains coarse and contains no attacker bytes.
6. Exact original successful input remains the transcript-bound `wireBytes`.
7. The manifest-driven corpus runs inside the canonical fuzz gate and checks accept/reject plus fixed
   internal/public classifications; focused parser/config/hardening tests, theorem/axiom checks, sanitizer
   lanes, interop gates, and the canonical `full-release` profile pass on one exact implementation-review
   revision.
8. Architecture review accepts the implementation and documentation before RFC 046 moves to `done/` or
   `0.127.0` is prepared.

## 13. Non-goals

No new TLS extensions, HelloRetryRequest, browser-grade/IDNA breadth, endpoint cipher authorization, deadline
enforcement, certificate-chain redesign, public API stabilization, configurable pre-parse resource admission,
or alert-policy redesign is included.

## 14. Implementation closeout

The four implementation slices were committed as `f3467b2`, `f6b380f`, `a1303cd`, and `ebae8f8`. Final
architecture review accepted the assembled implementation with no blocking findings. The accepted result
provides exact-region and whole-input proofs, strict nested and top-level framing, canonical SNI validation,
live `WireBound` transcript binding, deterministic focused tests, and a 23-seed manifest-driven hostile
corpus in the canonical fuzz executable.

One internal capacity variance from the design in §5 is accepted and recorded. At the reader positioned
after `msg_type`, `parseClientHello` passes the pre-prefix `r1.remaining` value as the `uint24` helper maximum
rather than subtracting `LenPrefix.len24.byteWidth`. The post-prefix slice still rejects every unavailable
declared body, the outer `expectEnd` still rejects residue, and the public exact-input theorem still links a
successful parse to the decoded header/body equation. Consequently this does not change successful parsing,
resource safety, or the public error projection; it can only change internal error precedence for a body
declaration one to three bytes beyond the available body. Preserve this accepted variance unless a later
authorized parser change deliberately aligns it and updates the corresponding classification evidence.

The implementation-review gate used complete-tree development evidence, including a dirty-tree canonical
`full-release` result, and independently reran the focused proof, parser, corpus, compatibility, hygiene, and
documentation checks. That evidence supports implementation acceptance but is not a content-addressed
`0.127.0` candidate attestation. Candidate designation and release still require a clean exact-commit
canonical ledger plus the required CI, sanitizer, interop, release-machinery, and provenance evidence.
