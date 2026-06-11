# Changelog

All notable changes to kroopt are recorded here. RFC lifecycle transitions are
governed by [`rfcs/done/000-rfc-lifecycle-policy.md`](rfcs/done/000-rfc-lifecycle-policy.md).

## [0.4.0-dev] — M3 nonce, sequence, epoch, key separation — 2026-06-11

Fourth implementation milestone (RFC 005). Proves the record layer's
cryptographic discipline — the part where a kroopt bug, not a HACL\* bug, would
destroy security: AEAD nonce reuse, sequence wrap, or read/write/epoch key
confusion. Built over the M2 record path; still no real crypto and no sockets.

### Added — nonce / key-epoch model (`Kroopt.Core.Nonce`)

- `KeyEpochId` — a non-secret key-epoch identity (conn, direction, epoch,
  generation) for correlating nonces, proofs, and logs without secret bytes.
- `RecordNonce` / `deriveNonce` — the nonce modeled as the public IV-base
  identity plus the sequence value (the data the uniqueness argument needs).
- `seqBytesBE`, `paddedSeqBytes`, `nonceBytes` — the concrete
  `iv_base XOR left_pad(seq)` byte realization for the interpreter and KATs.

### Added — proofs (`Kroopt.Proofs.Nonces`, `Kroopt.Proofs.KeySeparation`)

- `SeqNo.next_some_succ` / `next_none_overflow` — increment is exactly `+1`;
  `none` only at the `UInt64` ceiling (no wrapped value is produced).
- `successful_seal_increments_write_seq` / `successful_open_increments_read_seq`
  — an accepted seal/open advances that direction's sequence by exactly one.
- `no_crypto_on_write_seq_overflow` — **no silent wrap**: at the ceiling a send
  requests no crypto and fails.
- `nonce_unique_within_epoch` — distinct sequences derive distinct nonces for a
  fixed IV base (depends on no axioms at all).
- `aeadSeal_uses_write_keys` / `aeadOpen_uses_read_keys` — directional and epoch
  key separation: seal ops carry write/application metadata, open ops carry
  read/application metadata.
- All machine-checked, no `sorry`/`axiom`/`unsafe`; `#print axioms` shows only
  `propext` (one theorem none, one also `Quot.sound`).

### Added — tests, docs

- `Tests/Nonce.lean` (`kroopt-nonce-test`) — 12 checks: sequence increment and
  ceiling overflow, nonce uniqueness (modeled and concrete bytes), the
  direction/epoch metadata on emitted seal/open ops, and stale/early
  crypto-result behaviour; all passing.
- `docs/src/nonce-sequence.md`; expanded theorem inventory and proof-assumptions.

### Changed

- `Core.Record` gained the `SeqNo.next` increment/overflow lemmas. The gates now
  cover the nonce model and its proofs (22 pure-zone files).

## [0.3.0-dev] — M2 TLS 1.3 record model — 2026-06-11

Third implementation milestone (RFC 004). Adds the TLS 1.3 record model — the
outer/inner content-type distinction, the read/write record paths as core
actions, and the *no unauthenticated plaintext* proof — on top of the M0 core and
M1 parser. Still no real crypto and no sockets: AEAD seal/open are *requested* by
the core and their results fed back as events, exactly as the interpreter will
later drive them.

### Added — record model (`Kroopt.Core.Record`, `Kroopt.Parse.Record`)

- `ContentType` with wire-byte `toByte`/`ofByte` (unknown bytes decode to the
  explicit `invalid`, never a real type).
- `BoundedBytes max` — a byte string whose length bound is a field, so an
  over-length record body is unconstructable; record size limits are enforced
  *by construction*.
- `TLSPlaintext` / `TLSInnerPlaintext` / `TLSCiphertext` — the three record
  shapes keeping the outer `application_data` vs real inner content type
  distinct.
- Record framing: `takeRecordHeader` (rejects oversize length at the header,
  before allocation), `tryTakeRecord` (returns "need more" until a full record is
  buffered — reassembly), `parseInnerPlaintext` (strip padding, read inner type;
  safe list ops, no unchecked indexing), and `classifyCcs` (accept only the
  `0x01` compatibility CCS).

### Added — record path (`Kroopt.Core.RecordPath`, wired into `step`)

- Inbound: reassemble → frame → request `aeadOpen` → on success validate inner
  type and buffer application content → deliver via the existing connected
  `recv` path; auth failure is fatal with no plaintext.
- Outbound: connected `send` fragments to ≤ 2¹⁴, requests `aeadSeal`, and
  acknowledges ownership with `acceptPlaintextBytes`.
- Sequence numbers advance per direction with overflow checked before use; the
  core requests crypto and never calls it.

### Added — proofs (`Kroopt.Proofs.RecordPath`)

- `buffered_plaintext_authenticated` / `buffered_plaintext_provenance` — **no
  unauthenticated plaintext**: buffered application plaintext arises only from a
  successful `aeadOpened` result in `connected` state.
- `aead_open_failure_no_plaintext` — open failure emits no plaintext and is
  terminal.
- Handler no-emit / no-accept lemmas; the M0 `no_plaintext_emit_unless_connected`
  re-proved over the extended `step`, plus `accept_plaintext_only_connected`.
- All machine-checked, no `sorry`/`axiom`/`unsafe`; `#print axioms` shows only
  `propext` (some also `Quot.sound`).

### Added — tests, docs

- `Tests/Record.lean` (`kroopt-record-test`) — 19 checks: header parse, oversize
  reject, reassembly split points, inner-type validation, CCS accept/reject, and
  fake AEAD-open success (buffers plaintext) vs failure (buffers none, goes
  terminal); all passing.
- `docs/src/record-model.md`; expanded theorem inventory and proof-assumptions.

### Changed

- `Core.State` gained record buffers (`inboundCiphertext`, `outboundCiphertext`)
  and an op-id counter; `step`'s M0 placeholder arms became real record
  transitions. The proof-hygiene and dependency gates now cover the record
  modules (19 pure-zone files).

## [0.2.0-dev] — M1 bounds-safe parser foundation — 2026-06-11

Second implementation milestone (RFC 003). Adds the pure parsing/framing
foundation with bounds-safety proofs, on top of the M0 core. Still no crypto and
no sockets. (Per the roadmap, the released `v0.1` "synthetic handshake and record
core" line is reached once M1–M5 all land; these `0.x.0-dev` tags are internal
per-milestone snapshots.)

### Added — parser foundation (`Kroopt.Parse`)

- `Reader` — a byte cursor carrying its own `offset ≤ input.size` proof, so
  out-of-bounds readers are unconstructable (*bounds-safety by construction*).
- `UInt24` — a dedicated 24-bit wrapper for handshake lengths (RFC 003 §9.2), in
  place of an unchecked `UInt32` cast.
- Primitives — `takeBytes`, `takeU8`/`U16`/`U24`/`U32` (big-endian), `takeLen`
  (8/16/24-bit prefixes), `remaining`, `atEnd`, `expectEnd`.
- `takeVectorBytes` — length-prefixed byte vector with a `maxLen` budget check
  plus the remaining-input check; the framer the record/extension parsers build
  on.
- `takeCountedItems` — fuel-bounded item combinator (no unbounded recursion over
  attacker-controlled counts).
- `ParseError` — internal typed parse errors with positions/sizes but no raw
  bytes, plus `toPublic` projecting onto the redacted `Kroopt.ParseError`.

### Added — proofs (`Kroopt.Parse.Proofs`, module `Kroopt.Proofs.ParserBounds`)

- `reader_in_bounds`, `takeBytes_bounds`/`_mono`, `takeU8`/`U16`/`U24`/`U32_bounds`,
  `takeLen_bounds`, `takeVectorBytes_bounds`, and the umbrella `parser_bounds_safe`
  — every successful read advances the cursor monotonically, stays within the
  buffer, and preserves the buffer. All machine-checked, no `sorry`/`axiom`/
  `unsafe`; verified via `#print axioms` to depend only on `propext` (some also
  `Quot.sound`).

### Added — tests, fuzzing, docs

- `Tests/Parse.lean` (`kroopt-parse-test`) — 18 unit + negative checks (decode,
  truncation, over-budget length, trailing bytes, fuel exhaustion); all passing.
- `Tests/Fuzz.lean` (`kroopt-parse-fuzz`) — deterministic bounded smoke fuzzer
  asserting the reader invariant across pseudo-random buffers (50k iterations,
  zero violations).
- `docs/src/parser.md` and an expanded theorem inventory / proof-assumptions
  register.

### Changed

- The proof-hygiene and module-dependency gates now cover `Kroopt/Parse`.
- `Kroopt.Parse` depends only on `Kroopt.Error`, keeping it a pure sibling of the
  core (enforced by `scripts/check-deps.sh`).

## [0.1.0-dev] — M0 verified-core skeleton — 2026-06-11

First implementation milestone (RFC 001, 002, 022, 024). Establishes the
pure-core/interpreter architecture with machine-checked safety properties, ahead
of any real crypto or sockets.

### Added — verified core (`Kroopt.Core`)

- `Error` — typed, redaction-safe error and alert taxonomy (all enums; no
  secret-bearing fields), with a coarse `TlsError.category` for logging.
- `Id` — `ConnId` (value + generation), `OperationId`, `ConfigGeneration`.
- `Common` — `CloseMode`, `TimeoutKind`.
- `CipherSuite` — `HashAlgorithm`, `CipherSuite` (+ bound hash), `NamedGroup`,
  `SignatureScheme`.
- `Record` — `Direction`, `Epoch`, `SeqNo` with an overflow-checked `next` that
  returns `none` at the maximum (no silent wrap; RFC 005 §7.2), `EpochState`.
- `Crypto` — crypto-as-action shapes: non-printable `SecretKeyHandle`,
  `RecordCryptoMeta`, `CryptoOpKind`, `CryptoOp`/`CryptoResult`, and the
  pending-op correlation table. Secret-bearing types derive no
  `Repr`/`BEq`/`Hashable` (RFC 018 §3.5).
- `Transcript` — `TranscriptDigestHandle`, `TranscriptState` (minimal M0 shape).
- `State` — `HandshakeState` (16 phases incl. `failed`), `CloseState`,
  `NegotiationState`, `BudgetState`, and the single authoritative `State` with
  `initial` and a redacted diagnostic summary. `State` derives no `Repr`
  (transiently holds authenticated plaintext).
- `Event` / `Action` — `InputEvent` and `OutputAction`, with the classifier
  predicates the proofs quantify over (`isPlaintextEmit`, etc.).
- `Step` — the `step : State → InputEvent → Except TlsError (State × List
  OutputAction)` transition function (M0 shape: correct discipline, no real TLS
  logic yet).

### Added — proofs (`Kroopt.Proofs`)

- `step_deterministic`, `terminal_absorbing`, `terminal_no_error`,
  `no_plaintext_emit_unless_connected` (*no early plaintext*), and
  `no_plaintext_after_terminal`. All machine-checked, no `sorry`/`axiom`/
  `unsafe`; verified via `#print axioms` to depend only on `propext`.

### Added — tests, gates, docs

- `Tests/Model.lean` — deterministic model test driving `step` directly (9
  checks, all passing).
- `scripts/check-hygiene.sh` — RFC 022 proof-hygiene gate (no forbidden
  constructs in the strict zones).
- `scripts/check-deps.sh` — RFC 022 module-dependency gate (verified core may
  not import the interpreter, crypto provider, native shim, or iotakt).
- `docs/src/` — mdbook docs: introduction, boundary, theorem inventory, and the
  proof-assumptions register.

### Project

- Incorporated the ROADMAP and full RFC set (managed under the lifecycle policy)
  into the repository. RFCs remain `Proposed`; their M0 slices are implemented
  but the RFCs are not yet fully realized, so they stay in `rfcs/proposed/`.
- Lake package builds standalone on a clean Lean install — no mathlib, no C
  toolchain, no network reactor (RFC 024 `core` profile).
