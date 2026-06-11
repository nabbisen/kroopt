# Changelog

All notable changes to kroopt are recorded here. RFC lifecycle transitions are
governed by [`rfcs/done/000-rfc-lifecycle-policy.md`](rfcs/done/000-rfc-lifecycle-policy.md).

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
