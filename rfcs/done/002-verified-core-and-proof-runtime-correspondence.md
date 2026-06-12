# RFC 002 — Verified Core and Proof/Runtime Correspondence

**Project.** kroopt  
**Status.** Implemented (0.24.0-dev)  
**Type.** Implementation RFC  
**Target milestone.** M0  
**Depends on.** RFC 001  
**Touches.** `Kroopt/Core/` (`Event`, `Action`, `State`, `Step`); `Kroopt/Proofs/`  
**Canonical source.** kroopt fixed requirements and external design.  

---

## 1. Summary

This RFC defines kroopt's most important architectural mechanism: the TLS protocol is implemented as a pure Lean state transition core that emits output actions. Runtime code interprets those actions over iotakt and the crypto provider. The interpreter must not re-implement protocol decisions.

The verified core is the only place where state transitions, handshake sequencing, record admissibility, plaintext emission, key epoch installation, alert decisions, and transcript update ordering are decided.

## 2. Goals

- Define the core `step` interface.
- Define `InputEvent`, `OutputAction`, `CryptoOp`, `CryptoResult`, and `State` at the external-design level.
- Prevent model/runtime drift.
- Make the proof target executable by tests.
- Provide a foundation for deterministic tests and later iotakt/HACL integration.

## 3. Core API sketch

```lean
namespace Kroopt.Core

structure ConnId where
  value : UInt64
  generation : UInt64
  deriving DecidableEq

structure OperationId where
  value : UInt64
  deriving DecidableEq, Ord

inductive InputEvent where
  | transportBytes (conn : ConnId) (b : ByteArray)
  | transportReadable (conn : ConnId)
  | transportWritable (conn : ConnId)
  | cryptoResult (conn : ConnId) (op : OperationId) (r : CryptoResult)
  | appSend (conn : ConnId) (b : ByteArray)
  | appRecvRequested (conn : ConnId)
  | appFlush (conn : ConnId)
  | appClose (conn : ConnId)
  | timeout (conn : ConnId) (kind : TimeoutKind)

inductive OutputAction where
  | readTransport (conn : ConnId)
  | writeTransport (conn : ConnId) (b : ByteArray)
  | enableWriteInterest (conn : ConnId)
  | disableWriteInterest (conn : ConnId)
  | callCrypto (conn : ConnId) (op : OperationId) (request : CryptoOp)
  | emitPlaintext (conn : ConnId) (b : ByteArray)
  | reportHandshakeComplete (conn : ConnId) (info : HandshakeInfo)
  | reportError (conn : ConnId) (e : TlsError)
  | failWithAlert (conn : ConnId) (a : AlertDescription)
  | closeTransport (conn : ConnId) (mode : CloseMode)

def step : State -> InputEvent -> Except TlsError (State × List OutputAction)
```

The exact Lean signatures may change, but these principles must not:

- the core is pure;
- crypto is represented as an action/result pair (the resolved design — see §3.1) rather than an inline effectful call;
- every result is correlated to connection and operation id;
- the interpreter is action-only.

### 3.1 Design decision: crypto-as-action (resolves requirements §23 Q3)

Requirements §23 Q3 leaves one real architectural choice open: represent crypto
as an `OutputAction`/`cryptoResult` pair (the core stays fully pure and effect-free;
results re-enter as input events), or parameterize the core over a pure
`CryptoProvider` and prove over that abstraction. Both keep the core effect-free;
the requirement asks the resolving RFC to pick on proof ergonomics. This RFC
resolves it.

**Decision. The core uses crypto-as-action.** `callCrypto` is an `OutputAction`;
the provider runs in the interpreter; results re-enter `step` as
`InputEvent.cryptoResult` correlated by `OperationId`. The pure-provider
parameterization is permitted only as a *test-time* convenience inside the fake
harness (RFC 014), never as the production core's effect path.

Rationale:

1. **One uniform audit surface.** Every externally visible effect — transport
   reads/writes, plaintext emission, alerts, close, *and* crypto — is a single
   `OutputAction` list. Reviewers and proofs inspect one stream. A
   `CryptoProvider` type-class parameter would split effects into two shapes
   (actions for I/O, method calls for crypto), weakening the "every side effect
   is an action" property that RFC 001/002 rely on.
2. **Stale-result defense is first-class.** Modeling crypto results as events
   forces the `pendingOps`/`OperationId` correlation (§6.1) into the core's
   proof obligations, where stale/duplicate/wrong-kind results are rejected by
   construction. With a synchronous provider method, that correlation tends to
   leak into the interpreter and escape the proofs.
3. **Async-ready without rework.** A future asynchronous or worker-pool provider
   (RFC 016 performance scope) changes only the interpreter's scheduling of
   `callCrypto`; the core and its proofs are unchanged because they never
   assumed synchronous return.
4. **Proof ergonomics.** Theorems quantify over `step` and the emitted
   `OutputAction` list (key separation, nonce uniqueness, no-early/no-unauth
   plaintext) without carrying a `CryptoProvider` instance through every lemma.
   The provider's correctness is an *assumption* about the interpreter, not a
   parameter of the core's theorems.

Cost accepted: a handshake step is split across several `step` calls
(`callCrypto` → `cryptoResult` → next action), which is more ceremony than an
inline call. That ceremony is the same property that makes the core auditable
(§6.2) and is therefore intentional.

The fake-provider exception (RFC 014) runs deterministic crypto behind an `IO`
wrapper so model tests can drive a full synthetic handshake; it still enforces
`OperationId`/epoch/direction metadata so the core never depends on impossible
provider behavior.

## 4. State model

The `State` must be a single authoritative value containing at least:

```lean
structure State where
  connId          : ConnId
  handshake       : HandshakeState
  configGen       : ConfigGeneration
  readEpoch        : EpochState
  writeEpoch       : EpochState
  readSeq          : SeqNo
  writeSeq         : SeqNo
  pendingOps       : PendingCryptoOps
  inRecordBuf      : BoundedBuffer
  pendingCipherOut : BoundedQueue ByteArray
  pendingPlainOut  : Option ByteArray
  transcript       : TranscriptState
  negotiated       : NegotiationState
  closeState       : CloseState
  budgets          : BudgetState
```

The core state stores handles and abstract identifiers, not raw long-lived secrets.

## 5. Proof/runtime correspondence rules

1. Runtime code must call `step` for every external event that can affect TLS state.
2. Runtime code may dispatch on `OutputAction` constructors but must not dispatch on handshake state to decide protocol behavior.
3. Runtime code may maintain interpreter-local transport queues, but those queues must correspond to core-issued actions and bounded state.
4. A crypto result not found in `pendingOps` is a stale result and must be rejected.
5. A transport event with the wrong connection generation must be ignored or rejected before reaching the core.
6. An action emitted by a terminal core state must obey terminal-state proof obligations.

## 6. Internal design

### 6.1 Operation correlation

Every `callCrypto` action includes:

- `OperationId`;
- expected result kind;
- epoch and direction;
- transcript snapshot id where relevant;
- connection id and config generation;
- a small non-secret debug tag.

`PendingCryptoOps` maps operation id to expected metadata. `cryptoResult` must match this metadata exactly. A mismatch is a fatal internal error or deterministic alert depending on whether attacker-controlled input could have caused it.

### 6.2 Action emission discipline

Actions should be emitted in small, explicit batches. For example, a handshake step may emit:

1. `callCrypto ECDHE`
2. after result: `callCrypto HKDF`
3. after result: `writeTransport ServerHello`

This avoids hiding side effects inside a single giant action and keeps tests inspectable.

### 6.3 State transitions as constructors

Prefer named transition functions such as:

```lean
def onClientHello : State -> ValidClientHello -> Except TlsError (State × List OutputAction)
def onEcdheResult : State -> OperationId -> SharedSecretHandle -> Except TlsError (State × List OutputAction)
def onAppSendConnected : State -> ByteArray -> Except TlsError (State × List OutputAction)
```

Then `step` is a dispatcher into these transition functions. Proofs can target either the dispatcher or each named transition plus composition lemmas.

## 7. Proof obligations

- Determinism of `step` for the same state and input.
- Legal transition theorem for `HandshakeState`.
- No `emitPlaintext` before connected.
- No `callCrypto` with an epoch/direction inconsistent with state.
- No stale crypto result accepted.
- Terminal states emit no application plaintext and no ordinary write actions.
- State budgets monotonically consume or remain unchanged, never increase except on explicit rekey/config-reset events.

## 8. Testing requirements

- Golden tests for each input event in each major state.
- Property tests over random but well-typed event sequences to ensure terminal behavior and no early plaintext.
- Interpreter faithfulness tests that compare action traces against fake runtime side effects.
- Mutation tests or explicit negative tests proving that stale operation ids are rejected.

## 9. Security notes

This RFC prevents a dangerous class of TLS implementation bugs: where parse logic, state logic, crypto calls, and transport retries are spread across multiple imperative loops. The cost is more ceremony in the core/action interface. That ceremony is intentional; it is the shape that makes kroopt auditable.

## 10. Acceptance criteria

- The core `step` API exists and compiles.
- The interpreter can be implemented without inspecting private protocol internals.
- The repository includes a module-dependency rule or review checklist preventing core-to-FFI and core-to-iotakt imports.
- Stale crypto result handling is modeled.
- The first proof skeletons target `step`, not an informal model separate from implementation.
