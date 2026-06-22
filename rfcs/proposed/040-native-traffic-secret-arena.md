# RFC 040 — Native Traffic-Secret Arena and the IO Production Interpreter

**Project.** kroopt
**Status.** Proposed — **blocked on RFC 031** (not started).
**Type.** Implementation RFC.
**Target milestone.** Stable / v1 gate (not a pre-stable precondition).
**Depends on.** RFC 031 (pure proof/runtime correspondence must land first), RFC 037 (the
C-owned `NativeSecret` arena exists and is sanitizer-clean), RFC 013 (secret handling).
**Touches.** `Kroopt/Conn` (a new IO production interpreter), `Kroopt/Crypto` (`NativeSecret`,
the production provider), the trust-matrix docs.
**Canonical source.** kroopt fixed requirements and external design; this RFC records the
architect-reviewed decision on the traffic-secret C-arena migration.

---

## 1. Summary and decision context

Connection-lifetime **traffic secrets** (the ECDHE shared secret, the HKDF handshake/application
traffic secrets, and the per-record AEAD keys/IVs) currently live in the pure Lean `SecretArena`
(GC-managed `ByteArray` storage), so their zeroization is **best-effort**. The config-lifetime
**server private key** is already C-owned and explicitly zeroized (RFC 037); traffic secrets are
the connection-lifetime remainder.

The decision (architect review) is **D now, A later**: keep the honest best-effort posture for
the pre-stable line, and migrate via a **two-interpreter** architecture as a **stable/v1 gate**,
sequenced **after RFC 031**. This RFC specifies that migration. It is intentionally not yet in
progress — it must not start until RFC 031 has locked the pure correspondence, so the IO
production interpreter has a fixed pure model to correspond to.

## 2. Why this is deferred, not mechanical

The secret store/read/zeroize points sit *inside* the pure layer: `CryptoProvider.submit` stores
derived secrets in the pure arena, and `Conn.Interpreter.driveEvents` reads them mid-pipeline to
seal/open. Backing them with the native (IO) arena makes those points effectful, which would
collapse the pure, deterministic, replayable interpreter that the proofs and the RFC 031
correspondence rely on. Real zeroization therefore costs an IO interpreter — a change to the
*shape* of the proof/runtime-correspondence layer, not a memory-management patch.

Option B (IO-ify the single interpreter) is **rejected**: it puts the proof spine at risk by
making `driveEvents` non-pure at the type level. Option C (partial base-secret migration) is not
the default path — only revisit under a dedicated RFC with a very narrow, non-overstated claim.

## 3. Architecture — two interpreters

```text
Pure interpreter (unchanged):
  Core.step · pure CryptoProvider · pure SecretArena · pure driveEvents
  → the deterministic executable MODEL: proofs, replay tests, correspondence source of truth.

IO production interpreter (new):
  native C-owned zeroizing secret arena · live-server use · production hardening
  → makes NO additional protocol decisions; executes the same core-authorized actions.

Correspondence (proved/tested):
  same core actions · same state transitions · same selected suite/group/signature ·
  same transcript events · same alert behavior · same plaintext/ciphertext (modulo randomness) ·
  no extra protocol decisions in the IO interpreter.
```

The pure interpreter remains **permanently** the executable specification; the IO interpreter is
added for live-server use and shown to correspond to it.

## 4. Production secret-runtime contract

### 4.1 Production avoids `read` returning secret bytes to Lean

`NativeSecret` exposes `alloc/read/zeroize/release`, but for production traffic secrets `read`
must **not** be the normal path — returning bytes to Lean re-exposes them to GC-managed memory and
defeats the zeroization benefit. The production contract is **handle-in, handle-out**:

```text
HKDF extract/expand, AEAD seal/open, and key derivation CONSUME SecretHandle values.
Derived secrets are PRODUCED as new SecretHandle values.
Lean receives PUBLIC outputs only: ciphertext, authenticated plaintext, transcript hashes, errors.
```

This requires the native shim to grow handle-consuming derive/seal/open entry points (not just
byte-returning `read`), so secret bytes never round-trip through Lean.

### 4.2 Secret classes

| Class | Members | Lifetime | Owner / posture |
|-------|---------|----------|-----------------|
| `ConfigSecret` | server private / signing key | process / config | native-owned **today** |
| `ConnectionSecret` | ECDHE shared secret; handshake & application traffic secrets; AEAD key; IV/base nonce | connection / epoch | native-owned **under this RFC** |
| `EphemeralDerivedSecret` | intermediate HKDF outputs | operation / step | native temporary where feasible |

Each class declares an owner, lifetime, release point, and a logging/`Repr` prohibition.

### 4.3 Handle generation and stale-handle defense

Native traffic-secret handles carry connection/generation namespace protection:

```text
SecretHandle = connectionId × generation × slotId × kind
```

A stale handle after close/release **fails closed** and must never alias newly-allocated secret
memory (the monotonic, never-reused id discipline of `NativeSecret` extends to per-connection
generations).

## 5. Correspondence tests (pure ↔ IO)

The IO production interpreter is tested against the pure interpreter on scripted inputs, comparing
**public observations only** (never raw secrets): same core actions, same selected
suite/group/signature, same transcript events, same alert behavior, same plaintext/ciphertext
(modulo randomness). Golden traces are taken from the pure interpreter.

## 6. Failure cleanup

The IO production interpreter releases/zeroizes connection secrets on **every** terminal path:
normal `close_notify`; fatal alert; parse failure; provider failure; resource-budget failure;
stale crypto result; transport close/error; and any recoverable interpreter-failure path.

## 7. Sanitizer and leak tests

ASan/UBSan on the native arena and crypto shim; double-release tests; stale-handle tests;
release-on-failure tests; no-retained-Lean-pointer tests; no-raw-secret-logging tests.

## 8. Sequencing

1. **Finish RFC 031** — lock the pure proof/runtime correspondence (core ↔ pure interpreter).
2. **This RFC (040)** — production IO interpreter boundary; native secret-handle model; C-side
   secret-operation contract; pure↔IO correspondence; release/failure cleanup; trust-matrix updates.
3. **Implement Option A** — keep the pure interpreter as the model; add the IO production interpreter.
4. **Promote the claim** — only then may the trust matrix move traffic-secret zeroization from
   *best-effort* to *tested native zeroization*.

## 9. Acceptance criteria

1. The pure interpreter remains the deterministic executable model; its proofs and the RFC 031
   correspondence are untouched.
2. Connection traffic secrets are native-owned; secret bytes do not round-trip through Lean in
   production (handle-in/handle-out).
3. The IO production interpreter is shown to correspond to the pure interpreter on public
   observations.
4. All terminal paths release/zeroize connection secrets; sanitizer/leak tests pass.
5. Only after the above does any doc promote traffic-secret zeroization beyond best-effort.

## 10. Stable/v1 gate

Real traffic-secret zeroization is a **stable/v1 gate**: pre-stable interop and protocol work may
continue with documented best-effort traffic-secret zeroization; a stable/v1 release requires this
RFC (or an explicit owner-approved exception).
