# RFC 040 — Native Traffic-Secret Arena and the IO Production Interpreter

**Project.** kroopt
**Status.** Proposed — design in progress (0.123.x). Preconditions met: RFC 031 done (pure
proof/runtime correspondence locked); RFC 037's native zeroizing arena exists and is sanitizer-clean;
RFC 013 done. **RFC 037 does not block RFC 040** — RFC 040 *is* the remaining traffic-secret migration
branch of that broader native-secret arc (037 built the C-owned arena and put the config-lifetime signing
key on it; 040 migrates the connection-lifetime traffic secrets onto it).
**Type.** Implementation RFC.
**Target milestone.** Stable / v1 gate (not a pre-stable precondition).
**Depends on.** RFC 031 (done), RFC 037 (native zeroizing arena — precondition met), RFC 013 (done).
**Branch (architect review 2026-06-30).** Sync-first; staged native crypto surface; proved-shared-core +
tested IO lift. Async sealing/open offload is an explicit **non-goal** here (§11) and moves to a follow-up
RFC (likely 044).
**Companion handoff.** [`../handoffs/self/040-native-traffic-secret-arena/`](../handoffs/self/040-native-traffic-secret-arena/README.md)
— detailed internal design, slice/PR plan, and Slice 1 acceptance/QA checklist.
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

### 4.4 Handle defenses now; live async result path deferred (architect review 2026-06-30)

Under the sync-first branch (§11), the IO production interpreter executes crypto as **synchronous**
handle-consuming FFI calls within each drive — there is **no live asynchronous sealing path in this RFC**.
RFC 040 therefore designs the handle defenses that *also* make the architecture async-ready, but **does not
exercise** an async result path and **claims no live async correspondence evidence**.

What RFC 040 owns (necessary for sync-first correctness, and async-ready by construction):

```text
generation-bearing handles (connectionId × generation × slotId × kind);
a stale handle fails closed and never aliases fresh secret memory;
a terminal/closed connection invalidates its handles;
a released slot is never re-aliased into a fresh connection generation.
```

What moves to a follow-up RFC (likely **044**, created only when async offload is actually needed):

```text
the live asynchronous seal/open offload path;
the duplicate / stale-cross-generation / after-terminal result negative-space and its tests;
the jemmet egress-accounting contract change.
```

**Why the jemmet contract change is deferred, not silently broken.** Today `TlsConn.ownedOutboundBytes`
(= `rt.outbound.size`, queued ciphertext) is the *complete* kroopt-owned egress footprint, because the
synchronous provider seals accepted plaintext within the same `send` drive — no accepted-but-unencrypted
plaintext persists between calls, so jemmet sets its `connOwnedPlaintext` tier to zero for TLS (the
0.114.0-dev §6 commitment). **Sync-first preserves that invariant exactly: there is no in-flight accepted
plaintext after a drive returns, no async accepted-plaintext queue, and `connOwnedPlaintext` stays 0.** A
future async seal path would hold accepted plaintext across calls, making a second egress tier observable;
**that** is the explicit jemmet contract change — kroopt would then expose an in-flight accepted-plaintext
byte count (a companion to `ownedOutboundBytes`) and notify jemmet — and it is owned by the async follow-up
RFC, not smuggled into this v1 cleanup.

Note: AEAD *open* by handle still returns authenticated **plaintext** to Lean/jemmet — that is inbound
application data, a different class from traffic-secret residency, and RFC 040 makes no claim that
application plaintext never enters Lean. It claims only that *secret* material (keys, IVs/base nonces,
traffic secrets, HKDF intermediates) is native-owned end-to-end once the staged migration completes (§12).

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

Per the RFC 031 lock (architect review 2026-06-15), traffic-secret native residency must not be claimed
via RFC 031. Under the sync-first branch RFC 040 designs the **async-ready handle defenses** (§4.4) —
generation-bearing handles, stale-fails-closed, terminal invalidation, no released-slot aliasing — but
does **not** exercise a live async path and evidences **no** live async correspondence. The live async
result path, its duplicate / stale-cross-generation / after-terminal negative-space tests, and the jemmet
egress-accounting contract change are owned by the async follow-up RFC (§11), not by RFC 040.

## 11. Non-goals (this RFC)

- **No asynchronous sealing/open offload.** RFC 040 is synchronous-FFI only. Async crypto offload —
  out-of-band result correlation, in-flight accepted-plaintext accounting, duplicate/stale/after-terminal
  completion, cancellation, backpressure, and the jemmet egress-accounting contract change — is a separate
  throughput problem and moves to a follow-up RFC (likely **044**), created only when async offload is
  actually needed. RFC 040 designs the handle defenses that make this *possible later* (§4.4) without
  enabling it now.
- **No trust-matrix promotion before the migration is complete** (§12). Intermediate slices reduce exposure
  but the claim stays *best-effort* until every connection-lifetime secret class is native-owned end-to-end.

## 12. Staged migration plan and per-slice trust posture

The native crypto surface migrates in slices (Decision 2 = staged). The trust matrix is **not** promoted
until the final slice; each slice states honestly what remains in Lean.

```text
Slice 1 — handle ABI + AEAD-by-handle (exposure-reduction only)
  SecretHandle ABI; slot typing; connection/generation/kind/direction validation; stale-fails-closed;
  native AEAD seal/open by handle; live per-record AEAD uses handles.
  HKDF/key-schedule derivation STILL in Lean ⇒ key/IV bytes are imported into native handles from Lean.
  Trust posture: connection traffic-secret zeroization = BEST-EFFORT (unchanged);
                 AEAD record-path native handle use = partial / exposure reduced.
  NO promotion.

Slice 2 — key schedule by handle
  HKDF-Extract and HKDF-Expand-Label by handle; early/handshake/master + traffic-secret derivation by
  handle; Finished-key derivation by handle. Derived secrets are produced as handles, not bytes.
  Trust posture: still BEST-EFFORT unless every connection-lifetime secret class is covered. NO promotion.

Slice 3 — full record-protection state by handle + promotion
  client/server handshake + application traffic secrets; write/read AEAD keys; IV/base-nonce material;
  key-update secrets; close/terminal cleanup — all native-owned, no post-derivation Lean residency.
  Promotion ALLOWED only after the §12.1 gate holds.
```

Slices 2 and 3 may land together if clean; **Slice 1 is not blocked on them.**

### 12.1 Promotion gate

The trust matrix moves traffic-secret zeroization from *best-effort* to *tested native zeroization* only
when **all** hold:

```text
traffic secrets do not live in Lean after derivation;
AEAD keys and IV/base-nonce material do not live in Lean after derivation;
finished keys and relevant HKDF intermediates are native-owned;
key updates preserve native ownership;
close/failure paths release and zeroize (zeroization evidenced via test-only instrumentation, not ASan alone);
the pure decision core is shared (proved); the IO lift is differentially tested;
native secret paths are sanitizer-clean; no raw-secret logging/Repr; side effects documented honestly.
```

Resulting claim wording (not before):

```text
tested native zeroization for connection traffic-secret residency, over a proved shared protocol
decision core; the native zeroization implementation is trusted/tested, not Lean-proven.
```
