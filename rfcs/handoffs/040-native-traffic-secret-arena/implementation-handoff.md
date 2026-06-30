# RFC 040 — implementation handoff (detailed internal design)

**Companion to.** [`../../proposed/040-native-traffic-secret-arena.md`](../../proposed/040-native-traffic-secret-arena.md)
**Status.** Inherited from RFC 040 (Proposed — design in progress). Branch: **sync-first, staged,
proved-shared-core + tested IO lift** (architect review 2026-06-30).
**Authority.** The RFC owns *what/why*; this handoff owns *how to implement and verify*. If this handoff and
the RFC ever disagree, fix the RFC first, then this handoff (RFC 000 policy).

This document covers the 14 internal-design sections the review requires **before implementation starts**. It
is written so Slice 1 is mechanical and Slices 2–3 are planned.

---

## 1. Secret classes and ownership table

| Class | Members | Lifetime | Owner today | Owner end-state (040) | Release point |
|-------|---------|----------|-------------|-----------------------|---------------|
| `ConfigSecret` | server signing key (Ed25519; later ECDSA/RSA) | process/config | **native** (RFC 037) | native | process/config teardown |
| `ConnectionSecret` | ECDHE shared secret; handshake & application traffic secrets (client/server); AEAD read/write keys; IV/base-nonce; finished keys; key-update secrets | connection/epoch | **pure Lean arena** | **native (this RFC)** | every terminal path + epoch/key-update replacement |
| `EphemeralDerivedSecret` | intermediate HKDF outputs (Extract PRK, Expand stages) | operation/step | pure Lean | native temporary where feasible | immediately after the consuming op |

Every secret-bearing value declares: owner, lifetime, release point, and a logging/`Repr` prohibition (§9).
**Slice boundary:** Slice 1 makes only the AEAD read/write **keys** and **IV/base-nonce** flow through native
handles on the record path (imported from Lean-derived bytes); all *derivation* stays in Lean until Slice 2.

## 2. Native handle ABI

Modeled on the existing `Kroopt.Crypto.NativeSecret` over `kroopt_ffi_secret_*` (monotonic non-reused ids,
volatile-store wipe on zeroize/release, ASan/UBSan-clean) and the `ed25519SignH` by-handle precedent.

```text
SecretHandle (opaque, native-side identity):
  connectionId : u64      -- per-connection namespace
  generation   : u64      -- per-connection monotonic; bumped on terminal/key-update
  slotId       : u64      -- monotonic, never reused within the arena
  kind         : SlotKind -- §2.1
  -- (the Lean wrapper carries the same tuple as a non-Repr value; §9)

New native entry points (Slice 1):
  kroopt_ffi_aead_seal_h(handle_key, handle_iv, seq, aad, plaintext)  -> ciphertext | error
  kroopt_ffi_aead_open_h(handle_key, handle_iv, seq, aad, ciphertext) -> plaintext  | error
  kroopt_ffi_secret_import(kind, conn, gen, bytes) -> SecretHandle      -- copies into arena, wipes source caller-side
  kroopt_ffi_secret_release(handle)                                     -- zeroize + invalidate slot
Later slices add: kroopt_ffi_hkdf_extract_h, kroopt_ffi_hkdf_expand_label_h, derive-by-handle.
```

Every entry point: explicit length params, immediate status capture, output buffer owned by a single
documented owner, **no retained Lean pointer**, imported secret bytes **copied** into the arena (never
aliased), caller-side source bytes wiped after import.

### 2.1 `SlotKind` (Adjustment 2 — precise, not just "secret")

```text
SlotKind = trafficSecret | aeadKey | aeadIvBaseNonce | finishedKey
         | exporterSecret? | resumptionSecret?     -- only if/when present
         | hkdfTemporary
```

AEAD seal/open accept **only** `aeadKey` for the key handle and `aeadIvBaseNonce` for the IV handle, and only
for the matching connection/generation/direction/epoch (§5, §7). A wrong-kind handle fails closed.

## 3. Slot lifecycle state machine

```text
            import / derive-by-handle
   (none) ───────────────────────────▶ Live(slotId, kind, conn, gen)
                                          │   │
                  use (seal/open/derive)  │   │ epoch change / key-update / terminal
                   re-validates every     │   ▼
                   field, never mutates ──┘  Released(slotId)   ── zeroized, invalid, never re-aliased
                                              ▲
                                              │ release is idempotent; double-release is observable in
                                              │ debug/test instrumentation (Adjustment 4)
```

A handle in `Released` (or any handle whose connection is terminal) **fails closed** on use. A released
`slotId` is never reused; a released slot is never re-aliased into a fresh connection generation (§4).

## 4. Generation and connection binding (Adjustment 1 — forging must be harmless)

Do **not** rely on handle secrecy/unforgeability. Treat handles as weak in-process capabilities. The native
side **validates every field on every use**:

```text
connectionId matches the operation's connection;
generation matches the connection's current generation;
slotId is Live (not Released);
kind is the kind the operation requires;
direction (read/write) matches;
epoch / secret class matches if encoded;
cipher suite matches if relevant;
the connection is not in a terminal/closed state.
```

Any mismatch ⇒ **fail closed, no memory disclosure, no aliasing of fresh memory.** Generation is bumped on
every terminal path and on key-update, which atomically invalidates all of a connection's handles.

## 5. AEAD seal/open handle contract

```text
seal(writeKeyH : aeadKey, writeIvH : aeadIvBaseNonce, seq, aad, plaintext) -> ciphertext
open(readKeyH  : aeadKey, readIvH  : aeadIvBaseNonce, seq, aad, ciphertext) -> plaintext | authFail
```

- Nonce = ivBase XOR padded(seq) is computed **native-side** from the IV handle; the IV/base-nonce bytes
  never return to Lean.
- `seq` is supplied by the core (per-direction, monotonic, overflow-fatal upstream — unchanged).
- Lean receives: ciphertext (seal), authenticated plaintext (open), or a typed error. **No secret bytes.**
- The existing `Record13.sealRecord` 2^14 bound and `Except` rejection stay in the pure core *above* this
  call; the handle contract does not relax record bounds.
- `open` returning authenticated plaintext to Lean/jemmet is **inbound application data**, not a secret
  (Adjustment 6 / §14). It is delivered synchronously within the drive; no in-flight accepted-plaintext
  queue exists, so jemmet's `connOwnedPlaintext` stays 0.

## 6. HKDF / key-schedule migration plan (Slices 2–3)

```text
Slice 2: kroopt_ffi_hkdf_extract_h, kroopt_ffi_hkdf_expand_label_h consume/produce handles.
         Key-schedule nodes (early/handshake/master secrets; client/server traffic secrets; finished keys)
         derived by handle; outputs are handles, never bytes.
Slice 3: AEAD keys + IV/base-nonce derived directly into handles (no Lean import); key-update derives the
         next generation by handle; close/terminal cleanup releases all.
```

Until Slice 2 lands, Slice 1 **imports** Lean-derived key/IV bytes into handles — so those bytes still
transit Lean before import. This is stated honestly per slice (§13) and blocks promotion (§12.1 of the RFC).

## 7. Read/write direction and epoch typing

Lean-side wrapper types make direction/epoch non-interchangeable (no bare `ByteArray`):

```text
WriteKeyHandle ≠ ReadKeyHandle ; HandshakeEpoch ≠ ApplicationEpoch
ClientTrafficSecretHandle ≠ ServerTrafficSecretHandle ; aeadKey handle ≠ aeadIvBaseNonce handle
```

The native side also carries direction/epoch in the slot and rejects mismatched use (§4). This is the §9.6
key-separation discipline of the external design, enforced at both the Lean type level and the native
validation level.

## 8. Close / fatal / key-update cleanup (Adjustment 4)

Explicit release points — every one bumps generation and releases+zeroizes the connection's slots:

```text
normal close_notify; abortive close; fatal alert (sent or received); handshake failure; provider failure;
resource-budget failure; stale crypto result; transport close/error; key-update (release old epoch slots);
connection-generation bump; interpreter drop / finalizer path; test cleanup.
```

Zeroization uses a wipe primitive that **cannot be optimized away** (volatile store, as in the existing
`NativeSecret`). **ASan/UBSan are memory-safety gates, not zeroization evidence** — zeroization is evidenced
by **test-only instrumentation** that reads back the slot region post-release and asserts it is wiped
(extends `Tests.NativeSecret`).

## 9. Lean wrapper types and non-Repr policy (Adjustment 5 — broadened)

```text
no Repr / ToString / structural-equality / JSON / serialization on any secret-bearing wrapper;
errors never include secret bytes; logs never include secret bytes;
panic / dbg / debug paths never dump native secret memory;
handle IDs (connId/gen/slotId) are operationally sensitive (reveal session structure) — log conservatively,
  only when explicitly classified non-secret, and prefer counts/categories over raw ids.
```

Enforced by *not deriving* the forbidden instances and by review; a compile-checked test asserts the secret
wrappers have no `Repr` instance in scope.

## 10. Pure-to-IO interpreter lift structure (Decision 3)

The IO production interpreter has **no independent protocol decision logic**. It is a thin lift of the *same*
proved action-mapping the pure interpreter uses — mirroring the existing `Transport` seam, where one mapping
is instantiated by `FakeTransport` (pure) and a real adapter (IO).

```text
sharedActionMap : Core.OutputAction → InterpreterStep      -- pure, proved (no extra decisions)
pure interpreter  = sharedActionMap ∘ pure provider  ∘ pure SecretArena       (unchanged; the MODEL)
IO   interpreter  = sharedActionMap ∘ native provider ∘ native SecretArena    (new; lift into IO)
```

Because the IO interpreter contains no decision code of its own, "makes no extra protocol decisions" is
**structural** (nothing to diverge), not merely asserted. Only the *effect carriers* (provider, arena)
differ.

## 11. Differential-test plan (Decision 3)

Golden traces from the pure interpreter; the IO lift is run on the same scripted inputs; compare
**public observations only** (never raw secrets):

```text
core actions; alerts; selected suite/group/signature; record metadata; transcript event sequence;
ciphertext length and record shape; successful decrypt/open behavior; terminal state and close behavior.
```

Where ciphertext is deterministic and legitimate to compare, compare bytes; where randomness/native
differences make byte-equality brittle, compare **decryptability + public record properties** instead. Raw
traffic secrets are never compared.

## 12. Sanitizer / native tests

ASan/UBSan on the new native arena + AEAD-by-handle entry points (extends `scripts/sanitizer-check.sh`);
double-release; stale-handle (wrong gen/conn/kind/direction; released slot; terminal connection);
release-on-failure across all §8 paths; no-retained-Lean-pointer; no-raw-secret-logging; **zeroization
read-back** instrumentation (§8). Negative-control verified (a deliberately-broken build must fail the gate).

## 13. Trust-matrix wording per slice

```text
After Slice 1: connection traffic-secret zeroization = BEST-EFFORT (unchanged);
               AEAD record-path native handle use = partial / exposure reduced. NO promotion.
After Slice 2: still BEST-EFFORT unless every connection-lifetime secret class is covered. NO promotion.
After Slice 3 (gate §12.1 met): "tested native zeroization for connection traffic-secret residency, over a
               proved shared protocol decision core; native zeroization is trusted/tested, not Lean-proven."
```

## 14. Explicit non-goals

- **No asynchronous sealing/open in RFC 040** — synchronous FFI only. Async offload, out-of-band result
  correlation, in-flight accepted-plaintext accounting, and the jemmet egress contract change move to a
  follow-up RFC (likely 044), created only when needed (RFC §11, §4.4).
- **No trust-matrix promotion before Slice 3 / §12.1 gate.**
- RFC 040 makes **no claim** that application plaintext never enters Lean — AEAD `open` returns authenticated
  inbound plaintext synchronously; the claim is about *secret* material residency only (Adjustment 6).
