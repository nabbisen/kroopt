# RFC 040 — acceptance / QA checklist

**Companion to.** [`../../../proposed/040-native-traffic-secret-arena.md`](../../../proposed/040-native-traffic-secret-arena.md)

## Slice 1 acceptance criteria (all must hold)

1. `SecretHandle` validation rejects: stale generation, wrong connection, wrong kind, wrong direction,
   released slot, and terminal connection.
2. AEAD seal/open by handle works for valid handles (KATs pass via the handle path).
3. Invalid handle use **fails closed** with no memory disclosure and no aliasing of fresh memory.
4. Native code **copies** any imported secret material into the arena and **never retains Lean pointers**;
   the caller-side source bytes are wiped after import.
5. Release paths zeroize and invalidate slots (volatile wipe, not optimizable-away); zeroization is evidenced
   by **test-only read-back instrumentation**, not ASan alone.
6. ASan/UBSan pass on the new native arena + AEAD-by-handle entry points (negative-control verified).
7. Negative tests cover double-release and stale-handle reuse (wrong gen/conn/kind/direction; released;
   terminal).
8. Logs / errors / `Repr` / panic paths do not expose raw secret bytes; a compile-checked test asserts no
   `Repr` instance is in scope for secret-bearing wrappers; handle ids logged conservatively.
9. Trust matrix stays **BEST-EFFORT** with a partial-progress note (AEAD record-path native handle use =
   exposure reduced). **No promotion.**
10. RFC 040 text states promotion is deferred until the key schedule and all connection-lifetime
    traffic-secret material are native-owned end-to-end.

## Honesty guard (what remains in Lean after Slice 1 — state explicitly)

```text
AEAD key bytes        : imported into native handle from Lean-derived bytes  ⇒ transit Lean before import
AEAD IV/base nonce    : imported into native handle from Lean-derived bytes  ⇒ transit Lean before import
traffic secret bytes  : still derived and held in Lean (HKDF schedule in Lean)
finished key bytes    : still in Lean
HKDF intermediate bytes: still in Lean
```

⇒ Slice 1 is an **exposure-reduction** slice, not "traffic-secret zeroization complete." Do not describe it
otherwise.

## jemmet commitment (preserve under sync-first)

```text
no in-flight accepted plaintext retained by kroopt after the synchronous drive returns;
no async accepted-plaintext queue;
connOwnedPlaintext remains 0 (0.114.0-dev §6 commitment intact).
```

AEAD `open` returns authenticated inbound plaintext to Lean/jemmet synchronously — accounted honestly, not
hidden, and **not** claimed to never enter Lean.

## Promotion gate (RFC 040 overall — do NOT promote before all hold)

```text
traffic secrets do not live in Lean after derivation;
AEAD keys and IV/base-nonce material do not live in Lean after derivation;
finished keys and relevant HKDF intermediates are native-owned;
key updates preserve native ownership;
close/failure paths release and zeroize (read-back evidenced);
pure decision core is shared (proved); IO lift is differentially tested;
native secret paths are sanitizer-clean; no raw-secret logging/Repr; side effects documented honestly.
```

Only then: BEST-EFFORT → "tested native zeroization for connection traffic-secret residency, over a proved
shared protocol decision core; native zeroization is trusted/tested, not Lean-proven."
