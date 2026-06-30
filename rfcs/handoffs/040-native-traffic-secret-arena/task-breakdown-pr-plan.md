# RFC 040 — task breakdown / PR plan

**Companion to.** [`../../proposed/040-native-traffic-secret-arena.md`](../../proposed/040-native-traffic-secret-arena.md)
Branch: sync-first, staged. Slices ship as discrete tagged increments; **Slice 1 is not blocked on 2–3**.

## Slice 1 — handle ABI + AEAD-by-handle (exposure reduction; no promotion)

PRs (each gate-green, one verified increment):

1. **Native `SecretHandle` ABI + validation** — `kroopt_ffi_secret_import`, `_release`, slot lifecycle,
   field validation (conn/gen/slot/kind/direction/epoch/suite/terminal), generation bump, volatile wipe.
   Tests: double-release, stale-handle fail-closed, zeroization read-back, no-retained-pointer (ASan/UBSan).
2. **Native AEAD seal/open by handle** — `kroopt_ffi_aead_seal_h` / `_open_h`; nonce computed native-side
   from the IV handle; KATs (re-use existing AEAD vectors via the handle path). ASan/UBSan.
3. **Lean wrappers + non-Repr policy** — direction/epoch-typed handle wrappers; no `Repr`/`ToString`/serialize;
   compile-checked "no Repr in scope" test; conservative handle-id logging.
4. **Wire live per-record path to handles** — production provider seals/opens via handles; Lean-derived
   key/IV bytes imported (source wiped); HKDF schedule still Lean. Live interop re-run (`tls-interop.sh`,
   `https-e2e.sh`) unchanged-green over the stand-in.
5. **IO interpreter lift skeleton + differential harness** — `sharedActionMap` extracted/confirmed pure;
   IO interpreter = lift over native provider/arena; differential test vs pure golden traces (public
   observations only).
6. **Trust-matrix note (no promotion)** — record partial exposure reduction; promotion explicitly deferred.

Slice 1 acceptance: see `acceptance-qa-checklist.md`.

## Slice 2 — key schedule by handle

1. `kroopt_ffi_hkdf_extract_h`, `kroopt_ffi_hkdf_expand_label_h` (consume/produce handles).
2. Early/handshake/master + client/server traffic-secret derivation by handle.
3. Finished-key derivation by handle.
4. Differential + sanitizer tests extended. Still **no promotion** unless every connection-lifetime class is
   covered.

## Slice 3 — full record-protection state by handle + promotion

1. AEAD keys + IV/base-nonce derived directly into handles (no Lean import).
2. Key-update derives next-generation secrets by handle; old epoch slots released.
3. Close/terminal cleanup releases all connection slots on every §8 path.
4. Full pure↔IO differential + zeroization read-back + sanitizer pass.
5. **Promotion** — only after the RFC §12.1 gate holds; trust-matrix wording updated; RFC 040 → `done/`.

Slices 2 and 3 may be combined if clean.

## Out of scope (→ follow-up RFC, likely 044)

Async seal/open offload; out-of-band result ledger (duplicate / stale-cross-generation / after-terminal);
in-flight accepted-plaintext accounting; cancellation/backpressure; jemmet egress-accounting contract change.
