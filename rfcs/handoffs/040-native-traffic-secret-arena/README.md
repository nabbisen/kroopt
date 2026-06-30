# RFC 040 handoff — native traffic-secret arena + IO production interpreter

Implementation companion to [`../../proposed/040-native-traffic-secret-arena.md`](../../proposed/040-native-traffic-secret-arena.md).
Status is **inherited** from RFC 040 (Proposed — design in progress); this is not a separate lifecycle item
(RFC 000 policy).

Branch (architect review 2026-06-30): **sync-first**, **staged** native crypto surface,
**proved-shared-core + tested IO lift**. Async sealing is a non-goal here (→ follow-up RFC, likely 044).

| Document | Purpose |
|----------|---------|
| [`implementation-handoff.md`](implementation-handoff.md) | Detailed internal design — the 14 sections required before implementation starts |
| [`task-breakdown-pr-plan.md`](task-breakdown-pr-plan.md) | Slice/PR sequencing (Slice 1 → 3); Slice 1 not blocked on 2–3 |
| [`acceptance-qa-checklist.md`](acceptance-qa-checklist.md) | Slice 1 acceptance criteria, honesty guard, promotion gate |

**Next implementation step:** Slice 1 — `SecretHandle` ABI + AEAD seal/open by handle, fail-closed and
sanitizer-clean, no trust-matrix promotion.
