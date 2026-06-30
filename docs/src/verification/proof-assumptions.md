# Proof assumptions register

This register lists every assumption the kroopt verified core's proofs depend on
beyond Lean's trusted kernel (RFC 022 §4). The goal is that the trusted base is
small, explicit, and auditable.

## Lean kernel and standard axioms

The M0 proofs depend only on Lean's standard, sound axioms:

* `propext` — propositional extensionality (used by `simp`/rewriting). Four of
  the five M0 theorems use it; `step_deterministic` uses no axioms at all.

No proof depends on `sorryAx`. This is enforced two ways:

1. `scripts/check-hygiene.sh` rejects any `sorry`/`axiom`/`unsafe`/`admit`/
   `native_decide` as code in the strict zones (`Kroopt/Core`, `Kroopt/Proofs`).
2. `#print axioms` on each theorem (see `theorem-inventory.md`) shows only
   `propext`.

## Project-local assumptions

**None at M0–M4.** The core, parser foundation, record model,
sequence/nonce layer, handshake state model, and transcript model are
self-contained: no `axiom` declarations, no appeals to unproven lemmas, no
trusted project-local facts. Every parser primitive and every record transition
that runs in a strict zone carries a proof (see `theorem-inventory.md`).

Two *external* facts the record/nonce proofs lean on, both in the ASSUMED tier
(HACL\*/EverCrypt), tracked in the trust/test/proof matrix rather than as
project-local Lean assumptions:

* a `CryptoResult.aeadOpened` is returned only for a record whose AEAD tag
  verified — kroopt proves the structural half (plaintext is reachable only
  through that authenticated path);
* the concrete `iv_base XOR left_pad(seq)` nonce derivation is a bijection in the
  sequence for a fixed IV base — the uniqueness proof is stated over the abstract
  `deriveNonce` model (RFC 005 §5 sanctions abstracting the IV base), and the
  concrete byte realization is exercised by known-answer tests at M6.

Two **modeling abstractions** in the M4 layer, documented here and discharged at
later milestones rather than assumed away:

* the handshake key-schedule HKDF derivations are modeled as synchronous key
  installation; the operations whose *results gate* a phase change (ECDHE, the
  CertificateVerify signature, the client-Finished verification) are real crypto
  actions whose results re-enter as events. The provider-backed HKDF round-trips
  arrive with the crypto FFI at M6;
* the transcript proof model stores the exact committed bytes; the running hash
  is a provider action (RFC 007 §9.1 explicitly permits this hybrid — proofs
  cover event order and exact-byte binding, the digest value is provider-backed
  and checked by correspondence tests).

### Tested-but-not-yet-proved helpers (explicit follow-up tasks)

RFC 003 §12 permits "tested trusted helpers with explicit follow-up proof
tasks." There is currently one:

* `Reader.takeCountedItems` (the fuel-bounded item combinator) is exercised by
  unit tests and the fuzz harness, and is structurally terminating (recursion on
  explicit fuel), but its bounds-safety *lemma* (`takeCountedItems_bounds`, under
  a bounds-safe-item hypothesis) is scheduled for M4 alongside the extension-list
  parser that first uses it. It is not yet relied upon by any verified theorem.

## Assumptions deferred to later milestones (not yet in the tree)

These will become explicit trust-boundary assumptions when their layer lands.
They are recorded now so the eventual trusted base is anticipated, not
discovered:

* **Crypto provider correctness (M6, RFC 008/009).** AEAD seal/open, HKDF, X25519,
  signatures, and SHA-2 are assumed correct as provided by HACL\*/EverCrypt.
  kroopt proves it *uses* them correctly (nonce discipline, key separation,
  transcript binding); it does not re-prove the primitives. This will be the
  single largest trusted component and will be justified by known-answer tests
  and sanitizer runs, not by Lean proof.
* **FFI boundary faithfulness (M6, RFC 009/024).** The C shim is assumed to honour
  the documented ownership and result-correlation contract. Justified by tests
  and sanitizers, not proof. As of RFC 037 §7.5 this is partly discharged:
  `scripts/sanitizer-check.sh` runs the shim and the HACL\* calls it issues under
  ASan/UBSan on KAT and adversarial inputs with no out-of-bounds access or UB
  (buffer bounds checked tightly via malloc-backed direct calls, since Lean's
  allocator hides `ByteArray` data from ASan).
* **Interpreter faithfulness (M7, RFC 010).** The interpreter is assumed to
  execute each `OutputAction` exactly as specified and to feed back only
  correctly-correlated events. Justified by the deterministic harness comparing
  interpreter behaviour against the action stream (RFC 014).
* **Secret-memory zeroization (RFC 013 §13.4, RFC 037 §3) — two distinct postures, kept as
  separate rows (they must not be blurred).** The verified core never names key bytes; the two
  secret classes are handled differently:
  * **Config-lifetime server private key — TESTED C-owned zeroization.** The Ed25519 signing key
    lives only in the C-owned arena (`Kroopt.Crypto.NativeSecret` over the native
    `kroopt_ffi_secret_*` store): its bytes sit in malloc'd C memory addressed by a monotonic,
    never-reused id, it is signed **by handle** (never copied to the Lean heap), and
    `release`/`zeroize` overwrite the buffer through a volatile store before freeing it. The wipe
    is **observable** on a live buffer (`Tests.NativeSecret`) and the store is
    leak/double-free/UAF-clean under ASan/UBSan (`scripts/sanitizer-check.sh`).
  * **Connection-lifetime traffic secrets — BEST-EFFORT / tested logical invalidation.** The
    ECDHE shared secret, the HKDF handshake/application traffic secrets, and the per-record AEAD
    keys/IVs still live in the pure Lean `SecretArena`, threaded through the interpreter. On every
    terminal path the interpreter bumps the arena generation, which drops the stored bytes from
    the arena's reachable state and invalidates every outstanding handle (a stale handle resolves
    to `none`, never the wrong secret) — tested. It does **not** overwrite the underlying memory:
    dropped `ByteArray`s are reclaimed on the runtime's schedule, and copies the borrowed crypto
    made are outside this model. **No production zeroization is claimed for traffic secrets** until
    the native traffic-secret arena lands.

  Moving the connection-lifetime secrets onto the C-owned arena requires an **IO production
  interpreter**: the pure `CryptoProvider.submit` / `Conn.Interpreter.driveEvents` cannot hold an
  effectful secret lifecycle without losing the determinism the proofs and the RFC 031
  correspondence rely on. The architect-reviewed decision is to keep the best-effort posture for
  the pre-stable line and migrate via a **two-interpreter** architecture (pure model + IO
  production, with a pure↔IO correspondence) as a **stable/v1 gate**, sequenced **after RFC 031**
  locks the pure correspondence. Tracked by RFC 040; see `deferred-scope.md`. Ephemeral bytes that
  transit Lean for a crypto op remain outside any wipe guarantee.

Each deferred item will get its own dated entry here when the corresponding code
is introduced, including how the assumption is discharged or bounded.

At M5, the end-to-end harness uses a **fake crypto provider and fake transport**
(RFC 014). These live in the test zone, not the verified core: the proofs
constrain `step`'s behaviour for *any* provider result, and the fakes only script
particular results to exercise traces. One small synthetic imperfection is
recorded for honesty: a failed client-Finished verification re-uses the record
layer's `verifyFailed → bad_record_mac` fatal path rather than emitting
`decrypt_error`. Both are fatal and emit no plaintext; the distinction is a
cosmetic alert-code detail that keeps `aead_open_failure_no_plaintext` intact and
is resolved when real crypto correlation lands at M6.

At M6 the crypto provider boundary lands (RFC 008 / 009). The operation-id
correlation guard is *proved* in the core (`stale_crypto_result_rejected`), and
Randomness is the OS CSPRNG only (ASSUMED), drawn through a fail-closed wrapper: an
entropy failure aborts connection setup rather than proceeding with degraded entropy
(RFC 034). The real provider implements the AES-128/256-GCM and ChaCha20-Poly1305
suites with SHA-256/384 over X25519 and secp256r1 (P-256), and **Ed25519** signatures — the only
advertised signature scheme (ECDSA-P256 and RSA-PSS signing code and HACL\* bindings are present but
not advertised, so a config requiring them is rejected at validation; see
[current security state](current-security-state.md)). Capability validation is a total
deterministic function. The native HACL\*/EverCrypt shim is contracted (`Kroopt/Native/kroopt.h`)
and **vendored and built** — it is exercised under ASan/UBSan and known-answer tests; the
deterministic `Kroopt.Crypto.fakeProvider` remains available for the pure model tests. The choice of
provider does not weaken any proof: the core's guarantees hold for *any* provider result, so the
provider is outside the proof boundary. Cryptographic correctness and
constant-time behaviour of the primitives remain ASSUMED (inherited from
HACL\*/EverCrypt), never proved here, exactly as the trust matrix states. (That
inheritance presumes the vendored bytes *are* the upstream verified artifact; the
byte-level provenance anchor establishing that is currently pending — see the trust
matrix's provenance-anchor row.)
