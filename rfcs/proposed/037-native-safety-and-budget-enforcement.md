# RFC 037 — Native FFI Safety, Secret Arena, and Resource-Budget Enforcement

**Project.** kroopt  
**Status.** Proposed  
**Type.** Implementation RFC  
**Target milestone.** M37  
**Depends on.** RFC 008 (FFI contract), RFC 009 (shim/KAT/sanitizer), RFC 024 (native build/feature gates), RFC 034 (capability honesty + entropy); follows RFC 031/032/033  
**Touches.** `Kroopt/Native/kroopt_ffi.c`, `Kroopt/Crypto/{Arena,Secret}.lean`, `Kroopt/Core/Budget.lean`, `Kroopt/Core/Step.lean`, `Kroopt/Conn/Interpreter.lean`, `Kroopt/Conn/Record13.lean`, `docs/src/{secret-handling,proof-trust-test-matrix}.md`  
**Canonical source.** kroopt fixed requirements §13, §17.4; architect RFC review (RFC 034 split: the 034B / M37 half).  

---

## 1. Summary

The hardening that must land before external clients but after the correspondence work:
FFI length/error contracts on every primitive, a truthfully-classified or native secret
arena, and the proven resource budgets wired into the **core** (not only the
interpreter). This is the second half of the original RFC 034, deferred to M37 per the
architect's split; the immediate capability/entropy fixes are RFC 034.

## 2. FFI length and error contracts (all `uint32_t` parameters)

`kroopt_ffi.c` trusts Lean `ByteArray` lengths. Validate **before every HACL call**, and
reject (never truncate) any length that does not fit the `uint32_t` HACL parameter:

- X25519 private/peer = 32; Ed25519 private/public = 32, signature = 64;
- ChaCha20-Poly1305 key = 32, nonce = 12, tag = 16;
- **AAD length, plaintext length, ciphertext length** (AEAD seal/open);
- **message length** for Ed25519 sign/verify;
- **HKDF input and output lengths**.

Functions that can fail return explicit status-tagged results (the `0 = ok / 1 = fail`
convention); none proceeds silently on malformed input.

## 3. Secret arena — target state is not optional

`SecretArena` is currently a Lean `List (UInt64 × ByteArray)`: good for tests and proof
visibility, not the zeroizable C-owned memory requirements §13 intends. The architect
decision (not an implementer choice):

- a **C-owned zeroizable arena** (non-printable handles, best-effort zeroized on release,
  FFI retains no Lean pointers) is **required before any production/stable claim**;
- staged delivery is permitted: for the constrained external-interop/dev milestone the
  Lean arena may be tolerated **only if** the trust matrix classifies it
  `TESTED / best-effort / not zeroization-guaranteed` **and** the docs forbid production
  claims.

So the matrix must state the *real* guarantee; the *target* (native zeroizing arena) is
fixed, only its timing is staged. Add secret-leak tests on every terminal path; with
RFC 009, ASan/LSan coverage of the native arena once it lands.

## 4. Resource-budget enforcement in the core

`Core/Budget.lean` has charge/check functions with proofs but is not invoked by `step`,
the transport-bytes handler, op allocation, or the interpreter. **Attacker-controlled
parse and handshake budgets must be charged in the core path** (so proofs and tests see
them); transport/pending-output budgets may be interpreter-side.

Charge in `step` / core handlers: inbound buffered-ciphertext growth; total handshake
bytes and per-message size (including the §RFC 033 assembler buffer); ClientHello bytes,
extension count, total extension bytes. Charge interpreter-side: pending outbound
ciphertext; progress-loop steps and `wouldBlock` retries per external event.

### 4.1 Crypto-op budget and lifetime

Pending crypto operations are attacker-amplifiable. Budget and bound them:

- max outstanding ops per connection;
- max total pending-op bytes;
- operation timeout / handshake-phase expiry;
- explicit result-after-close behavior (released and ignored; map cleared on close —
  consistent with RFC 031 §4).

Budget exhaustion is terminal, typed, metric-visible, and yields no partial plaintext.

## 5. Record-size enforcement

`Record13.sealRecord` must enforce, not merely cast to `UInt16`:

- application content length ≤ `2^14`;
- `TLSInnerPlaintext` overhead (content-type octet + padding);
- AEAD tag expansion;
- resulting `TLSCiphertext` length within bounds.

Return `Except` (or reject) on oversize input so future interpreter code cannot misuse it.

## 6. Lower-severity polish

- Graceful close seals and sends an encrypted `close_notify` in the current epoch before
  `closeTransport` (required before a production-ready API claim).
- Inbound alert records parse level/description deterministically (coordinated with
  RFC 033 §5) rather than pushing toward closing unparsed.

## 7. Acceptance criteria

1. Every native primitive validates all input lengths (including AAD/plaintext/
   ciphertext/message/HKDF) and rejects `uint32_t`-overflowing lengths; failures are
   status-tagged.
2. The secret arena is either native-zeroizing or explicitly classified
   `TESTED / best-effort` with production claims forbidden in docs; leak tests pass on all
   terminal paths.
3. Parse/handshake budgets are charged in the core path; crypto-op count/bytes/lifetime
   are bounded; exhaustion is terminal, typed, and emits no plaintext; tests cover each.
4. `Record13.sealRecord` enforces the §5 size bounds.
5. An ASan/UBSan (and LSan if a native arena lands) target exists and runs the native
   tests (closing the RFC 009/024 sanitizer deliverable).
6. `close_notify` is sealed/sent on graceful close; inbound alerts parse level/description.

## 8. Risk

Native-shim changes can surface latent FFI lifetime/refcount issues; de-risk
incrementally (each primitive's length-check + KAT in isolation), as done for the M35
socket shim. No "test secrets export" build mode in CI release artifacts.
