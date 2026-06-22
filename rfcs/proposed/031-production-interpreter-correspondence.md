# RFC 031 — Production Interpreter Correspondence

**Project.** kroopt  
**Status.** Proposed — **milestone reached (0.47.0-dev): `RealHandshake` retired** (§5/§7.5). Slices 1–9 plus the driver removal land the correspondence substance: the production interpreter (`Kroopt.Conn.Interpreter`, `driveEvents`) drives the real `Kroopt.Core.step` from an inbound ClientHello to `connected` against a real crypto provider — real ECDHE/HKDF/CertificateVerify/Finished, real inbound AEAD-open of the protected client Finished, and a complete post-`connected` application-data wire path (record-header framing + first-record sequence 0 + record-header AAD for both `aeadSeal` and `aeadOpen`). The core carries the exact ClientHello-inclusive committed transcript prefix in every bound op and the interpreter hashes that carried prefix (§3); real records are sealed by the interpreter under the core-authorized epoch/sequence (§2); a wrong-kind crypto result drives the interpreter terminal (§4). The bespoke `Tests/RealHandshake.lean` RD driver (alternative flight assembly, transcript substitution, record sealing) is **deleted**; `Tests/Correspondence.lean` (25 checks, real fixtures in `Tests/RealFixtures.lean`) is the §6 suite, including the negative-bypass set (wrong-kind result, no early plaintext emit, no app accept before-`connected`/after-close, wrong client Finished rejected) and the migrated RFC 033 reassembly checks. **Deferred to the async-crypto work:** the §5 runtime ledger and the async §4 refinements (duplicate/stale/after-terminal results) — in the synchronous interpreter the properties they witness are already pinned by the direct §6 checks, and the ledger's negative-space value (no *unauthorized* effect) first applies where stale/duplicate effects become possible.

Remaining for the milestone, in priority order: **(1)** crypto-op-id lifecycle (§4) — the wrong-kind guard (`resultMatchesKind`) is implemented and tested (`Tests/Correspondence.lean` checks 16–17), with a first §6 no-early-plaintext bypass check (18); the remaining refinements (duplicate→fatal, stale cross-generation→ignored+metric, result-after-terminal→released) concern asynchronous crypto results the synchronous interpreter never produces and land with async crypto; **(2)** correspondence ledger (§5) + the rest of the negative-bypass set (§6) — the §6 set now covers wrong-kind crypto results (checks 16–17), no early plaintext emission (18), and no application plaintext accepted before `connected` or after close (19–20); the ledger (§5) remains; **(3)** reduce/delete `Tests/RealHandshake.lean` (§5 criterion).  
**Type.** Implementation RFC  
**Target milestone.** M36  
**Depends on.** RFC 002 (verified-core correspondence), RFC 010 (TlsConn/interpreter), RFC 032 (typed assembly contract), RFC 033 (real-client handshake processing); benefits from RFC 034 (capability honesty) landing first  
**Touches.** `Kroopt/Conn/Interpreter.lean`, `Tests/RealHandshake.lean`, new `Tests/Correspondence.lean`, `docs/src/verified-core.md`  
**Canonical source.** kroopt fixed requirements §8, §15.3; external design §15; architect reviews of 2026-06-12 (HANDOFF + RFC reviews).  

---

## 1. Summary

The byte-accurate real handshake currently runs in a **test driver**
(`Tests/RealHandshake.lean`), not in the production interpreter
(`Kroopt/Conn/Interpreter.lean`), which still appends the core's placeholder
handshake frames verbatim. The driver recognizes those placeholders *by first byte* and
substitutes real handshake bytes, real transcript hashes, and real AEAD sealing at the
crypto and `writeTransport` seams.

Both architect reviews rule this acceptable as M35 de-risking but **not acceptable as
the production correspondence contract**. This RFC makes the production interpreter emit
and consume byte-accurate TLS 1.3 records from typed, core-authorized actions
(RFC 032), with a single transcript authority, a precise crypto-op-id lifecycle, and a
runtime correspondence ledger that lets tests assert the full authorization chain — not
just end-state equality. It is the backbone of M36 and the precondition for any iotakt
binding (RFC 010) or external-client milestone (RFC 015/026).

## 2. Goals

1. The production interpreter (generic over `Transport`, threading the real
   `CryptoProvider` and secret arena) drives the full real server handshake to
   `connected` over `FakeTransport`, producing real TLS records: a cleartext ServerHello
   record plus encrypted EncryptedExtensions / Certificate / CertificateVerify /
   Finished records.
2. **No production path recognizes a handshake message by the first byte of placeholder
   data.** Assembly is driven by the typed actions of RFC 032 (enforced by RFC 032's CI
   gate).
3. A single transcript authority (RFC 032): the handshake-message bytes the core
   authorizes, the bytes serialized to the wire, and the bytes hashed for HKDF /
   CertificateVerify / Finished are the same sequence.
4. A precise crypto-op-id lifecycle (§4) so stale/duplicate/cross-connection/wrong-kind
   results are handled by explicit policy.
5. A runtime correspondence ledger (§5) and correspondence tests (§6) proving every
   externally visible effect is authorized by a `Core.step` action and never originates
   in the interpreter.
6. `Tests/RealHandshake.lean` reduced to a thin wrapper or deleted, containing **no**
   alternative flight assembly, transcript substitution, or record sealing.

## 3. The production interpreter contract

The interpreter MAY serialize, sign, seal, allocate secrets, call crypto, and perform
I/O. It MUST NOT decide protocol order, state legality, epoch/direction selection,
application-data legality, transcript progression, sequence advancement, or
close/failure policy independently of `Core.step`. A byte assembler is allowed; a
second handshake state machine is not.

The interpreter is unacceptable (requirements §15.3) if it: contains transition logic
independent of `Core.step`; emits plaintext other than via a core `emitPlaintext`
action; accepts application bytes outside `appSend`/`acceptPlaintextBytes`; calls crypto
without a matching core-emitted `CryptoOp`; advances a record sequence number outside a
core-controlled transition; updates the transcript outside the core/parser discipline;
or bypasses secret release on any terminal path.

## 4. Crypto-operation-id lifecycle (required, precise)

A crypto result is accepted only if its operation id is **all** of:

- outstanding (allocated by a prior core `callCrypto`, not yet consumed);
- owned by the same connection id;
- the same operation kind;
- the same epoch and direction;
- satisfies the pending operation's handshake-phase/state predicate;
- consumed exactly once.

Policy for non-conforming results:

- same-connection **wrong-kind** or **duplicate** result → **fatal** internal-invariant
  failure (release associated output, set terminal reason);
- obviously **stale cross-generation** result (the connection/fd generation has moved
  on) → **ignored + metric** (`kroopt_crypto_failures_total{kind=stale}`);
- any result after terminal state → released and ignored; the pending-op map is cleared
  on fatal failure and close.

This makes RFC 034/037's "result-after-close" and stale-result rules concrete at the
interpreter layer.

## 5. Runtime correspondence ledger (debug/test-only)

The interpreter maintains a debug/test-only event ledger recording, per step:

- the input event consumed;
- the `Core.step` output-action id(s) produced;
- each crypto op id allocated and the op it answers;
- serialized handshake-message bytes produced (with the authorizing action);
- transcript bytes contributed (handshake-message bytes only, per RFC 032);
- record sequence advances;
- secret-handle releases;
- plaintext emitted or accepted.

The ledger is built only under a `debug_trace`/test profile, carries no secrets
(handles and ids only, never key material), and is the substrate for §6.

## 6. Correspondence tests (`Tests/Correspondence.lean`)

Assert the full authorization chain, not only end-state:

1. The production interpreter drives the full handshake to `connected` over
   `FakeTransport` with the real provider, emitting the real flight as real records.
2. Every ledger entry is core-authorized: every serialized handshake message, crypto
   call, transcript contribution, sequence advance, secret release, plaintext
   emit/accept maps to a `Core.step` action; nothing originates in the interpreter.
3. **Negative interpreter-bypass tests** — hand-written interpreter effects cannot:
   emit plaintext without `emitPlaintext`; advance a sequence without a core action;
   write a record after terminal state; call crypto with no outstanding core op; or
   release only some secrets after failure (leak counter must reach zero on every
   terminal path).
4. A **wrong** client Finished, a **bad AEAD tag**, a **stale** crypto result, and a
   **post-close** application write are each rejected at the interpreter layer per §4.

## 7. Acceptance criteria

1. No production path recognizes a handshake message by first byte (RFC 032 gate green).
2. `Conn.Interpreter` drives the byte-accurate server flight over `FakeTransport` with
   the real provider and reaches `connected`; the flight is real TLS records.
3. Transcript hashes for key schedule, CertificateVerify, server Finished, and client
   Finished verification derive from the same serialized handshake-message bytes.
4. The crypto-op-id lifecycle (§4) is implemented and tested; the correspondence ledger
   (§5) and tests (§6), including the negative-bypass set, pass.
5. `Tests/RealHandshake.lean` is wrapper-only or removed, with **no** alternative
   assembly/substitution/sealing logic remaining.
6. The three gates stay green (re-establishing any proofs touched by RFC 032/033); the
   suite set and `conn`/`https` suites are updated for the production interpreter.

## 8. Sequencing, risks, alternatives

- **Sequencing.** RFC 032 (typed contract) and RFC 033 (receive-side record path +
  reassembly) land first or together; RFC 034 (capability honesty + fail-closed entropy)
  should land as the M36-prelude before this integration so the real provider is honest.
  iotakt binding (RFC 010) and external interop (RFC 015/026) stay **frozen** until this
  RFC's acceptance criteria pass.
- **Risk: suite churn.** The `conn`/`https` suites depend on placeholder behavior and
  will change; re-point them behind the same public surface.
- **Alternative considered (rejected as end state).** A transitional
  `Conn.LegacyPlanDecode` adapter remains a fallback only if RFC 032 slips; enriching the
  core directly is preferred since RFC 033 already reopens the core/proof surface.
