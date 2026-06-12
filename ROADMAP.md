# kroopt ROADMAP — RFC Themes and Implementation Sequencing

**Project.** kroopt  
**Document type.** ROADMAP  
**Status.** Draft for implementation planning  
**Canonical source.** kroopt fixed requirements and external design  
**Primary rule.** Build the verified executable core first; attach crypto and real I/O only through a thin interpreter.  
**RFC management.** RFCs follow the [RFC lifecycle policy](rfcs/done/000-rfc-lifecycle-policy.md). The folder under `rfcs/` is the source of truth for each RFC's state; see [`rfcs/README.md`](rfcs/README.md) for the live index.

---

## 1. Roadmap intent

This ROADMAP decomposes kroopt into implementable RFC themes. The purpose is not merely to list features; it defines a safe development order for a Lean 4 TLS secure-channel library whose core value depends on proof/runtime correspondence.

The roadmap is organized around four risks:

1. **Model drift risk.** A clean proof model may diverge from the running TLS driver. Mitigation: a pure verified core emits actions, and the interpreter only executes those actions.
2. **Security regression risk.** TLS bugs often come from parsing, sequence numbers, nonce reuse, transcript mismatch, or terminal-state confusion. Mitigation: parser and record invariants are implemented before real network exposure.
3. **FFI trust-boundary risk.** The crypto implementation is borrowed from HACL\*/EverCrypt, but the FFI shim and secret lifecycle remain kroopt responsibilities. Mitigation: provider capability matrix, known-answer tests, sanitizers, and opaque secret handles.
4. **Integration pressure risk.** jemmet and iotakt integration could push shortcuts into protocol logic. Mitigation: runtime integration is delayed until the core, parser, record model, and fake harness are already working.

---

## 2. RFC set overview

The planning package contains **RFC 001–030**, in two waves:

- **Wave 1 — implementation architecture and protocol scope (RFC 001–016).** These derive directly from requirements §20 and define the core TLS architecture and the immediate implementation plan.
- **Wave 2 — cross-cutting security, lifecycle, verification governance, and release readiness (RFC 017–030).** These are net-new relative to requirements §20. They are not feature creep; they are the controls that preserve kroopt's verification and security posture once the core RFCs reach real crypto, real iotakt I/O, and jemmet integration.

Wave 2 was added after the requirements document was frozen. Per the RFC lifecycle policy, RFC numbers are stable and additive: RFC 017–030 extend the set without renumbering 001–016. Requirements §20 remains the canonical *scope* baseline for wave 1; this ROADMAP is the canonical *sequencing* baseline for the full set. See §11 for the reconciliation note.

---

## 3. Milestone summary

### 3.1 Wave 1 — protocol architecture milestones

| Milestone | Theme | Output | Main RFCs |
|---|---|---|---|
| M0 | Boundary, repository skeleton, pure core shape | No sockets, no real crypto, state/action skeleton compiles | RFC 001, 002 |
| M1 | Bounds-safe parser/framer | Validated TLS byte structures and parse errors | RFC 003 |
| M2 | TLS 1.3 record model | TLSPlaintext / TLSInnerPlaintext / TLSCiphertext, record budgets | RFC 004 |
| M3 | Sequence, nonce, epoch, key proofs | Nonce uniqueness, monotonic sequence, key separation | RFC 005 |
| M4 | Server handshake model without HRR | ClientHello through Finished state machine; transcript | RFC 006, 007 |
| M5 | Fake crypto + deterministic tests | Full synthetic handshake over fake provider/transport | RFC 014 plus prior RFCs |
| M6 | Crypto provider contract | HACL\*/EverCrypt FFI surface and secret handles | RFC 008, 009 |
| M7 | Runtime connection API | TlsConn, flush semantics, iotakt interpreter | RFC 010 |
| M8 | Config and certificate presentation | SNI/ALPN table, server cert/key presentation | RFC 011, 012 |
| M9 | Close and error behavior | Alerts, close_notify, terminal policy | RFC 013 |
| M10 | jemmet integration and acceptance | OpenSSL/curl interop; jemmet HTTPS E2E | RFC 015 |
| Future | Deferred protocol breadth | X.509 path validation, client role, mTLS, tickets, HRR, KeyUpdate, TLS 1.2 | RFC 016 |

### 3.2 Wave 2 — cross-cutting milestones

Wave 2 RFCs are mostly continuous concerns rather than single milestones. Their earliest-active milestone is given below; several stay current across all subsequent releases.

| RFC | Theme | Earliest active | Hard deadline |
|---|---|---|---|
| 017 | Threat model and abuse cases | M0 | current before v0.3 |
| 018 | Data classification and lifecycle | M0 | maintained continuously |
| 019 | Resource budgets, backpressure, DoS defense | v0.1 (fake) | v0.3 (network exposure) |
| 020 | Observability, audit logging, redaction | v0.3 | v0.4 |
| 021 | Configuration lifecycle and reload | v0.3 (snapshots) | v0.4 (reload) |
| 022 | Proof gates, CI, Lean hygiene | M0 | enforced from M0 onward |
| 023 | Parser fuzzing, corpus, mutation policy | v0.1 | mandatory before v0.4 |
| 024 | Native build, Lake packaging, feature gates | M0 (skeleton) | v0.2 (native crypto) |
| 025 | Performance and memory benchmark policy | v0.2 (micro) | v0.3 onward |
| 026 | Compatibility, interop, negative matrix | v0.3 | v0.4 (browser) |
| 027 | Public API stability and versioning | M0 | commitment from v0.3/v0.4 |
| 028 | Security review and vulnerability process | — | before v0.3 exposure |
| 029 | Developer documentation and examples | v0.3 | v0.4 |
| 030 | Production readiness and release runbook | — | v0.4 and every release after |

---

## 4. Release staging

### 4.1 Internal M0 — executable verified-core skeleton

**Goal:** Establish the architecture so that the protocol model and runtime cannot split later.

Deliverables:

- `Kroopt.Core.Event`, `Kroopt.Core.Action`, `Kroopt.Core.State`, `Kroopt.Core.Step` modules.
- Initial `InputEvent`, `OutputAction`, `CryptoOp`, `State`, and `TlsError` types.
- A minimal `step` function with no real TLS logic but correct shape.
- Proof namespace and theorem skeletons for state/action discipline.
- Repository conventions: no project-local `sorry`, `axiom`, or `unsafe` in the proof/model area except explicitly documented assumptions (RFC 022).
- Cross-cutting foundations adopted early: threat model (RFC 017), data classification (RFC 018), proof-hygiene CI gate (RFC 022), and package/profile skeleton (RFC 024).

Exit criteria:

- Core modules compile.
- Model tests can call `step` directly.
- Runtime modules cannot bypass the core by design convention and module dependency rules.

### 4.2 v0.1 — synthetic handshake and record core

**Goal:** Finish the pure, testable protocol shape before real crypto and sockets.

Deliverables:

- Bounds-safe parser/framer foundation.
- TLS 1.3 record model with sequence, epoch, nonce derivation, and size budgets.
- Server handshake state machine without HelloRetryRequest.
- Transcript model tied to exact wire bytes.
- Fake crypto provider and fake transport.
- Deterministic full synthetic handshake test.
- Structural proofs for no early plaintext, no unauthenticated plaintext, legal transitions, terminal behavior, parser bounds, action discipline, nonce uniqueness, sequence monotonicity, and key separation.
- Resource-budget model over the fake transport (RFC 019) and the first parser fuzz harnesses/corpus (RFC 023).

Exit criteria:

- A full handshake completes over fake transport and fake crypto.
- Every state transition and terminal path has deterministic tests.
- All required pure-core proofs are complete or explicitly split into follow-up proof tasks with no runtime exposure.

### 4.3 v0.2 — HACL\*/EverCrypt FFI and real crypto provider

**Goal:** Attach real cryptographic primitives while preserving the core boundary.

Deliverables:

- Crypto provider trait/interface and capability matrix.
- HACL\*/EverCrypt C shim.
- Opaque secret handles and C-owned zeroizable secret storage.
- Known-answer tests for AEAD, SHA-2, HKDF, X25519, P-256 as adopted, and signatures.
- ASan/UBSan sanitizer jobs for the shim.
- Real AEAD record round-trip tests over fake transport.
- Native build profiles and feature gates settled (RFC 024); pure-core/crypto data lifecycle documented (RFC 018); crypto microbenchmarks begun (RFC 025).

**Status (M12, package 0.13.0-dev) — primitives layer delivered, integration pending.**
Done: vendored portable-C HACL\* subset built through Lake (`extern_lib krooptCrypto`); FFI glue and `Kroopt.Crypto.Hacl` wrappers; known-answer tests through Lean for AEAD (ChaCha20-Poly1305), SHA-2, HKDF, HMAC, X25519, and Ed25519 signatures (`kroopt-hacl-test`, 14 checks). Pending and scoped next: opaque-secret-handle **arena** and C-owned zeroizable storage; threading that state through `CryptoProvider.submit` so real key material flows through the key schedule (the pure handle-returning provider cannot do this alone — see `docs/src/native-crypto.md`); ASan/UBSan jobs; real AEAD record round-trip over transport; P-256; microbenchmarks.

**Status (M13, package 0.14.0-dev) — stateful seam + real key schedule delivered.**
Done: the secret **arena** (`Kroopt.Crypto.SecretArena`, generation-tagged, bounded); `CryptoProvider.submit` now threads it; the real TLS 1.3 key schedule (`Kroopt.Crypto.KeySchedule`) and arena-backed record AEAD (`Kroopt.Crypto.Real`) on HACL\*, **validated against the RFC 8448 §3 trace** end-to-end plus a real-key arena AEAD round-trip (`kroopt-keyschedule-test`, 20 checks). Handle opacity preserved; the 78 core theorems are untouched. Pending and scoped next: enrich the core `CryptoOp`/`CryptoResult` shapes (labels, input-secret handles, epoch-keyed key install) and re-prove operation-id correlation over them so `Kroopt.Core.step` drives the real provider — then a real handshake on one suite. Still pending after that: P-256, ASan/UBSan jobs, the iotakt `Transport` adapter, microbenchmarks.

**Status (M23, package 0.23.0-dev) — Ed25519 "defect" retracted as a false positive; corrected and interop-validated.**
The M19–M22 "non-RFC-8032 Ed25519 defect" was a **test-vector provisioning error, not a
HACL\*/compiler/Edwards-arithmetic defect.** The reproduction paired a non-RFC seed
(`9d61…7e8f`) with RFC 8032 §7.1 Test 1's public key (`d75a9801…`), which belongs to a
different seed (`9d61…7f60`); HACL\* correctly derived `bcd55c06…` for the seed it was
given. The earlier "isolation" steps were internally valid but all ran on the wrong seed,
so they only confirmed HACL\*'s self-consistency. Corrected this milestone: HACL\* Ed25519
reproduces the RFC 8032 §7.1 Test 1 public key **and** signature byte-for-byte, confirmed
independently by an RFC 8032 reference implementation and by OpenSSL `CertificateVerify`
interop (`scripts/ed25519-interop.sh`). The provision KATs now assert the real RFC vector
(`kroopt-provision-test`, 20 checks), vectors carry provenance + length discipline
(`Tests/Vectors/Ed25519Rfc8032.lean`), and the non-RFC seed is retained only as a labelled
regression vector. **No re-vendor, no compiler workaround, no trust-matrix downgrade**:
Ed25519 stays ASSUMED (inherited verified) with KAT + interop as TESTED evidence. Build
green, **87** theorems. (M24 closed the incident out with test-governance cleanup: false
language stripped from the changelog, provenance comments on every crypto KAT, and a
postmortem at `docs/src/postmortem-ed25519.md`.)

**Top pending — the structural-to-real handshake.** Now that Ed25519 is cleared, the real
next priority is replacing the structural placeholder frames and snapshot transcript with
real wire bytes and real transcript hashes, computing the real server `Finished` MAC, then
driving a full TLS 1.3 handshake against OpenSSL `s_client` / `curl` with an Ed25519 server
certificate (the `CertificateVerify` *construction* is already cross-validated against
OpenSSL; what remains is the live handshake).

*M26–M27 shipped the first increments:* `Kroopt/Parse/Wire.lean`, a real TLS 1.3
handshake wire serializer for the **whole server flight** (ServerHello,
EncryptedExtensions, Certificate, CertificateVerify, Finished), validated
byte-for-byte against RFC 8448 §3 (RSA cert/sig blobs treated as opaque, since RSA
is outside the vendored HACL subset). Two real-crypto joins are checked:
`SHA-256(ClientHello ‖ serialized ServerHello)` equals the RFC 8448 CH‥SH
transcript hash the key schedule derives over; and the **server Finished MAC**
recomputed over the serialized flight — `HMAC(finished_key, Transcript-Hash(CH‥
CertVerify))` — equals the RFC 8448 `verify_data`. Remaining for v0.3, in order:
sign CertificateVerify with kroopt's own Ed25519 cert key (RSA out of scope); wire
the serializers into the live handshake transcript (removing the `[snap.id]`
placeholders in `Core/Handshake.lean`); real record encryption; the iotakt
`Transport` socket adapter; then OpenSSL/curl interop. Still pending beyond v0.3:
P-256 (no `Hacl_P256.c` vendored — header only), ASan/UBSan jobs, and
microbenchmarks.

*The 0.35.0-dev architecture review (and the follow-up review of the RFCs) reset the
v0.3 finishing sequence into gated milestones (RFC 031–037). iotakt binding (RFC 010) and
external interop (RFC 015/026) are **frozen** until these gates pass, in this order:*

- **M36-prelude — honesty fixes (RFC 034).** Real provider advertises only the
  constrained capabilities (`realCapabilities`) with config rejection; entropy is
  fail-closed (typed `RandomResult`, no zero-fill success); deterministic/test randomness
  is separated from the real source. Small, no core/proof change, landed first.
- **M36 — production interpreter correspondence (RFC 031/032/033).** Typed handshake/
  record actions replace placeholder frames (no first-byte recognition, CI-gated);
  CertificateVerify/Finished are two-stage; transcript is over handshake-message bytes;
  the production interpreter drives the byte-accurate handshake over `FakeTransport` with
  a correspondence ledger + tests; the core processes protected handshake records before
  `connected`, with handshake-message reassembly and overlap-selection ClientHello
  negotiation; `Tests/RealHandshake.lean` becomes wrapper-only or is removed.
- **M37 — native and resource hardening (RFC 037).** FFI length contracts on all
  `uint32_t` params; secret arena native-zeroizing or truthfully classified; parse/
  handshake + crypto-op budgets charged in the core; record-size guards; sanitizer
  target; `close_notify` sealed.
- **M38 — constrained external interop (RFC 015/026/036).** Captured-ClientHello replay
  fixtures and a no-secrets trace harness; constrained `openssl s_client`/`curl`
  handshake green with archived traces; iotakt adapter begins only after M36 and M37 are
  green. Documented as a **constrained** profile, not browser-grade.
- **post-M38 — browser-grade crypto surface (RFC 035).** AES-GCM/P-256/ECDSA/RSA and a
  practical public-certificate story, only after the above are green.

*M36 part 1 shipped — the client Finished opens in the core (RFC 033):* the protected
client Finished (outer `application_data`) is now opened **in-core** under the handshake
read epoch and routed through the handshake model to `connected`, with no out-of-core
decryption workaround; inner application data before `connected` is fatal. Read-epoch
correctness landed (read stays handshake until the client Finished verifies). Proofs
re-established (91 theorems): `buffered_plaintext_authenticated` + four preservation
lemmas, `KeySeparation.aeadOpen_uses_read_keys` (now read-epoch-relative), and
`Nonces.successful_open_increments_read_seq`. RFC 033 stays in `proposed/` — the
handshake-message reassembler, overlap negotiation, ClientHello strictness, and CCS
policy remain. `kroopt-realhandshake-test` grew +4 checks (25).

*M36-prelude shipped the honesty fixes (RFC 034):* the real provider now advertises only
`realCapabilities` (the constrained ChaCha/X25519/Ed25519/SHA-256, OS-CSPRNG profile),
`validateServerConfigCapabilities` rejects an out-of-profile config with a typed
`CapabilityError`, `Hacl.randomBytes` returns a typed `RandomResult` with the native side
failing closed, and `provisionRealConfig` fails closed with `entropyFailure`.
Deterministic randomness is confined to the fake provider. `kroopt-capabilities-test`
(8 checks); no core/proof change (87 theorems, 36 pure files unchanged). RFC 034 moved to
`rfcs/done/`. The next gates (M36 correspondence, M37 hardening, M38 interop) are as above.

*M35 ran a server flight over a real OS socket:* `kroopt-socket-test` seals the
server flight (cleartext ServerHello + four ChaCha20-Poly1305 records) and exchanges
it, plus the peer's encrypted Finished and application data, across an `AF_UNIX`
socketpair — confirming the sealed records survive real kernel I/O and open on the
peer. The socket glue is test-only; kroopt's core still performs no syscalls. This
de-risks the transport boundary ahead of the production iotakt adapter (RFC 010) and
a live `s_client`/`curl` handshake (RFC 015/026).

*M34 cross-validated the record layer with an outside implementation:*
`scripts/record-interop.sh` has Python's `cryptography` library independently derive
the traffic key/IV (RFC 8446 §7.3) and decrypt kroopt's `Record13`-sealed records,
recovering the exact plaintext + content type and rejecting a tampered record — so
the record layer is standards-compliant, not merely self-consistent (RFC 026,
partial). The remaining v0.3 work is productionizing the interpreter and the iotakt
socket transport (RFC 010), after which a live `s_client`/`curl` handshake runs.

*M33 made the presented certificate real:* the live handshake now presents a real,
OpenSSL-parseable Ed25519 X.509 certificate whose leaf key is kroopt's signing key
(`scripts/gen-test-cert.sh`), replacing the placeholder DER. `ed25519-interop.sh`
now confirms OpenSSL parses the cert, its leaf key matches kroopt's key, and OpenSSL
verifies a kroopt CertificateVerify under that extracted leaf key — the property a
real client relies on. This unblocks `s_client`/`curl` interop, which still awaits
productionizing the interpreter and the iotakt socket transport (RFC 010).

*M32 put the encrypted flight on the wire:* the live `step`-driven handshake now
exchanges real TLS 1.3 records — the server flight after ServerHello is sealed as
`TLSCiphertext` records (seqs 0–3) under the server handshake-traffic key, and the
inbound client Finished is opened by the interpreter, while the core works on
plaintext. The seal/open lives in the test driver where the production interpreter
will host it; records are still exchanged in memory. Next: fold this into the
production `Conn.Interpreter` send/receive path and the iotakt socket transport
(RFC 010), then OpenSSL/curl interop (RFC 015 / 026).

*M31 shipped real TLS 1.3 record protection:* `Kroopt/Conn/Record13.lean`
(ChaCha20-Poly1305) frames the inner plaintext, the §5.2 AAD, and the per-record
nonce into a real `TLSCiphertext` and back — round-tripped, with tamper/wrong-key/
wrong-sequence all yielding no plaintext, and demonstrated end-to-end protecting a
real application record under the live handshake's negotiated keys after
`connected`. Next: emit seal/open from the core's send/receive path and the iotakt
socket transport (RFC 010), then OpenSSL/curl interop (RFC 015 / 026).

*M29–M30 shipped the live wiring through to `connected`:* the verified core `step`
machine is driven end-to-end against the **real** provider with a **real
transcript** assembled by `Flight` (`Tests/RealHandshake.lean`). It parses the
ClientHello, runs real X25519 + the real key schedule, produces a **valid Ed25519
CertificateVerify over the real transcript**, and (M30) verifies a real client
Finished to reach **`connected`** — with a negative control confirming a wrong
client Finished is rejected. The transcript-hash substitution lives in the impure
driver, where the production interpreter will host it. A correctness fix keyed the
secret arena's base secrets by `(direction, epoch)` so the server verifies the
client Finished with the client (read) handshake-traffic secret. The verified state
machine and its 87 theorems were untouched. Next: real record encryption of the
flight (messages are still assembled in the clear), the iotakt socket transport
(RFC 010), then OpenSSL/curl interop (RFC 015 / 026).

Exit criteria:

- FFI KATs pass.
- Sanitizer-clean shim builds.
- Secret-bearing Lean types are not printable, serializable, or accidentally comparable.
- The verified core still has no direct FFI dependency.

### 4.4 v0.3 — iotakt integration and mainstream CLI interop

**Goal:** Drive kroopt over a real iotakt connection and interoperate with OpenSSL/curl.

Deliverables:

- `TlsConn` API with `recv`, `send`, `flush`, `progress`, `close`, `state`, `alpn`, and error inspection.
- iotakt interpreter for `OutputAction` execution.
- Non-blocking readiness handling: WANT_READ/WANT_WRITE mapped to iotakt readiness hints.
- Partial-write queue and bounded pending ciphertext.
- OpenSSL `s_client` and curl interop tests.
- Negative tests for malformed ClientHello, missing X25519 key_share, duplicate extensions, bad Finished, truncated record, oversize record, and post-close operations.
- Network-exposure controls current: resource budgets enforced (RFC 019), observability/redaction taxonomy (RFC 020), immutable config snapshots (RFC 021), negative/interop matrix (RFC 026), and the pre-exposure security review (RFC 028).

Exit criteria:

- OpenSSL and curl complete TLS 1.3 handshakes over iotakt.
- Application data matches plaintext both directions.
- malformed/hostile input produces deterministic alerts or typed failures, never plaintext leakage or crashes.
- No source change to iotakt is required.

### 4.5 v0.4 — jemmet integration and operational hardening

**Goal:** Serve real HTTPS requests through jemmet and harden browser-facing edge behavior.

Deliverables:

- jemmet connection abstraction integration.
- SNI/ALPN immutable config table and validated config generation, with reload (RFC 021).
- Server certificate/key presentation and CertificateVerify signing.
- Browser smoke tests (RFC 026).
- Fuzz harnesses for record, ClientHello, extension, and minimal DER parsing, mandatory in CI (RFC 023).
- Audit logging and redaction tests (RFC 020).
- Current proof/trust/test matrix; developer docs and examples (RFC 029); production-readiness runbook (RFC 030).

Exit criteria:

- jemmet serves an HTTPS request end-to-end through kroopt + iotakt.
- SNI selects the expected certificate configuration.
- ALPN result is surfaced to jemmet without giving kroopt HTTP policy ownership.
- Resource budgets and log redaction are tested.
- The release-readiness checklist (RFC 030) passes with no RFC 028 release blockers.

---

## 5. RFC dependency map

### 5.1 Wave 1 — implementation architecture

```text
001 Boundary and Non-Goals
  └─ 002 Verified Core and Proof/Runtime Correspondence
       ├─ 003 Bounds-Safe Parser and Framer
       │    ├─ 004 TLS 1.3 Record Model
       │    │    └─ 005 Nonce / Sequence / Epoch / Key-Separation Proofs
       │    └─ 006 Handshake State Model without HRR
       │         └─ 007 Transcript Model over Exact Wire Bytes
       ├─ 014 Deterministic Test Harness and Fuzzing
       └─ 010 TlsConn API and iotakt Interpreter
            ├─ 008 Crypto Provider Capability and FFI Contract
            │    └─ 009 HACL*/EverCrypt Shim and KAT/Sanitizers
            ├─ 011 SNI/ALPN Configuration Model
            │    └─ 012 Server Certificate/Key Presentation
            ├─ 013 Alerts, close_notify, and Terminal Policy
            └─ 015 jemmet Integration and E2E Acceptance

016 Deferred Future TLS Features is a standing scope-control RFC.
```

### 5.2 Wave 2 — cross-cutting controls

Wave 2 RFCs depend on wave 1 RFCs and on each other. They are mostly continuous
concerns rather than a tree, so the binding dependencies are listed directly. The
`**Depends on.**` header field of each RFC is authoritative; this is the summary
view.

```text
017 Threat Model                ← 001, 002, 003, 004, 013, 014   (informs all)
018 Data Classification         ← 002, 004, 005, 008, 009, 010, 012
019 Resource Budgets / DoS      ← 003, 004, 010, 013, 014, 017
020 Observability / Redaction   ← 010, 011, 012, 013, 017, 018
021 Config Lifecycle / Reload   ← 011, 012, 018, 020
022 Proof Gates / CI / Hygiene  ← 002, 005, 006, 007, 014
023 Parser Fuzzing / Corpus     ← 003, 004, 006, 014, 017, 019
024 Native Build / Packaging    ← 008, 009, 022
025 Performance / Memory Bench  ← 004, 008, 010, 019
026 Compatibility / Interop     ← 006, 009, 010, 011, 012, 013, 014
027 API Stability / Versioning  ← 001, 010, 011, 012, 020
028 Security Review / Vuln Proc ← 017, 020, 022, 026
029 Developer Docs / Examples   ← 010, 011, 012, 020, 027
030 Production Readiness        ← 020, 022, 026, 028, 029
```

---

## 6. RFC themes

### Wave 1 — implementation architecture

### RFC 001 — Boundary and non-goals

Defines kroopt as a secure-channel library between iotakt and jemmet. Locks down ownership boundaries, explicitly excludes raw socket ownership and HTTP semantics, and establishes the rule that changes to iotakt are not permitted for kroopt convenience.

### RFC 002 — Verified core and proof/runtime correspondence

Defines the pure core, `InputEvent`, `OutputAction`, `CryptoOp`, `State`, and `step`. Establishes the rule that the interpreter executes actions but does not decide protocol behavior.

### RFC 003 — Bounds-safe parser and framer foundation

Defines validated parsing for TLS vectors, record headers, handshake messages, extensions, and minimal DER metadata. Returns structured values only after bounds and policy checks.

### RFC 004 — TLS 1.3 record model

Defines TLSPlaintext, TLSInnerPlaintext, TLSCiphertext, encrypted outer content type behavior, record size limits, AEAD open/seal orchestration, partial reassembly, and plaintext buffering limits.

### RFC 005 — Nonce, sequence, epoch, and key-separation proofs

Defines directional epochs, sequence numbers, nonce derivation, overflow handling, and proof targets that prevent AEAD nonce reuse and key confusion.

### RFC 006 — Handshake state model without HRR

Defines the server TLS 1.3 handshake path from ClientHello through Finished, excluding HelloRetryRequest, tickets, 0-RTT, KeyUpdate, and post-handshake auth.

### RFC 007 — Transcript model using exact wire bytes

Defines transcript events, exact-byte binding, transcript hash update order, and Finished/CertificateVerify input derivation.

### RFC 008 — Crypto-provider capability and FFI contract

Defines the crypto provider interface, operation ids, result correlation, capability selection, error mapping, secret-handle API, and provider test responsibilities.

### RFC 009 — HACL\*/EverCrypt shim, KAT, and sanitizer strategy

Defines the native shim, build integration, memory ownership, known-answer tests, sanitizer jobs, and failure handling for HACL\*/EverCrypt.

### RFC 010 — TlsConn API and non-blocking iotakt interpreter

Defines public connection APIs, write/flush semantics, readiness mapping, pending ciphertext queue, resource budgets, and stale-event defense.

### RFC 011 — SNI/ALPN configuration model

Defines immutable validated server configuration, SNI matching, ALPN negotiation, listener generation, config reload semantics, and policy separation from jemmet.

### RFC 012 — Server certificate/key presentation

Defines configured chain loading, minimal leaf metadata parsing, key/certificate compatibility lint, CertificateVerify signing, and non-goal of peer path validation.

### RFC 013 — Alerts, close_notify, and terminal policy

Defines fatal alert mapping, graceful close, inbound close_notify, transport EOF, abortive close, terminal states, and post-terminal behavior.

### RFC 014 — Deterministic test harness, fake crypto, fake transport, and fuzzing

Defines the fake provider, fake transport, scripted model tests, interpreter faithfulness tests, and fuzzing targets.

### RFC 015 — jemmet integration and E2E acceptance

Defines how jemmet consumes `TlsConn`, how ALPN is handed off, how HTTPS listener wiring works, and what end-to-end tests certify readiness.

### RFC 016 — Deferred future TLS features

Maintains scope control for peer X.509 path validation, client role, mTLS, tickets/resumption, HRR, KeyUpdate, 0-RTT, TLS 1.2, QUIC, DTLS, and performance tuning.

### Wave 2 — cross-cutting controls

| RFC | Theme | Why it matters |
|---|---|---|
| 017 | Threat model and abuse cases | Keeps every later decision grounded in internet-edge attacker behavior. |
| 018 | Data classification and lifecycle | Prevents accidental plaintext, secret, transcript, and queue ownership bugs. |
| 019 | Resource budgets and backpressure | Prevents slowloris, oversized-input, and hidden-buffer DoS classes. |
| 020 | Observability and redaction | Enables operation without leaking secrets or attacker-controlled blobs. |
| 021 | Configuration lifecycle and reload | Ensures SNI/ALPN/cert policy is validated, immutable, and atomically reloadable. |
| 022 | Proof gates and CI | Preserves verification value by blocking model/proof hygiene regressions. |
| 023 | Parser fuzzing corpus | Complements proofs with hostile byte-level regression pressure. |
| 024 | Native build and feature gates | Keeps pure core, FFI, fake providers, and interop profiles separated. |
| 025 | Performance and memory benchmark policy | Catches pathological allocation/latency without weakening invariants. |
| 026 | Compatibility and negative matrix | Defines what interop is tested and how unsupported TLS features fail. |
| 027 | API stability and versioning | Lets jemmet and future iotakt consumers depend on kroopt safely. |
| 028 | Security review and vulnerability process | Defines release blockers and handling for TLS-layer vulnerabilities. |
| 029 | Developer documentation and examples | Teaches correct `TlsConn` progress, write, close, ALPN, and config usage. |
| 030 | Production readiness and release runbook | Gives a release gate for proof, security, interop, docs, and operations. |

---

## 7. Cross-cutting security decisions

These decisions apply to every RFC:

1. **No early plaintext.** Public read/write APIs must not expose or accept application plaintext before the core is connected.
2. **No unauthenticated plaintext.** Decrypted bytes are emitted only after successful AEAD open and inner content-type validation.
3. **No secret logging.** Secret handles, keys, nonces, traffic secrets, transcript secrets, and private-key material must never derive printable or serializable interfaces.
4. **No unbounded queues.** Input reassembly, pending output, handshake bytes, extension counts, and progress loops are bounded.
5. **No stale result acceptance.** Crypto results and transport events are correlated to connection generation, epoch, and operation id.
6. **No proof bypass.** Runtime code may not implement alternate state transitions outside `Kroopt.Core.step`.
7. **No implicit trust store.** Server mode presents configured material; peer path validation is future scope.
8. **No feature creep into v0.4.** HRR, tickets, 0-RTT, KeyUpdate, TLS 1.2, client mode, and mTLS require separate RFC approval.

---

## 8. Suggested implementation order

1. RFC 001, 002: create the core shape and module dependency rules. Adopt RFC 017, 018, 022, 024 foundations alongside.
2. RFC 003: parser foundation before handshake logic. Begin RFC 023 corpus.
3. RFC 004, 005: record model and sequence/nonce/key proofs. Begin RFC 019 budget model.
4. RFC 006, 007: handshake and transcript logic.
5. RFC 014: fake crypto/transport tests; use them to drive the core before real FFI.
6. RFC 008, 009: crypto provider and HACL\*/EverCrypt attachment. Settle RFC 024 native profiles; begin RFC 025 microbenchmarks.
7. RFC 010: TlsConn and iotakt interpreter. Enforce RFC 019 budgets; stand up RFC 020 taxonomy.
8. RFC 011, 012: config, SNI/ALPN, certificate presentation. Apply RFC 021 snapshots.
9. RFC 013: alerts and close behavior across all paths.
10. RFC 026, 028: interop/negative matrix and pre-exposure security review before treating v0.3 interop as acceptance.
11. RFC 015: jemmet integration and E2E acceptance. Apply RFC 029 docs and RFC 030 readiness runbook.
12. RFC 016: maintain as a living backlog and scope guard throughout.

---

## 9. Management gates

### Gate A — model gate

No real socket and no HACL\*/EverCrypt FFI may be merged before the pure core compiles, the parser foundation exists, and the fake test harness can drive `step` directly. (RFC 002, 003, 014, 022.)

### Gate B — proof gate

No public `TlsConn` API may be treated as stable before the core proves no early plaintext, no unauthenticated plaintext, terminal-state behavior, nonce uniqueness, sequence monotonicity, and key separation. (RFC 005, 006, 013, 022.)

### Gate C — FFI gate

No real crypto provider may be used by default before known-answer tests and sanitizer jobs pass in CI. (RFC 008, 009, 024.)

### Gate D — network exposure gate

No iotakt network interop may be enabled by default before the interpreter is action-only, stale crypto/result correlation is implemented, resource budgets are enforced, and the pre-exposure security review is complete. (RFC 010, 017, 019, 028.)

### Gate E — jemmet gate

No jemmet integration may be merged as a default HTTPS path before OpenSSL/curl interop, negative tests, config validation, and redaction tests pass. (RFC 015, 020, 026.)

---

## 10. Deliverable definition

A roadmap item is complete only when it includes:

- implementation modules;
- tests;
- proof obligations or explicit proof deferral notes;
- documentation updates;
- proof/trust/test matrix update;
- security review note for any trusted or tested boundary.

"Works against curl" is not enough. For kroopt, each milestone must preserve the architecture that gives verification value.

---

## 11. Requirements reconciliation

The kroopt fixed requirements document (§20) enumerates RFCs 001–016. RFC 017–030 were added during planning as cross-cutting controls and are net-new relative to that list. This divergence is intentional and policy-compliant (RFC numbers are stable and additive), but it must not be silent:

- This ROADMAP is the canonical sequencing baseline for RFC 001–030.
- Requirements §20 remains the canonical scope baseline for wave 1 (RFC 001–016).
- The next revision of the requirements document should add a short note that wave 2 (RFC 017–030) exists as a continuation set, so the canonical requirements and the RFC index do not drift (RFC lifecycle policy "status fields that lie" and "letting cross-references rot" anti-patterns).
- Until that revision lands, treat any conflict between requirements §20 and the RFC set as: requirements win on wave-1 *scope*; this ROADMAP wins on *sequencing and the existence of wave 2*.

---

## 12. RFC lifecycle and this package

RFCs are managed under the [RFC lifecycle policy](rfcs/done/000-rfc-lifecycle-policy.md):

- All kroopt RFCs currently live in `rfcs/proposed/` because none has been implemented yet; the folder is the source of truth for state.
- When an RFC's work ships, it moves to `rfcs/done/` with its `**Status.**` field updated to `Implemented (vX.Y.Z)` in the same change, and `rfcs/README.md` is updated in that same commit.
- Withdrawn or superseded RFCs move to `rfcs/archive/` with a one-line reason.
- RFC numbers are permanent and never reused; cross-references use relative paths reflecting the target's current folder.
