# kroopt

A Lean 4 TLS 1.3 secure-channel library with a **pure verified protocol core**.

kroopt consumes an abstract non-blocking byte-transport interface
(`Kroopt.Conn.Transport`; [iotakt](https://github.com/nabbisen/iotakt) is one
instance) and presents a uniform plaintext connection interface upward to a
consumer such as an HTTP server (jemmet is one such consumer). It depends on
those *interfaces*, not on either project. The TLS state
machine is a total Lean function, `Kroopt.Core.step`, that emits explicit output
actions; a thin interpreter executes those actions over real crypto and sockets
and never makes protocol decisions of its own. That separation carries
machine-checked safety properties into the running code.

## Status: M0–M29 (verified core → handshake → TlsConn → config → alerts/close → HTTPS → hardening → native crypto → key schedule → real provider → orchestrator → both schedule stages wired into step → connection provisioning → Ed25519 RFC 8032 KAT verified + OpenSSL CertificateVerify interop + crypto KAT hardening → RFC lifecycle migration: 19 implemented RFCs moved to rfcs/done/ → real handshake wire serializer + full server-flight framing + server-Finished MAC KAT vs RFC 8448 §3 → real server-flight assembler + Ed25519 CertificateVerify → live step-driven real handshake to sentServerFinished)

This tree implements milestones **M0**–**M5** from the [ROADMAP](ROADMAP.md). M0
fixes the pure-core/interpreter architecture; M1 adds the bounds-safe parsing
foundation; M2 adds the TLS 1.3 record model with the *no unauthenticated
plaintext* proof; M3 proves the record layer's cryptographic discipline (sequence
monotonicity, no nonce wrap, nonce uniqueness, key separation); M4 adds the
server handshake state machine (no HelloRetryRequest) and the exact-wire-byte
transcript; M5 wires the handshake into the live `step` dispatcher and drives the
**full synthetic handshake end-to-end through `step`** against a fake transport
and fake crypto provider — closing the v0.1 synthetic-core line. M6 adds the crypto
provider trusted boundary with the **operation-id correlation guard** proved over
the live handshake; the native HACL\*/EverCrypt shim is contracted with its build
deferred until HACL\* is vendored, so the deterministic fake provider still stands
in and there are no sockets yet. M7 adds the runtime layer — the `TlsConn` API
and the thin interpreter, which executes the core's actions over a (fake)
transport and provider and carries no protocol logic; the real iotakt binding is
a thin deferred adapter. M8 makes server configuration real — an immutable,
validated SNI→cert table with deterministic ALPN negotiation and certificate
presentation, wired into the handshake, with the key selection-safety properties
proved (notably that ALPN never selects an unoffered protocol). M9 makes alert
mapping and close behaviour explicit and proved: a centralized deterministic
alert mapping, explicit graceful/fatal/abortive close states, truncation kept
distinct from clean close, and proved terminal discipline. M10 closes the v0.x
acceptance target: a consumer (e.g. jemmet) consumes kroopt through one uniform connection
abstraction (the same handler path for plaintext and TLS), with a full HTTPS
request served end-to-end over the fakes, ALPN handoff, redacted error views, and
negative inputs proven never to reach the handler as plaintext. M11 hardens
the edge: a resource-budget model with proved DoS bounds, deferred-feature scope
control, a documented threat model, and a third proof gate (axiom audit, no
`sorryAx`) wired into CI. These layers are built and proven first so the
protocol model and the running code cannot drift apart later (RFC 001–022, 024).

M12 begins the native crypto binding (v0.3): a vendored, portable-C subset of
HACL\* (Project Everest) is built through Lake and its verified primitives —
SHA-256/384, X25519, ChaCha20-Poly1305, HKDF/HMAC-SHA256, Ed25519 — are called
from Lean over a thin FFI and checked against RFC known-answer vectors
end-to-end (`kroopt-hacl-test`). This delivers the primitives layer; wiring it
into the stateful TLS key schedule is a scoped next step (a provider-arena
refactor), because the pure, handle-returning crypto provider the proofs rely on
cannot thread real key material on its own. See
[`docs/src/native-crypto.md`](docs/src/native-crypto.md) for the honest
boundary. The pure verified core still builds with no C toolchain; only the FFI
library and its KAT executable need a C compiler.

M13 does that provider-arena refactor. A generation-tagged secret arena
(`Kroopt.Crypto.SecretArena`) is threaded through `CryptoProvider.submit`, so
real key material can flow while the verified core still sees only opaque
handles (its 78 theorems are untouched). On top of it sits the real TLS 1.3 key
schedule (`Kroopt.Crypto.KeySchedule`) on HACL\*, **validated end-to-end against
the RFC 8448 §3 trace** — every secret, traffic key, IV, and Finished key matches
— plus a real derived key driven through the arena into the ChaCha20-Poly1305
AEAD (`kroopt-keyschedule-test`, 20 checks). It is not yet driven by
`Kroopt.Core.step`: the core's crypto ops must first be enriched (and their
correlation proofs re-established) to express a real schedule, which is the next
step toward a real handshake. See
[`docs/src/key-schedule.md`](docs/src/key-schedule.md).

M14 makes the seam expressive enough to drive that schedule and ships a real
provider. The `CryptoOp` interface now names secret inputs by opaque handle
(HKDF extract/expand with salt/IKM/secret handles, a traffic-key install op, and
ECDHE returning the server share), so the key schedule is a handle-threaded
chain — while the AEAD shapes, the only ones the proofs destructure, stay fixed,
so all 78 theorems hold unchanged. `Kroopt.Crypto.mkRealProvider` answers every
operation with real HACL\* cryptography, and `kroopt-realprovider-test` drives it
through the **exact RFC 8448 §3 operation sequence via `submit`** — the same
calls the core will emit — confirming every derived secret, a real record
round-trip, a real Ed25519 signature, and Finished-MAC verification. What remains
is for `Kroopt.Core.step` to *emit* this sequence (plus production entropy and
certificate provisioning); see
[`docs/src/enriched-crypto-interface.md`](docs/src/enriched-crypto-interface.md).

M15 takes that step on the core side: the *sequence* of the schedule — which op
comes next, with which handle — is now a pure, proved core state machine,
`Kroopt.Core.KeyScheduleDriver`. It emits the schedule's ops and threads the
handles; three machine-checked properties hold (it emits only ECDHE/HKDF/install
ops and never plaintext or AEAD-open, it makes monotone progress so the schedule
is finite, and `complete` is absorbing), lifting the audited theorem count to 82.
`kroopt-scheduledriver-test` drives this orchestrator through `mkRealProvider`,
feeding each result back to get the next op, and checks every collected secret and
the installed handshake key/IV against the RFC 8448 §3 trace. What remains is for
`Kroopt.Core.step` to *invoke* the orchestrator in the live handshake; see
[`docs/src/key-schedule-orchestrator.md`](docs/src/key-schedule-orchestrator.md).

M16 corrects the orchestrator's derivation timing to match TLS 1.3: handshake
keys are installed right after ServerHello, but application keys only after the
server Finished is committed. So the orchestrator now runs in **two stages** — a
handshake-key stage that parks at a `handshakeKeysInstalled` pause, then a
`resumeApplication` that supplies the CH..server-Finished transcript and runs the
application-key stage. The schedule-ops-only and progress proofs now cover both
stages (85 theorems), and `kroopt-scheduledriver-test` drives both through the real
provider, checking each stage against RFC 8448. The orchestrator now matches the
handshake's interleaving, so it can be driven exactly the way `step` will — the
wiring itself is the next milestone.

M17 takes that step: the handshake-key stage is now invoked by `Kroopt.Core.step`.
`onEcdheDone` frames ServerHello and starts the stage (storing the orchestrator in
the new `State.keySched` field, entering a `derivedHandshakeSecrets` pump phase);
`onHsScheduleResult` feeds each returning HKDF/install result to the orchestrator
and emits the next op, self-looping until the `handshakeKeysInstalled` pause, then
frames EncryptedExtensions/Certificate and requests the CertificateVerify signature.
The new phase's transitions are proved legal and the pump emits only
`callCrypto`/`writeTransport` — never plaintext — so the handshake's absence-based
safety proofs extend to it (86 theorems). The full synthetic handshake drives the
stage end-to-end through `step` in `kroopt-e2e-test` and `kroopt-handshake-test`.
The application-key stage is now wired too (M18): when the CertificateVerify
signature returns, `onCertVerifySigned` frames the server Finished, snapshots the
CH..server-Finished transcript, and calls `resumeApplication` to start the
application-key stage (→ `sentCertificateVerify`); `onApScheduleResult` pumps it to
`complete`, installs the application epoch, and moves to `sentServerFinished`. Both
pump phases are proved to take legal edges and emit no plaintext (87 theorems), and
the full synthetic handshake drives the entire RFC 8446 §7.1 schedule end-to-end
through `step`. M19 adds production connection provisioning (`Kroopt.Crypto.Provision`):
a fresh ephemeral X25519 key pair drawn from the OS CSPRNG per connection, and
certificate material derived (not trusted) from a signing seed with a fail-closed
config lint. The crypto KATs were strengthened along the way (SHA-512 binding + FIPS
180-4 value KATs). A suspected non-RFC-8032 Ed25519 "defect" reported in M19–M22 was
found in M23 to be a **false alarm — a test-vector provisioning error** (a non-RFC seed
paired with RFC Test 1's public key); HACL\* Ed25519 reproduces the RFC 8032 §7.1 Test 1
public key and signature byte-for-byte and interoperates with OpenSSL on the TLS 1.3
`CertificateVerify` construction (`scripts/ed25519-interop.sh`). What remains: resolve the
abstract transcript snapshots to real hashes and the real server-Finished MAC, then a full
handshake against OpenSSL/curl.

The headline M5 result: every M2/M3 safety theorem — above all *no early
plaintext* — **still holds over the live handshake**, which is the
proof/runtime correspondence contract.

What builds and is checked today:

- the pure core — `Kroopt.Core` (`Id`, `Common`, `CipherSuite`, `Record` with the
  TLS 1.3 record types and `SeqNo`, `Crypto`, `Nonce`, `Transcript` with the
  exact-byte binding, `State`, `Event`, `Action`, `RecordPath` with the live
  handshake dispatch, `Handshake` with the five transition functions, `Step`);
- the bounds-safe parser foundation — `Kroopt.Parse` (`Reader`, fixed-width and
  length-prefixed reads, the budgeted vector framer, the record framer
  `tryTakeRecord`, the `Handshake` ClientHello parser, inner-plaintext parsing,
  CCS classification);
- 78 machine-checked theorems in `Kroopt.Proofs` (audited by the axiom gate),
  including *no early plaintext*
  and *no unauthenticated plaintext* **preserved over the live handshake**, *no
  silent sequence wrap*, nonce uniqueness, key separation, *legal handshake
  transitions*, *client-Finished-before-connected*, *exact transcript byte
  binding*, *stale-crypto-result rejection* (operation-id correlation), *ALPN never selects an
  unoffered protocol*, *the fatal alert is the only post-failure write*, *resource budgets are hard
  bounds*, and parser bounds-safety — all with **no `sorry`/`axiom`/`unsafe`**,
  depending only on `propext` (some also `Quot.sound`, several on no axioms);
- deterministic tests — model (9), parser (18), record (19), nonce/seq (12),
  handshake/transcript (10), end-to-end through `step` (12), crypto provider +
  correlation (11), TlsConn + interpreter (13), SNI/ALPN/cert config (17),
  alerts + close (16),
  jemmet HTTPS E2E (12), hardening (12), all green, plus a parser/ClientHello fuzz
  harness, and three proof gates (hygiene, dependency, axiom) run in CI;
- two CI gates that run from M0: proof hygiene and module-dependency isolation.

See the [theorem inventory](docs/src/theorem-inventory.md) and
[proof-assumptions register](docs/src/proof-assumptions.md).

## Build and test

Requires the Lean toolchain pinned in [`lean-toolchain`](lean-toolchain)
(`leanprover/lean4:v4.15.0`), managed by [elan](https://github.com/leanprover/elan).
No mathlib, no C toolchain, no network reactor are needed for M0.

```sh
lake build                    # build the core + parser + proofs + test exes
lake exe kroopt-model-test    # M0 model test (drives `step`)
lake exe kroopt-parse-test    # M1 parser unit + negative tests
lake exe kroopt-record-test   # M2 record-model unit + negative tests
lake exe kroopt-nonce-test    # M3 sequence/nonce/key-separation tests
lake exe kroopt-handshake-test # M4 synthetic handshake + transcript tests
lake exe kroopt-e2e-test      # M5 full handshake end-to-end through `step`
lake exe kroopt-crypto-test   # M6 crypto provider + operation-id correlation tests
lake exe kroopt-conn-test     # M7 TlsConn API + non-blocking interpreter tests
lake exe kroopt-config-test   # M8 SNI/ALPN config + certificate presentation tests
lake exe kroopt-close-test    # M9 alerts, close_notify, and terminal-policy tests
lake exe kroopt-https-test    # M10 jemmet integration + end-to-end HTTPS acceptance
lake exe kroopt-hardening-test# M11 resource budgets + deferred-feature scope control
lake exe kroopt-hacl-test     # M12 native HACL* crypto KATs through the Lean FFI (needs a C compiler)
lake exe kroopt-keyschedule-test # M13 TLS 1.3 key schedule vs RFC 8448 + secret arena (needs a C compiler)
lake exe kroopt-realprovider-test # M14 real provider driven through RFC 8448 §3 via submit (needs a C compiler)
lake exe kroopt-scheduledriver-test # M15 verified orchestrator driving the real provider through RFC 8448 §3 (needs a C compiler)
./scripts/check-axioms.sh     # proof gate: no sorryAx across all public theorems
lake exe kroopt-parse-fuzz    # parser + ClientHello smoke fuzzer (optional arg: iterations)
./scripts/check-hygiene.sh    # RFC 022 proof-hygiene gate
./scripts/check-deps.sh       # RFC 022 module-dependency gate
```

## Layout

```text
Kroopt.lean            root module (re-exports the M0 core)
Kroopt/
  Error.lean           typed, redaction-safe error/alert taxonomy
  Core/                pure verified core: types, records, nonce, transcript, handshake, step
  Parse/               pure bounds-safe parser/framer foundation (Reader, …)
  Crypto/              trusted boundary: provider capability model + fake provider
  Native/              C shim contract (kroopt.h) — HACL* build deferred
  Conn/                runtime layer: TlsConn, interpreter, transport, jemmet integration
  Proofs/              structural proofs over `step` and the parser
Tests/
  Model.lean           deterministic model test (drives `step`)
  Parse.lean           parser unit + negative tests
  Record.lean          record-model unit + negative tests
  Nonce.lean           sequence/nonce/key-separation tests
  Handshake.lean       synthetic handshake + transcript tests
  EndToEnd.lean        full handshake end-to-end through `step` (fake crypto/transport)
  Crypto.lean          provider capability + operation-id correlation tests
  Conn.lean            TlsConn + interpreter faithfulness tests
  Config.lean          SNI/ALPN config + certificate-presentation tests
  Close.lean           alerts + close + terminal-policy tests
  E2EHttps.lean        jemmet integration + HTTPS end-to-end acceptance
  Hardening.lean       resource budgets + deferred-feature scope control
  Fuzz.lean            parser + ClientHello smoke fuzzer
scripts/               CI gates (hygiene, module dependencies)
docs/src/              mdbook documentation (incl. theorem inventory)
rfcs/                  RFC set, managed per rfcs/done/000 lifecycle policy
ROADMAP.md             milestones, dependency map, release staging
```

The development plan lives in the [RFC set](rfcs/README.md) and the
[ROADMAP](ROADMAP.md). RFCs are managed under the
[RFC lifecycle policy](rfcs/done/000-rfc-lifecycle-policy.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

kroopt vendors a portable-C subset of HACL\* (MIT) with the kremlin headers
(Apache-2.0) under `Kroopt/Native/hacl/`, redistributed verbatim with headers
intact. See [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md),
[`Kroopt/Native/hacl/LICENSE`](Kroopt/Native/hacl/LICENSE), and the
[provenance docs](docs/src/third-party.md).
