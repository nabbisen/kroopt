# Changelog

All notable changes to kroopt are recorded here. RFC lifecycle transitions are
governed by [`rfcs/done/000-rfc-lifecycle-policy.md`](rfcs/done/000-rfc-lifecycle-policy.md).

## [0.45.0-dev] — M36 (RFC 032 slice 3): typed Certificate action — 2026-06-12

Third step of RFC 032: Certificate becomes a typed action. Because the core holds only an
opaque chain handle (no DER), the interpreter owns the DER resolution.

### Added

- `Core/Action.lean`: `OutputAction.writeCertificate (conn) (chain :
  CertificateChainHandle)` (a distinct action, not a `HandshakeOut` case, since its bytes
  are not pure-serializable), with classifier simp lemmas. Action now imports
  `Core.Cert` for the handle type (cycle-free).

### Changed

- `Core/Handshake.lean`: `step` emits `writeCertificate (selectedCert)` rather than a
  placeholder `writeTransport`. The abstract transcript contribution is unchanged.
- `Conn/Interpreter.lean`: a `writeCertificate` arm serializes the Certificate from the
  handle. With no configured DER wired into the runtime yet (RFC 031), production
  serializes a structurally-valid empty Certificate instead of the four-byte placeholder.
- `Tests/RealHandshake.lean`, `Tests/EndToEnd.lean`: drivers resolve the handle to their
  configured chain (the real test cert / an empty Certificate) and bind the
  CH‥Certificate transcript hash, matching the placeholder path they replace.

### Proofs

- Theorem set unchanged (91, axiom-clean); the new constructor is handled by the existing
  wildcard classifiers.

### Tests

- 24/24 suites pass, including socket and wire (which validate server-flight bytes); the
  synthetic flight reaches `connected` with a byte-identical Certificate.

### RFC lifecycle

- **RFC 032** stays in `proposed/`. Three of five server-flight messages
  (EncryptedExtensions, Certificate, CertificateVerify) are now typed and first-byte-free.
  Remaining: ServerHello + Finished (need server-share / Finished-MAC crypto-op flow), the
  §5 transcript restatement, and the §7 CI gate.

## [0.44.0-dev] — M36 (RFC 032 slice 2): typed CertificateVerify action — 2026-06-12

Second step of RFC 032: CertificateVerify joins EncryptedExtensions as a typed
handshake-output action, realizing the two-stage request/write rule for it.

### Added

- `Core/Action.lean`: `HandshakeOut.certificateVerify (scheme : UInt16) (signature :
  ByteArray)`.
- `Core/Handshake.lean`: `sigSchemeToU16` (SignatureScheme → wire code point) and the
  CertificateVerify case of `serializeHandshakeOut`.

### Changed

- `Core/Handshake.lean`: `onCertVerifySigned` emits `writeHandshake (.certificateVerify
  <scheme> <sig>)` instead of a placeholder `writeTransport`. The signature is the core's
  own `signCertificateVerify` result and the scheme is a negotiated fact, so serialization
  is authorized by the typed write action — not by bare crypto-result arrival (RFC 032 §4
  two-stage rule). The abstract transcript contribution is unchanged.
- `Tests/RealHandshake.lean`: the typed-message driver refreshes the post-CertificateVerify
  transcript hash (over which the server Finished MAC is taken), matching the placeholder
  path it replaces.

### Proofs

- Theorem set unchanged (91, axiom-clean). `writeHandshake` continues to be handled by the
  existing wildcard classifiers; no proof edits.

### Tests

- 24/24 suites pass; the synthetic flight reaches `connected` with byte-identical
  CertificateVerify, and the Ed25519 CertificateVerify interop check is unaffected.

### RFC lifecycle

- **RFC 032** stays in `proposed/`. Two of five server-flight messages
  (EncryptedExtensions, CertificateVerify) are now typed and first-byte-free. Remaining:
  Certificate (interpreter owns DER behind the chain handle), ServerHello + Finished
  (need server-share / Finished-MAC crypto-op flow), the §5 transcript restatement, and
  the §7 CI gate.

## [0.43.0-dev] — M36 (RFC 032 slice 1): typed EncryptedExtensions action — 2026-06-12

First step of RFC 032 (Typed Handshake/Record Assembly Contract): the core begins emitting
typed handshake-output actions that carry protocol facts instead of placeholder frame
bytes, with a single pure serializer realizing the wire bytes. EncryptedExtensions is
converted; no path recognizes it by its first byte.

### Added

- `Core/Action.lean`: `inductive HandshakeOut` (slice 1: `encryptedExtensions (alpn :
  Option ByteArray)`) and `OutputAction.writeHandshake (conn) (msg : HandshakeOut)`.
  Classifier simp lemmas mark `writeHandshake` as neither a plaintext emit nor an ordinary
  transport write.
- `Core/Handshake.lean`: `serializeHandshakeOut`, the one pure serializer that realizes a
  typed handshake message into wire bytes (EncryptedExtensions → ALPN-bearing exts).

### Changed

- `Core/Handshake.lean`: `step` emits EncryptedExtensions as `writeHandshake
  (.encryptedExtensions <selected ALPN>)` rather than a placeholder `writeTransport`. The
  abstract transcript contribution is unchanged (real-bytes transcript is a later slice).
- `Conn/Interpreter.lean`, `Tests/EndToEnd.lean`, `Tests/RealHandshake.lean`: realize
  `writeHandshake` via total pattern matching on the typed message through the shared
  `serializeHandshakeOut` — no first-byte dispatch for EncryptedExtensions.

### Proofs

- Theorem set unchanged (91, axiom-clean). `writeHandshake` is handled by the existing
  wildcard classifiers and the `isPlaintextEmit_eq_true` lemma's `simp` branch; the
  action-discipline and transcript-consistency proofs hold without edits.

### Tests

- 24/24 suites pass. The synthetic server flight still reaches `connected` with identical
  EncryptedExtensions wire bytes (the typed path serializes byte-for-byte what the
  placeholder path produced); the e2e flight-count and seven-message-transcript checks are
  unaffected.

### RFC lifecycle

- **RFC 032** stays in `proposed/`; this lands acceptance criterion 1 for one message.
  Deferred to later slices: CertificateVerify (two-stage), Certificate (handle→DER in the
  interpreter), ServerHello + Finished (need server-share / MAC crypto-op flow), the
  transcript-over-real-bytes restatement (§5), and the placeholder/first-byte CI gate (§7).

## [0.42.0-dev] — M36 (part 6): handshake-message reassembler — RFC 033 complete — 2026-06-12

The bounded handshake-message reassembler lands, completing RFC 033 (Real-Client
Handshake Processing). A ClientHello fragmented across records now parses correctly.

### Added

- `Core/State.lean`: `handshakeReasm : ByteArray` — the handshake-message reassembly
  buffer, a plain `ByteArray` with a runtime cap (like `inboundCiphertext`).
- `Core/RecordPath.lean`: `frameHandshakeMessage` frames one complete handshake message
  (1-byte type, 3-byte length, body), returning the message and the unconsumed tail, or
  `none` while incomplete; `maxHandshakeReasmBytes` bounds the buffer.

### Changed

- `Core/RecordPath.lean`: the plaintext handshake branch of `handleTransportBytes` now
  accumulates record fragments into `handshakeReasm`, frames and processes one complete
  message, keeps the tail for the next record, and fails the connection (oversized-record
  alert) if the buffer exceeds the bound. Previously each record body was assumed to be
  one complete handshake message, so a fragmented ClientHello was rejected as truncated.

### Tests

- `kroopt-realhandshake-test` (+3 checks, 28 total): `frameHandshakeMessage` framing unit
  (complete / incomplete / coalesced-with-tail); a ClientHello split across two records
  reassembles to the same state as one delivered whole; an over-large reassembly buffer
  fails the connection.
- Fixed three synthetic client-Finished fixtures (`Tests/EndToEnd`, `Tests/Conn`,
  `Tests/E2EHttps`) that used a 2-byte length where a handshake message requires a 3-byte
  length, and one malformed-ClientHello fixture made complete-per-header so the parser
  (not the reassembler) rejects it. These were latent malformations the old lenient path
  ignored; the reassembler parses the header correctly and exposed them.

### Proofs

- No change to the proof set (91 theorems, all axiom-clean). The three theorems that
  case-split `handleTransportBytes` hold over the new branch unchanged — the obligation
  is `pendingPlainOut` preservation. The earlier deferral cited a missing
  `ByteArray.extract` size bound; that premise was false (the buffer is unproven-size,
  capped at runtime), so no extract lemma was needed.

### RFC lifecycle

- **RFC 033** (Real-Client Handshake Processing) → `done/`, **Implemented (0.42.0-dev)**.
  All six M36 parts complete: protected client Finished in-core, capability-bound
  negotiation of all three parameters, ClientHello strictness, the CCS phase window, and
  the reassembler. RFC counts: done 22, proposed 16.

## [0.41.0-dev] — M36 (part 5): explicit change_cipher_spec phase window (RFC 033) — 2026-06-12

The compatibility-mode `change_cipher_spec` record is now confined to its RFC 8446 §5
window in the record path; the payload check was already present.

### Changed

- `Core/RecordPath.lean`: `handleTransportBytes` gates the `change_cipher_spec` branch on
  the handshake phase. A compatibility CCS is accepted-and-ignored only during an active
  handshake (after the ClientHello, before the client's Finished). A CCS before any
  ClientHello (`start`), after `connected`, or while closing/terminal is rejected as an
  illegal record (`unexpectedMessage`). The single-0x01 payload check (`classifyCcs`)
  was already in place.

### Tests

- `kroopt-close-test` (+3 checks, 19 total): a compatibility CCS during the handshake is
  accepted and ignored; a CCS before any ClientHello is rejected; a CCS after `connected`
  is rejected.

### Proofs

- No change to the proof set (91 theorems, all axiom-clean). The three theorems that
  case-split `handleTransportBytes` (`buffered_plaintext_authenticated`,
  `aeadOpen_uses_read_keys`, `successful_open_increments_read_seq`) hold over the added
  branch unchanged.

### RFC lifecycle

- **RFC 033** — partial; stays in `proposed/`. One item remains: the bounded
  handshake-message reassembler (gated on a clean `ByteArray.extract` size bound).

## [0.40.0-dev] — M36 (part 4): ClientHello strictness on legacy fields (RFC 033) — 2026-06-12

The ClientHello parser now enforces two TLS 1.3 invariants on legacy fields it
previously parsed but ignored (RFC 8446 §4.1.2).

### Changed

- `Parse/Handshake.lean`: reject a ClientHello whose `legacy_version` is not 0x0303
  (TLS 1.3 carries version preference in `supported_versions`; the legacy field is
  fixed by the spec). Reject a ClientHello whose `legacy_compression_methods` is
  anything other than the single null byte (compression is forbidden in TLS 1.3).

### Tests

- `kroopt-hardening-test` (+2 checks, 18 total): a ClientHello with `legacy_version`
  ≠ 0x0303 is refused; a ClientHello offering non-null compression is refused. New
  `chBadVersion` / `chBadCompression` / `rejects` helpers.

### Proofs

- No change to the proof set (91 theorems, all axiom-clean). The new checks are
  conditionals on already-parsed values; the parser bounds proofs are unaffected.

### RFC lifecycle

- **RFC 033** — still partial; stays in `proposed/`. Remaining: the handshake-message
  reassembler and explicit `change_cipher_spec` policy.

## [0.39.0-dev] — M36 (part 3): cipher-suite selection bound to provider capability (RFC 033) — 2026-06-12

Negotiation now selects the cipher suite from the client's offers *and* binds it to
what the provider can actually perform — completing the overlap-selection discipline
across all three negotiated parameters (suite, group, signature scheme).

### Changed

- `Parse/Handshake.lean`: `suiteOfU16` maps only `TLS_CHACHA20_POLY1305_SHA256` (0x1303),
  the suite the vendored provider performs; the AES-GCM code points map to `none` and
  are skipped by `selectSuite`. kroopt no longer negotiates a suite it cannot complete,
  even when the client lists it first. The map widens when a real AES provider lands
  (RFC 035).

### Fixed

- A latent inconsistency the test harness masked: with a `13 01 13 03` ClientHello (AES
  first), the core selected AES-128-GCM while the ServerHello and key schedule used
  ChaCha20-Poly1305. The core now selects ChaCha20, matching the schedule.

### Tests

- `kroopt-hardening-test` (+2 checks, 16 total): a ClientHello offering only AES-128-GCM
  is refused; a ClientHello listing AES-128-GCM before ChaCha20 negotiates ChaCha20
  (capability overlap, not first-offered). New `chWithSuites` / `negotiatedSuite` helpers.
- `kroopt-e2e-test`, `kroopt-conn-test`: the negotiated-suite assertions now expect
  ChaCha20-Poly1305 (they previously encoded the buggy AES-128-GCM selection).
- Three fake-provider fixtures (EndToEnd, Conn, E2EHttps) now offer ChaCha20 in their
  ClientHello, matching the real constrained profile.

### Proofs

- No change to the proof set (91 theorems, all axiom-clean). Suite selection is pure
  list folding over bounds-checked data; the parser bounds proofs are unaffected.

### RFC lifecycle

- **RFC 033** — still partial; stays in `proposed/`. Remaining: handshake-message
  reassembler, broader ClientHello strictness (`legacy_version`, etc.), and explicit
  CCS policy.

## [0.38.0-dev] — M36 (part 2): signature_algorithms overlap selection (RFC 033) + repo hygiene — 2026-06-12

The ClientHello parser now negotiates the signature scheme from the client's offers
instead of hardcoding it, plus repository-hygiene work (GitHub language classification,
README, docs layout).

### Changed

- `Parse/Handshake.lean`: **signature_algorithms overlap selection.** New
  `sigSchemeOfU16` / `selectSigScheme` / `offeredSigSchemes` read the client's offered
  schemes (extension 0x000d) and select Ed25519 (0x0807) only when the client offers
  it — mirroring `selectSuite`. `parseClientHello` no longer hardcodes
  `selectedSigScheme := .ed25519`; a cert-authenticating server with no acceptable
  overlap (no `signature_algorithms`, or only RSA/ECDSA) is rejected (RFC 8446 §4.2.3).
  This makes the constrained profile's interop limit explicit: kroopt rejects the
  RSA/ECDSA-only RFC 8448 §3 ClientHello rather than presenting an Ed25519 certificate
  the client cannot verify.

### Repository hygiene

- **`.gitattributes`**: the vendored `Kroopt/Native/hacl/**` (HACL*/EverCrypt with the
  KaRaMeL C runtime, ~26k lines) is marked `linguist-vendored`, so GitHub classifies
  the repository by its own Lean 4 sources rather than the borrowed C. Every byte and
  its license stay in the tree and in production builds; only the language-stats display
  changes. Our own ~330-line FFI/socket shim remains first-party and counted.
- **README.md** rewritten (247 → 108 lines): a concise hero/overview/quick-start/design-
  notes/docs structure replaces the run-on status line and the stale per-milestone wall;
  the per-milestone history now lives in this changelog and the ROADMAP.
- **docs/src/** reorganized into `architecture/`, `crypto/`, and `verification/`
  subdirectories (introduction stays at the root); `SUMMARY.md` and all inter-doc and
  top-level links updated and verified to resolve.

### Tests

- `kroopt-hardening-test` (+2 checks, 14 total): a ClientHello offering only ECDSA/RSA
  signature_algorithms is refused; a ClientHello with no signature_algorithms is refused.
- `kroopt-wire-test`: the RFC 8448 §3 ClientHello check now asserts the constrained
  profile **rejects** it (no Ed25519 overlap); the byte-level serialization and SHA-256
  transcript KATs over the raw RFC 8448 bytes are unchanged.
- Five fixtures (EndToEnd, Conn, E2EHttps, Hardening, Wire) updated to carry a realistic
  `signature_algorithms` extension.

### Proofs

- No change to the proof set (91 theorems, all axiom-clean). The selection logic is pure
  list folding over already-bounds-checked extension data; the parser bounds proofs are
  unaffected.

### RFC lifecycle

- **RFC 033** — still partial; stays in `proposed/`. Remaining: handshake-message
  reassembler, broader ClientHello strictness, explicit CCS policy, and binding
  cipher-suite selection to the provider's presentation capability.

## [0.37.0-dev] — M36 (part 1): the client Finished opens in the core (RFC 033) — 2026-06-12

The receive-side blocker from the architecture review (deep-review blocker #2): the
core now processes the **protected client Finished in-core** instead of silently
dropping it, driving the handshake to `connected` entirely through `Core.step` with
no out-of-core decryption workaround. The no-unauthenticated-plaintext guarantee is
preserved and re-proved.

### Changed

- `Core/RecordPath.lean`: `readMeta` is **epoch-aware** (`epoch := s.readEpoch.epoch`).
  A protected record arriving in `sentServerFinished` is opened under the **handshake**
  read epoch; the opened inner message is routed through `handshakeOnPlaintextRecord`
  → `onClientFinishedBytes` → `verifyFinished` → `connected`. Inner application data
  before `connected` is fatal. The two pre-`connected` silent drops are gone.
- `Core/Handshake.lean`: **read-epoch correctness.** The read epoch stays `handshake`
  through `sentServerFinished` (only the server's *write* switches to application
  after its Finished) and becomes `application` when the client Finished verifies.
  Previously the application read epoch was installed too early.

### Proofs (91 theorems, all axiom-clean; was 87)

- `Proofs/RecordPath.lean`: re-proved `buffered_plaintext_authenticated` (no
  unauthenticated plaintext) over the new branch, via four new
  `pendingPlainOut`-preservation lemmas (`onClientHello_pp`, `onClientFinishedBytes_pp`,
  `handshakeOnClientHello_pp`, `handshakeOnPlaintextRecord_pp`).
- `Proofs/KeySeparation.lean`: `aeadOpen_uses_read_keys` now proves the honest
  property `meta.direction = .read ∧ meta.epoch = s.readEpoch.epoch` (opens use the
  current read epoch — handshake for the client Finished, application afterwards).
- `Proofs/Nonces.lean`: `successful_open_increments_read_seq` re-proved over the new
  branch (which buffers no plaintext).

### Tests

- `kroopt-realhandshake-test` (+4 checks, 25 total): the **sealed** client Finished is
  driven through `step`, asserting the core opens it under the handshake epoch, routes
  it to `verifyFinished`, reaches `connected`, and buffers no application plaintext.
- `kroopt-nonce-test`: `connectedState` now carries application epochs (faithful to the
  real connected transition).

### RFC lifecycle

- **RFC 033** — partial; stays in `proposed/`. Remaining: bounded handshake-message
  reassembler (fragmented/coalesced records), overlap-selection negotiation, ClientHello
  strictness, explicit CCS. The current fix handles a single-record-complete Finished.

## [0.36.0-dev] — M36-prelude: provider capability honesty + fail-closed entropy (RFC 034) — 2026-06-12

The immediate honesty fixes the architecture review asked to fast-track ahead of the
M36 correspondence work. The real provider no longer advertises crypto it cannot
perform, and entropy no longer fails open. No core or proof changes — the 87 theorems
and 36 pure-zone files are unchanged.

### Added

- `Kroopt.Crypto.Provider.realCapabilities` — the real provider's honest, constrained
  profile: `TLS_CHACHA20_POLY1305_SHA256`, X25519, Ed25519, SHA-256, OS CSPRNG. No
  AES-GCM, SHA-384, P-256, ECDSA, or RSA.
- `Kroopt.Crypto.ConfigCheck` — `requiredCryptoOfServerConfig` and
  `validateServerConfigCapabilities`, rejecting a config that requires out-of-profile
  suites/signature schemes with a typed `CapabilityError` (RFC 008 §3 / RFC 034 §2).
- `Kroopt.Crypto.Hacl.RandomResult` / `EntropyError` and a fail-closed `randomBytes`
  returning a typed result.
- `kroopt-capabilities-test` (8 checks): real profile rejects AES/ECDSA and accepts the
  constrained config; the fake profile still accepts AES (profiles differ); the real
  provider advertises the constrained profile; a `randomBytes` op reaching the real
  provider is a typed error; entropy is fail-closed and typed.

### Changed

- `mkRealProvider.capabilities` is now `realCapabilities` (was `fakeCapabilities`).
- The real provider's `randomBytes` operation returns a typed error instead of
  deterministic zeros — deterministic randomness can never enter the real provider.
- `kroopt_ffi_random` fails **closed**: on `getrandom` failure it returns a zero-length
  buffer (never a zero-filled buffer reported as success).
- `Provision.genEphemeralX25519` / `provisionRealConfig` fail closed with a new
  `ProvisionError.entropyFailure` rather than emit a zero or partial key.
- Docs: `crypto-ffi-contract.md` and `proof-assumptions.md` record the real capability
  profile and the fail-closed entropy guarantee.

### RFC lifecycle

- **RFC 034** — *Provider Capability Honesty and Fail-Closed Entropy* — moved to
  `rfcs/done/` (Implemented, 0.36.0-dev). The config-capability check's call-site at live
  listener startup is the one deferred mechanical item, tracked to RFC 010 / RFC 031.
- RFCs 031–037 amended per the RFC-set review (handshake-message reassembly, transcript
  precision, two-stage crypto actions, overlap-selection negotiation, the 034 split, new
  RFC 036 trace harness); archive layout fixed to `rfcs/proposed/`.

## [0.35.0-dev] — M35 TLS 1.3 records over a real OS socket — 2026-06-12

A full server flight now traverses a real OS socket and opens on the peer,
exercising the transport boundary with real kernel I/O for the first time. No core,
crypto, or proof changes — the 87 theorems are unchanged.

### Added

- `Kroopt/Native/kroopt_socket.c`: minimal, test-only `AF_UNIX` socketpair plus
  blocking read/write/close (no protocol logic), wired through the same IO FFI ABI as
  `randomBytes`. kroopt's production core still performs no syscalls; this glue exists
  only to drive a test over a real socket.
- `kroopt-socket-test` (`Tests/SocketHandshake.lean`): seals a server flight
  (cleartext ServerHello + four `TLSCiphertext` records for EE/Cert/CertVerify/
  Finished under the server handshake key), writes it to the socket, and a peer reads
  the records back and opens them; the peer's encrypted Finished and an application
  record then round-trip the other way — all over the socketpair (5 checks). Added to
  CI (now 22 suites).
- `docs/src/socket-transport.md`.

### Notes

This de-risks the transport binding with real kernel I/O. The production iotakt
socket adapter (RFC 010) and a live `openssl s_client` / `curl` handshake (RFC
015/026) remain: they run the same record layer over a real, non-blocking,
externally-driven peer.

## [0.34.0-dev] — M34 record-layer cross-implementation interop — 2026-06-12

An independent implementation now decrypts kroopt's TLS 1.3 records, establishing
that the record layer is standards-compliant rather than only self-consistent. No
core, crypto, or proof changes — the 87 theorems are unchanged.

### Added

- `kroopt-wire-dump` (`Tests/WireDump.lean`): emits real `Record13`-sealed records
  (a handshake EncryptedExtensions at seq 0 and application data at seq 1, under the
  RFC 8448 §3 server handshake-traffic secret) for an outside tool to open.
- `scripts/record-interop.sh`: Python's `cryptography` library independently derives
  the traffic key/IV (RFC 8446 §7.3 HKDF-Expand-Label), reconstructs the §5.3 nonce
  and §5.2 AAD, and decrypts kroopt's records — recovering the exact plaintext and
  inner content type, and rejecting a tampered record. Added to CI.
- `docs/src/record-protection.md`: a cross-implementation interop section.

### Notes

A non-kroopt implementation decrypting kroopt's records is interop-grade evidence for
the record layer (RFC 026, partial). A full `openssl s_client` / `curl` handshake
still awaits productionizing the interpreter and the iotakt socket transport
(RFC 010).

## [0.33.0-dev] — M33 real Ed25519 X.509 certificate presentation — 2026-06-12

The live handshake now presents a real, OpenSSL-parseable Ed25519 X.509 certificate
instead of a placeholder DER, and the OpenSSL cross-check ties that certificate to
the CertificateVerify signature. No core, crypto, or proof changes — the 87 theorems
are unchanged.

### Added

- `scripts/gen-test-cert.sh`: provisions a self-signed Ed25519 `CN=kroopt.test`
  certificate whose subject public key is kroopt's certificate key (the RFC 8032
  §7.1 key that also signs CertificateVerify), via an RFC 8410 PKCS#8 wrap of the
  raw seed.
- `Tests/RealHandshake.lean`: presents the real 351-byte certificate DER (`certDer`)
  in the Certificate message and checks it is a well-formed X.509 embedded at the
  expected offset, with the handshake still reaching `connected` (21 checks).
- `scripts/ed25519-interop.sh` step 5: OpenSSL parses kroopt's certificate, confirms
  the leaf public key extracted from it equals kroopt's signing key, and verifies a
  kroopt CertificateVerify signature under that extracted leaf key — the property a
  real client relies on.
- `docs/src/cert-presentation.md` (linked in `SUMMARY.md`).

### Notes

A real client could now parse kroopt's Certificate message and verify its
CertificateVerify. This is a prerequisite for `openssl s_client` / `curl` interop,
which still awaits productionizing the interpreter and the iotakt socket transport
(RFC 010). Certificate path validation (client role / mTLS) stays out of scope.

## [0.32.0-dev] — M32 encrypted flight on the wire (record protection in the send/receive path) — 2026-06-12

The live `step`-driven handshake now exchanges real TLS 1.3 records: the server
flight after ServerHello is sealed, and the inbound client Finished is opened, in the
interpreter layer, while the core works on plaintext (its design). No core, crypto,
or proof changes — the 87 theorems are unchanged.

### Added

- `Tests/RealHandshake.lean` now applies `Record13` record protection across the
  handshake (20 checks): the ServerHello goes in the clear; EncryptedExtensions,
  Certificate, CertificateVerify, and Finished are sealed as four real `TLSCiphertext`
  records under the server handshake-traffic key with handshake-epoch sequences 0–3,
  each verified to decrypt back to its plaintext message; the client's Finished
  arrives as a real encrypted record that the interpreter opens (with the client
  handshake-traffic key) to drive the core to `connected`. The ServerHello now
  advertises `TLS_CHACHA20_POLY1305_SHA256` so the negotiated record cipher matches
  the wire protection. The transcript hash remains over the plaintext messages.

### Notes

The wire is now genuine TLS 1.3 records, but the seal/open lives in the test driver
(not yet the production `Conn.Interpreter`) and records are exchanged in memory (not
over a socket). Folding this into the production send/receive path and the iotakt
socket transport (RFC 010) is next, enabling OpenSSL/curl interop (RFC 015 / 026).

## [0.31.0-dev] — M31 real TLS 1.3 record protection (ChaCha20-Poly1305) — 2026-06-12

Adds the record-protection framing that turns a message + content type into a real
`TLSCiphertext` and back, and demonstrates it end-to-end over the live handshake's
negotiated keys. The verified core and its 87 theorems are unchanged.

### Added

- `Kroopt/Conn/Record13.lean` (impure interpreter zone): `innerPlaintext`
  (`content || content_type || zero*`), `recordAAD` (the §5.2 TLSCiphertext header),
  and `sealRecord` / `openRecord` — ChaCha20-Poly1305 under that AAD with the
  per-record nonce (`IV XOR seq`), wrapping/unwrapping the outer
  `application_data` record and stripping padding on open. No plaintext escapes a
  framing or authentication failure.
- `kroopt-record13-test` (`Tests/Record13.lean`, 11 checks): round-trip, wire
  structure, ciphertext-not-plaintext, padding stripping, content-type recovery, and
  authentication failures (tamper, wrong key, wrong sequence — the nonce binds the
  sequence).
- `Tests/RealHandshake.lean` now protects a real application-data record under the
  server application-traffic key derived by the live handshake after `connected`
  (16 checks total), confirming the round-trip and that the body is ciphertext.
- `docs/src/record-protection.md` (linked in `SUMMARY.md`). CI runs 21 suites.

### Notes

ChaCha20-Poly1305 is the record cipher (no AES-GCM in the vendored HACL subset), so
these are self-consistent round-trips, not an RFC 8448 §3 (AES-128-GCM) replay. The
verified core does not yet emit seal/open actions for the handshake flight (still
assembled in the clear in the driver), and records are not yet driven over a socket;
wiring record protection into the core's send/receive path and the iotakt socket
transport (RFC 010) is next, enabling OpenSSL/curl interop (RFC 015 / 026).

## [0.30.0-dev] — M30 live `step`-driven handshake reaches `connected` — 2026-06-12

The live `step`-driven real handshake (M29) now runs to **`connected`**: the driver
feeds a real client Finished and the verified core completes the handshake. A
correctness fix to the secret arena was required; the verified core and its 87
theorems are unchanged.

### Changed

- `Kroopt/Crypto/Arena.lean`: base traffic-secrets are now keyed by
  `(Direction × Epoch)` instead of `Epoch` alone (matching how installed record
  keys are keyed). A TLS 1.3 server verifies the client's Finished with the **read
  (client)** handshake-traffic secret; keying by epoch alone let the read/write
  secrets overwrite each other. `recordBaseSecret` / `lookupBaseSecret` take a
  direction.
- `Kroopt/Crypto/RealProvider.lean`: `verifyFinished` looks up the read-direction
  handshake base secret and compares its HMAC against the verify_data extracted from
  the client Finished message body (the octets after the 4-octet handshake header).

### Added

- `Tests/RealHandshake.lean` now drives to `connected` (14 checks): captures the
  client and server hs-traffic secrets, computes a real client Finished
  (`HMAC(finished_key(client_hs_traffic), Transcript-Hash(CH‥ServerFinished))`),
  feeds it back, and confirms the core reaches `connected`; a negative control
  confirms a wrong client Finished is rejected.

### Notes

The full server handshake now completes through the verified core on real crypto
over real wire bytes. The flight messages are still assembled in the clear (not yet
sealed with the record AEAD keys); real record encryption, the iotakt socket
transport (RFC 010), and OpenSSL/curl interop (RFC 015 / 026) remain.

## [0.29.0-dev] — M29 live `step`-driven real handshake (real provider + real transcript) — 2026-06-12

Drives the verified core `Kroopt.Core.step` state machine through a server
handshake against the **real** crypto provider with a **real transcript** assembled
by `Kroopt.Conn.Flight`, to `sentServerFinished`. The verified state machine is
unchanged: the 87 theorems and the 36 pure-zone files are untouched.

### Added

- `Tests/RealHandshake.lean` (`kroopt-realhandshake-test`, 12 checks): a driver that
  runs each `callCrypto` against `RealProvider.submit` (real HACL X25519 / HKDF /
  Ed25519 / HMAC, threading a real `SecretArena`) and maintains a real transcript —
  recognising each server-flight placeholder by message type, assembling the real
  bytes via `Flight`/`Wire`, and substituting the real transcript hashes
  (`CH‥SH`, `CH‥Cert`, `CH‥ServerFinished`) at the crypto seam. It checks that the
  live core runs without error to `sentServerFinished`, emits the full real server
  flight (SH, EE, Cert, CertVerify, Finished, in order), and produces a **valid
  Ed25519 CertificateVerify over the real transcript** (verifies against the leaf
  key; rejected against a wrong hash). CI now runs 20 suites (`realhandshake`).
- `docs/src/live-handshake.md` (linked in `SUMMARY.md`).

### Notes

This is a self-consistent handshake, not a replay of RFC 8448 §3: kroopt's cert is
Ed25519 (no RSA/P-256 in the vendored HACL), so the ClientHello offers `ed25519`
and the transcript is kroopt's own. The certificate entry is an opaque placeholder
DER (real provisioning is separate); it does not affect the CertificateVerify, which
signs the transcript hash. Remaining toward live interop: client Finished →
`connected`, real record encryption, the iotakt socket transport (RFC 010), and
OpenSSL/curl interop (RFC 015 / 026).

## [0.28.0-dev] — M28 real server-flight assembler + Ed25519 CertificateVerify — 2026-06-12

Adds the interpreter-side component that turns negotiated parameters and real
crypto outputs into the exact server-flight wire bytes, and produces a **real**
Ed25519 CertificateVerify with kroopt's own key. No change to the verified state
machine: the 87 theorems and existing suites are unchanged.

### Added

- `Kroopt/Conn/Flight.lean` (impure interpreter zone) composing the M26/M27 wire
  serializers with HACL primitives: `transcriptHash`, `serverHelloMessage`,
  `serverFinishedVerifyData` / `serverFinishedMessage`, and the real
  CertificateVerify path (`certVerifyContent` / `signCertVerify` /
  `verifyCertVerify` / `certificateVerifyMessage`). The core holds only abstract
  handles (no DER, no signature, no MAC, no random); this module is where those
  real bytes are supplied.
- `kroopt-flight-test` (`Tests/Flight.lean`, 14 checks): the RFC 8446 §4.4.3
  CertificateVerify content construction (the format cross-validated against
  OpenSSL in `scripts/ed25519-interop.sh`); a real Ed25519 sign/verify round-trip
  that rejects a wrong transcript hash and a wrong key; the Ed25519 key anchored to
  the RFC 8032 §7.1 KAT; ServerHello assembly and the server `finished_key` /
  Finished MAC anchored to RFC 8448 §3. CI now runs 19 suites (`flight`).
- `docs/src/server-flight.md` (linked in `SUMMARY.md`).

### Notes

kroopt can now produce a complete, self-consistent server flight (a real Ed25519
CertificateVerify that verifies, a real Finished MAC over the real transcript).
Remaining toward live interop (RFC 010/015/026): call this assembler from the
`step`-driven interpreter — feed the real bytes into the transcript in place of the
placeholders in `Core/Handshake.lean` and resolve the core's transcript snapshots
to these real hashes at the crypto seam — then real record encryption, the iotakt
socket transport, and OpenSSL/curl interop.

## [0.27.0-dev] — M27 real server-flight serializers + server-Finished MAC KAT (RFC 8448 §3) — 2026-06-12

Extends the wire serializer (M26) to the **entire** TLS 1.3 server flight and adds
a real server-Finished MAC known-answer test. No change to the verified state
machine: the 87 theorems and existing suites are unchanged.

### Added

- `Kroopt/Parse/Wire.lean`: `certificate` / `certificateEntry` (RFC 8446 §4.4.2)
  and `certificateVerify` (§4.4.3) serializers, alongside the existing
  `serverHello` / `encryptedExtensions` / `finished`.
- `kroopt-wire-test` grew from 11 to **13 checks**, all against RFC 8448 §3:
  - **Framing** — ServerHello, EncryptedExtensions, Certificate, CertificateVerify,
    and Finished each serialize **byte-for-byte** to the trace. RFC 8448 §3 uses an
    RSA cert / RSA-PSS signature (outside the vendored HACL subset), so the
    432-byte cert DER and 128-byte signature are sliced from the vector and fed
    back as opaque inputs — the framing is validated, not the RSA math.
  - **Real server-Finished KAT** — `finished_key = HKDF-Expand-Label(server hs
    traffic, "finished", "", 32)` matches RFC 8448, and `verify_data =
    HMAC(finished_key, Transcript-Hash(CH ‖ SH ‖ EE ‖ Cert ‖ CertVerify))`
    recomputed over the *serialized* flight equals the RFC 8448 server Finished
    `verify_data` (`9b 9b 14 1d …`). Ties serializers + transcript + Finished MAC
    to the authoritative trace.

### Notes

Remaining toward real interop (RFC 010/015/026): sign CertificateVerify with
kroopt's own Ed25519 cert key (RSA stays out of scope); wire the serializers into
the live handshake transcript (replacing the `[snap.id]` placeholders in
`Core/Handshake.lean`); real record encryption; an iotakt socket transport; then
OpenSSL/curl handshake interop.

## [0.26.0-dev] — M26 real handshake wire serializer (RFC 8448 §3 byte-exact) — 2026-06-12

First increment of the structural→real wire work. Adds a real TLS 1.3 handshake
serializer and validates it byte-for-byte against an authoritative vector. No
change to the verified state machine: the 87 theorems and existing suites are
unchanged.

### Added

- `Kroopt/Parse/Wire.lean` — pure, total TLS 1.3 handshake wire serializers (the
  counterpart to the bounds-safe `Reader` parser): big-endian integers,
  length-prefixed vectors, the handshake header, extensions, and `serverHello` /
  `encryptedExtensions` / `finished`. Pure-zone module (now 36 clean); no proof
  obligations (serialization has no over-read risk).
- `kroopt-wire-test` (`Tests/Wire.lean`, 11 checks) validating against the
  **RFC 8448 §3 "Simple 1-RTT Handshake"** trace (vectors transcribed verbatim
  from rfc-editor.org, provenance recorded in-test):
  - `serverHello` serializes **byte-for-byte** to the 90-octet RFC 8448 ServerHello;
  - `SHA-256(ClientHello ‖ serialized ServerHello)` equals the RFC 8448
    CH‥ServerHello transcript hash the key schedule already derives over — the
    real-wire-bytes → real-transcript-hash join;
  - the existing `parseClientHello` accepts the real RFC 8448 ClientHello and
    extracts its x25519 `key_share` (parser is not over-strict on real input).
- `docs/src/wire-format.md` (linked in `SUMMARY.md`) describing the serializer,
  the RFC 8448 validation, and the remaining structural→real steps. CI test loop
  now runs `wire` (18 suites).

### Notes

This is step 1 of several toward real interop. Still pending (RFC 010/015/026):
real Certificate/CertificateVerify/Finished bodies, wiring the serializers into
the live handshake transcript (replacing the `[snap.id]` placeholders in
`Core/Handshake.lean`), real record encryption, an iotakt socket transport, and
OpenSSL/curl handshake interop. The placeholder frames remain in use by the
synthetic handshake until that wiring lands.

## [0.25.0-dev] — M25 RFC lifecycle migration (audit + `proposed/` → `done/`) — 2026-06-12

Governance only; no code, test, or proof change (87 theorems unchanged). Audits the
implementation RFCs against their own acceptance criteria per the RFC lifecycle policy
(RFC 000) and migrates the fully-shipped ones to `rfcs/done/`.

### Changed — RFC states

- Moved **19 RFCs** to `rfcs/done/` with `**Status.** Implemented (0.24.0-dev)`: 001–008,
  011–014, 016–019, 021–023. Each had every acceptance criterion met by shipped
  code/tests/proofs/gates in this repo.
- **11 RFCs remain in `rfcs/proposed/`**, each with one named open deliverable: 009 and
  024 (ASan/UBSan sanitizer CI), 010 (real iotakt socket transport), 015 + 026 (real
  OpenSSL/curl interop + HTTPS E2E), 020 (operator metric/event doc), 025 (benchmarks),
  027 (API-stability commitment), 028 (`SECURITY.md`), 029 (tested examples), 030
  (release runbook).
- Rebuilt `rfcs/README.md` as a state-grouped index (Done with "Shipped in" milestone;
  Proposed with the pending deliverable). RFC 000 invariants checked: folder/Status
  agreement, no duplicate numbers, every index link resolves, every file is listed.
  Cross-references are by RFC number in prose, so no link rewriting was needed.

## [0.24.0-dev] — M24 Ed25519 false-positive closeout (test-governance cleanup) — 2026-06-12

Final cleanup closing the Ed25519 false-positive incident, per architectural review. No
code-path or proof change; build green at 87 theorems. This is test-governance hardening,
not a cryptographic change.

### Changed — changelog hygiene

- Removed all standing "HACL broken / gcc miscompile / Edwards arithmetic defect" language
  from the M19–M22 entries, restructured them with proper version headers, and kept only
  the legitimate deliverables (connection provisioning; SHA-512 KAT hardening) plus a dated
  retraction pointer. The detailed correction remains in `[0.23.0-dev]`.

### Added — vector provenance + postmortem

- Provenance comments on every published crypto KAT (`Tests/Hacl.lean`,
  `Tests/Provision.lean`): source, section, input, and length. Round-trip /
  self-consistency checks are now explicitly labelled and never presented as standards
  conformance.
- `docs/src/postmortem-ed25519.md`: a short postmortem — *the expected value was wrong;
  test-vector provenance is now mandatory* — with the operational rule (verify vector
  provenance byte-for-byte before localizing a defect into the primitive, compiler, or
  FFI). Linked from `SUMMARY.md`.

### Unchanged

- The RFC 8032 KAT, the labelled non-RFC regression vector, and the OpenSSL
  `CertificateVerify` interop (a separate evidence layer) all remain from `[0.23.0-dev]`.
  Trust matrix unchanged: Ed25519 stays ASSUMED (inherited verified). Incident closed.

## [0.23.0-dev] — M23 Ed25519 "defect" retracted as a false positive; corrected + interop-validated — 2026-06-12

Retracts the M19–M22 "non-RFC-8032 Ed25519 defect." It was a **test-vector
provisioning error, not a HACL\*, compiler, or Edwards-arithmetic defect.** HACL\*
Ed25519 is RFC 8032 compliant. No functional protocol change; build green at 87
theorems. The legitimate work from those milestones — connection provisioning and the
SHA-512 KAT hardening — stands and is unaffected.

### Root cause of the false alarm

- The reproduction paired a **non-RFC seed** `9d61b19deffe1f1e92ca4cd2b5e3c0f8a8f1b2c3d4e5f60718293a4b5c6d7e8f`
  with RFC 8032 §7.1 Test 1's **public key** `d75a9801…`, which actually belongs to a
  **different seed** `9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60`.
  HACL\* correctly derived `bcd55c06…` for the seed it was given.
- Every earlier "isolation" step (clamped scalar, base point, `2d`, optimisation,
  uint128, FFI) was internally valid but ran on the wrong seed, so it only ever
  confirmed HACL\*'s self-consistency — never an independently-provisioned RFC vector.

### Corrected (independent verification)

- HACL\* on the **correct** RFC 8032 §7.1 Test 1 seed reproduces the published public
  key `d75a9801…` **and** the signature `e5564300…` byte-for-byte. Confirmed by an
  independent RFC 8032 reference implementation and by OpenSSL.
- `kroopt-provision-test` now asserts the real RFC 8032 KAT (public + signature), a
  labelled non-RFC regression vector, and vector well-formedness/length discipline
  (**20 checks**, was 16). The old "tripwire" asserting non-compliance is removed.

### Added

- `Tests/Vectors/Ed25519Rfc8032.lean` (built via the new `KrooptTestVectors` lib):
  test vectors carry an explicit `source`, algorithm, and length-asserted hex; the RFC
  seed and the local regression seed are kept distinct so they cannot be re-mixed.
- `scripts/ed25519_hacl_cli.c` + `scripts/ed25519-interop.sh`: cross-library
  `CertificateVerify` interop — HACL\* and OpenSSL sign and verify each other's RFC 8446
  §4.4.3 signatures over a shared keypair, and both reject a tampered transcript. (Full
  `s_client`/`curl` handshake interop remains gated behind the pending real-handshake
  work.)

### Trust matrix

- **Unchanged.** Ed25519 stays **ASSUMED (inherited verified)**, with the RFC 8032 KAT
  and OpenSSL interop as **TESTED** evidence. No re-vendor, no compiler workaround, no
  unverified reference binding.

## [0.22.0-dev] — M21 (retracted Ed25519 investigation) — 2026-06-12

Recorded a now-**retracted** Ed25519 investigation. No code change and no functional
deliverable; its conclusions were a false positive caused by a mistyped RFC 8032 test
seed and are fully corrected in 0.23.0-dev. Build green at 87 theorems. Retained as a
dated placeholder for the audit trail — see 0.23.0-dev for the resolution.

## [0.21.0-dev] — M20 crypto KAT hardening (SHA-512 binding + value KATs) — 2026-06-12

### Added / changed — crypto KAT hardening

- Bound `Hacl.sha512` (FFI shim + `opaque`) and added a **SHA-512("abc") FIPS 180-4**
  value KAT; **upgraded SHA-384** from a size-only check to a value KAT. The HACL suite
  (`kroopt-hacl-test`) is now 15 checks. No new theorems (Crypto/Native zone); 87
  unchanged.
- Confirmed the vendored `Hacl_Ed25519.c` and its dependencies are byte-identical
  (`diff` = 0) to the pristine HACL\* 0.4.5 release at tag `ocaml-v0.4.5`.

> A suspected Ed25519 non-compliance investigated under this milestone was later found to
> be a **test-vector provisioning error (false positive)** — HACL\* Ed25519 is RFC 8032
> compliant (see 0.23.0-dev). The KAT hardening above is unaffected and stands.

## [0.20.0-dev] — M19 connection provisioning (`Kroopt.Crypto.Provision`) — 2026-06-12

### Added — connection provisioning (`Kroopt.Crypto.Provision`)

- `genEphemeralX25519 : IO (priv × pub)` draws a fresh ephemeral X25519 key pair from the
  OS CSPRNG (`Hacl.randomBytes`) per connection — no longer injected.
- `CertProvision` (signing seed, opaque DER chain, signature scheme) plus a deterministic
  config lint: `Provision.lint` checks seed length and scheme support and returns the
  *derived* leaf public; `lintAgainstClaimed` additionally rejects a mis-paired claimed
  public (`keyMismatch`), failing closed at load with a typed `ProvisionError`.
  `provisionRealConfig` assembles a `RealCryptoConfig` from linted certificate material
  and a fresh ephemeral pair.

### Changed — tests and CI (17 suites)

- New `kroopt-provision-test` covering ephemeral liveness / well-formedness / X25519
  determinism, the four lint branches, and the certificate-key sign+verify round-trip.
  Added to the verification loop and the CI test matrix. All 17 suites, parser fuzz, and
  the three gates green; theorem count unchanged at 87 (provisioning is `Crypto`-zone, no
  proof obligations).

> A suspected non-RFC-8032 Ed25519 defect reported under this milestone was later found to
> be a **test-vector provisioning error (false positive)** — a non-RFC seed paired with
> RFC 8032 Test 1's public key. HACL\* Ed25519 is RFC 8032 compliant (see 0.23.0-dev); the
> provisioning feature above is unaffected. The provision test's Ed25519 KAT is now a
> positive RFC 8032 KAT and the original "tripwire" was removed.



## [0.19.0-dev] — M18 wire the application-key schedule stage into live `step` — 2026-06-11

Completes the schedule wiring: `Kroopt.Core.step` now drives **both** stages of the
RFC 8446 §7.1 key schedule. After the CertificateVerify signature returns, the
handshake resumes the application-key stage instead of installing application keys
via a placeholder. The full synthetic handshake runs the entire schedule through
`step`.

### Changed — handshake drives the application-key stage (`Kroopt.Core`)

- `onCertVerifySigned` now frames CertificateVerify and the server Finished,
  snapshots the CH..server-Finished transcript, and calls `resumeApplication` to
  start the application-key stage (→ `sentCertificateVerify`) instead of jumping
  straight to `sentServerFinished` with a placeholder epoch install. (The transcript
  is committed only on the success path, so failure paths leave state untouched.)
- New `onApScheduleResult` pumps the application-key stage: each HKDF / install
  result advances the orchestrator and emits the next op, self-looping until
  `complete`, then installs the application epoch and moves to `sentServerFinished`.
- The gating dispatch routes `hkdfSecret` / `keysInstalled` to `onApScheduleResult`
  when in `sentCertificateVerify` (and still to `onHsScheduleResult` when in
  `derivedHandshakeSecrets`). `legalEdge` reroutes
  `requestedCertificateVerifySignature → sentCertificateVerify → sentServerFinished`.

### Changed — proofs (→ 87 theorems)

- New `onApScheduleResult_legal` (self-loops in `sentCertificateVerify` or advances
  to `sentServerFinished`, both legal). `onCertVerifySigned`'s legal / no-emit /
  no-accept proofs re-established for the nested `resumeApplication` match; the
  dispatch no-emit / no-accept proofs extended to the application pump. Global
  action-discipline and `connected_requires_finished_verified` unchanged. Axiom
  audit green; `{propext, Quot.sound}`.

### Changed — tests

- `kroopt-handshake-test` pumps both stages (5+2 then 4+2 schedule results) and
  checks the full seven-phase order through `sentCertificateVerify`; `kroopt-e2e-test`
  drives both via the generic fuel loop. All 16 suites, parser fuzz, and the three
  gates remain green.

### The honest boundary (next)

- The schedule's transcript contexts are still the core's abstract snapshot
  references, not real hash bytes, and the server Finished is synthetic rather than a
  real MAC — the wiring is structural. Real transcript resolution and the real
  Finished MAC are next, then production entropy / certificate provisioning, then a
  real handshake against OpenSSL/curl. See `docs/src/key-schedule-orchestrator.md`.



## [0.18.0-dev] — M17 wire the handshake-key schedule stage into live `step` — 2026-06-11

The verified orchestrator is now invoked by `Kroopt.Core.step`: the handshake
drives the handshake-key stage of the key schedule itself, gated and proved, rather
than installing handshake keys via a placeholder. The full synthetic handshake runs
the stage end-to-end through `step`.

### Added — schedule entry points (`Kroopt.Core.KeyScheduleDriver`)

- `startPostEcdhe` — the handshake-key stage entered post-ECDHE (the ECDHE op was
  already emitted and answered by the existing handshake), recording the shared
  handle and emitting the Early-Secret extraction. `emptyHashSha256` — the RFC 8446
  §7.1 empty-hash constant the schedule uses as Derive-Secret context.

### Changed — handshake drives the stage (`Kroopt.Core`)

- `State` gains `keySched : Option KeyScheduleDriver.State := none`, the active
  orchestrator while the schedule runs.
- `onEcdheDone` now frames ServerHello, installs the handshake epoch, and *starts
  the handshake-key stage* (→ `derivedHandshakeSecrets`) instead of jumping to the
  CertificateVerify request. New `onHsScheduleResult` pumps the stage: each HKDF /
  install result advances the orchestrator and emits the next op, self-looping until
  the `handshakeKeysInstalled` pause, then frames EncryptedExtensions / Certificate
  and requests the CertificateVerify signature (→ `requestedCertificateVerifySignature`).
- `handleCryptoResultCorrelated` now routes `hkdfSecret` / `keysInstalled` results
  to the gating dispatch (previously dropped); the dispatch forwards them to the
  pump when in `derivedHandshakeSecrets`. `legalEdge` reroutes
  `requestedEcdhe → derivedHandshakeSecrets → requestedCertificateVerifySignature`.

### Changed — proofs (→ 86 theorems)

- New `onHsScheduleResult_legal`: the pump self-loops in `derivedHandshakeSecrets`
  or advances to `requestedCertificateVerifySignature`, both legal. `onEcdheDone`'s
  legal/no-emit/no-accept proofs re-established for the new target; the dispatch
  no-emit / no-accept proofs extended to the pump (it emits only `callCrypto` /
  `writeTransport`, never plaintext). The global action-discipline and
  `connected_requires_finished_verified` proofs hold unchanged. Axiom audit green;
  `{propext, Quot.sound}`.

### Changed — tests

- `kroopt-e2e-test` and `kroopt-handshake-test` drive the schedule stage through the
  full handshake (e2e via the generic fuel loop; the direct-driven test pumps the
  seven stage results explicitly). All 16 suites, parser fuzz, and the three gates
  remain green.

### The honest boundary (next)

- The **application-key stage** is not yet driven by `step` (the orchestrator parks
  at `handshakeKeysInstalled`; application keys still use a placeholder) — wiring
  `resumeApplication` as a second pump phase after the server Finished is M18. And
  the schedule's transcript contexts are the core's abstract snapshot references,
  not real hash bytes; the wiring is structural, with real-transcript resolution a
  later milestone. See `docs/src/key-schedule-orchestrator.md`.



## [0.17.0-dev] — M16 two-stage (interleaved) key-schedule orchestrator — 2026-06-11

Corrects the orchestrator's derivation timing to match TLS 1.3. The M15 version
took both transcript hashes up front, which assumes the whole schedule runs at
once; in a real handshake the handshake-traffic keys are installed right after
ServerHello, but the application-traffic keys can only be derived after the server
Finished is committed (their transcript runs CH..server-Finished). The
orchestrator now pauses between the two stages, so it can be driven exactly the way
the live handshake will drive it. Still not invoked by `Kroopt.Core.step` — wiring
is the next milestone — so the existing handshake proofs remain untouched.

### Changed — orchestrator splits into two stages (`Kroopt.Core.KeyScheduleDriver`)

- `start` now takes only the suite, peer share, empty-hash, and the
  CH..ServerHello transcript (the application transcript is not yet known) and runs
  the **handshake-key stage** (ECDHE → … → install handshake keys), then parks at a
  new `handshakeKeysInstalled` phase. A crypto result delivered at the pause is
  held, not consumed.
- New `resumeApplication apTranscript` supplies the CH..server-Finished transcript
  once the server flight is committed and opens the **application-key stage**
  (Derive-Secret(handshake, "derived") → master → application-traffic secrets →
  install application keys → `complete`).

### Changed — proofs (→ 85 theorems)

- `advance_progress` now excludes both non-advancing phases (`complete` and the
  `handshakeKeysInstalled` pause). Added `advance_pause_inert` (the pause emits
  nothing under a crypto result), `resumeApplication_emits_schedule_ops`, and
  `resumeApplication_progress`. The schedule-ops-only and progress disciplines now
  cover both stages. Axiom audit green; `{propext, Quot.sound}`.

### Changed — test drives both stages (`kroopt-scheduledriver-test`, 12 checks)

- Stage 1 runs from `start` to the `handshakeKeysInstalled` pause and checks the
  handshake secrets and installed handshake `write_key`/`write_iv` against RFC 8448
  §3; `resumeApplication` then supplies the CH..server-Finished transcript and stage
  2 runs to `complete`, checking the Master and application-traffic secrets and all
  four installed traffic keys. Both stages run against the real provider.

### The honest boundary (next)

- The orchestrator now matches the handshake's interleaving but is still not
  invoked by `Kroopt.Core.step`. Faithful wiring is now two insertions: pump the
  handshake-key stage after ServerHello is framed, then `resumeApplication` and
  pump the application-key stage after the server Finished is committed. The
  handshake's safety proofs are absence-dominated and the orchestrator is proved to
  emit only schedule ops, so the integration is expected to preserve them. See
  `docs/src/key-schedule-orchestrator.md`.



## [0.16.0-dev] — M15 verified key-schedule orchestrator, driven through the real provider — 2026-06-11

Moves the *sequence* of the TLS 1.3 key schedule — which operation comes next,
with which handle as input — out of test code and into the verified core, as a
pure proved state machine. The orchestrator emits the schedule's ops and threads
the secret handles; the real provider answers them on HACL\*; the whole loop is
validated against the RFC 8448 §3 trace. It is not yet invoked by
`Kroopt.Core.step` — that integration is the next milestone — so the existing 78
theorems are untouched and four new ones are added (82 total).

### Added — key-schedule orchestrator (`Kroopt.Core.KeyScheduleDriver`)

- A pure core state machine: a fifteen-phase linear chain from the ECDHE share to
  the installed application keys. `start` emits the opening ECDHE op; each
  `advance` consumes the awaited result, records the handle it yields, and emits
  the next op (threading handles from each step into the next). Constructs
  `CryptoOp` values only — no crypto, IO, or FFI — so it sits in the verified core
  zone (deps gate: now 35 pure-zone files, clean).

### Added — proofs (`Kroopt.Proofs.KeyScheduleDriver`, +4 theorems → 82)

- `advance_emits_schedule_ops` — the orchestrator emits only ECDHE/HKDF/install
  ops, never AEAD, signature, or randomness ops (the discipline the `step`
  integration will rely on to preserve "no plaintext / no AEAD-open before
  connected").
- `advance_progress` — each accepted result advances the phase by exactly one
  rank, so the schedule is finite and cannot loop.
- `advance_complete_terminal` — `complete` is absorbing.
- `start_emits_schedule_op` — the opening op is itself a schedule op. All within
  `{propext, Quot.sound}`; axiom audit green.

### Added — orchestrator driven through the real provider (`kroopt-scheduledriver-test`, 11 checks)

- The orchestrator emits each op, `mkRealProvider` answers it on real HACL\* crypto
  threading the arena, and the result is fed back to `advance` for the next op,
  until `complete`. Every secret the orchestrator collected (read back from the
  arena by the handle it stored) and the installed handshake key/IV are then
  checked against the RFC 8448 §3 trace (ECDHE shared, Handshake/Master Secrets,
  server handshake/application traffic secrets, installed server-handshake
  `write_key`/`write_iv`, all four traffic-key installs present). Wired into CI.

### The honest boundary (next)

- The orchestrator is not yet invoked by `Kroopt.Core.step`. Wiring it into the
  live handshake — `onEcdheDone` and the gating dispatch kicking off and pumping
  the schedule, threading its state through negotiation — is the next milestone.
  The handshake's safety proofs are absence-dominated and the orchestrator is
  proved to emit only schedule ops, so the integration is expected to preserve
  them, but it does touch those proofs, which is why it is sequenced separately.
  See `docs/src/key-schedule-orchestrator.md`.



## [0.15.0-dev] — M14 enriched crypto interface + real provider driven through RFC 8448 §3 — 2026-06-11

Makes the crypto seam expressive enough to drive a real TLS 1.3 key schedule, and
ships a real `CryptoProvider` that performs a full handshake's cryptography
through the actual `submit` interface — validated against the RFC 8448 §3 trace
operation by operation. The verified core keeps handle opacity, so its 78
theorems hold over the enriched interface unchanged.

### Changed — enriched `CryptoOp` / `CryptoResult` (secret inputs named by handle)

- `hkdfExtract` now carries optional salt and IKM handles; `hkdfExpandLabel` now
  carries the input-secret handle, label, and context; a new `installTrafficKeys`
  op asks the provider to expand a traffic secret into the record key/IV and
  install them for a (direction, epoch). ECDHE now returns `ecdheComplete` (the
  server public share plus a shared-secret handle). The key schedule is now
  expressible as a handle-threaded chain.
- The AEAD operations are deliberately **unchanged** — still keyed by record
  metadata, with the provider resolving the installed key internally. Those are
  the only crypto shapes the proofs destructure, so leaving them fixed kept the
  proof migration empty.

### Unchanged — proofs

- All 78 machine-checked theorems hold over the enriched interface with no
  changes, and the axiom audit is identical: the proofs constrain operation
  *kind* and emission discipline, not secret payloads, and the AEAD shapes were
  preserved. Handle opacity intact (the core still sees only `SecretKeyHandle`s).

### Added — real provider (`Kroopt.Crypto.mkRealProvider`)

- Answers every enriched op with genuine HACL* cryptography, threading the arena:
  X25519 ECDHE, HKDF extract/expand resolving input handles, `installTrafficKeys`
  deriving and recording record keys (and the base secret for the Finished key),
  ChaCha20-Poly1305 record seal/open by installed key, real Ed25519
  CertificateVerify, and Finished-MAC verification. Static secrets it cannot
  itself produce (the server ephemeral X25519 key and the Ed25519 certificate
  key) are injected via `RealCryptoConfig`.
- `SecretArena` gained an installed-traffic-key index and per-epoch base-secret
  record so AEAD and Finished resolve keys without the core naming key bytes.

### Added — RFC 8448 validation through `submit` (`kroopt-realprovider-test`, 17 checks)

- Drives the real provider through the exact RFC 8448 §3 operation sequence via
  `submit` — the same calls the core will emit — and reads every produced secret
  back out of the arena to confirm it matches the published trace (ECDHE shared
  and server share, Early/Handshake/Master Secrets, all traffic secrets), checks
  the install path against the RFC's AES traffic key/IV, round-trips a real
  ChaCha20-Poly1305 record (with tamper rejection), verifies a real Ed25519
  signature, and accepts/rejects Finished MACs. Wired into CI.

### The honest boundary (next)

- The verified core does not yet *emit* this sequence — its handshake still emits
  the simpler op set. Making `Kroopt.Core.step` orchestrate the full schedule
  (threading the handles through negotiation state) is the next step; the
  interface and proofs are now ready, and the fixed AEAD shapes mean it should not
  disturb the safety proofs. Production entropy seeding and certificate
  provisioning through the interpreter remain a scoped follow-up. See
  `docs/src/enriched-crypto-interface.md`.



## [0.14.0-dev] — M13 provider-arena refactor: stateful crypto seam + real TLS 1.3 key schedule (RFC 8448-validated) — 2026-06-11

Makes the crypto seam stateful so real key material can flow, and builds the real
TLS 1.3 key schedule on the native HACL* primitives — validated against the
RFC 8448 §3 trace. The verified core and its 78 theorems are untouched: handle
opacity is preserved, so this adds a stateful trusted seam beside the proofs, it
does not modify them.

### Added — secret arena (`Kroopt.Crypto.SecretArena`)

- A bounded, generation-tagged store mapping `SecretKeyHandle` ids to secret
  bytes, threaded as a pure value (no hidden `IORef`). Handles carry the arena
  generation; a stale handle is rejected after `bumpGeneration`. Capacity-bounded
  (RFC 019); release/zeroize documented honestly as best-effort.

### Changed — stateful provider seam

- `CryptoProvider.submit` now threads the arena:
  `SecretArena → OperationId → CryptoOp → Except CryptoError (SecretArena × CryptoResult)`.
  The interpreter threads it through `RuntimeState.arena`. The fake provider
  allocates real handles from the arena (ECDHE/HKDF), so the existing handshake
  tests now exercise arena allocation end-to-end. All seam-affected suites stay
  green with no behaviour change.

### Added — real key schedule (`Kroopt.Crypto.KeySchedule`) and arena AEAD (`Kroopt.Crypto.Real`)

- The RFC 8446 §7.1 schedule on HACL*: HKDF-Expand-Label, Derive-Secret, the
  early/handshake/master chain, handshake/application traffic secrets, traffic
  keys/IVs, and Finished keys (SHA-256 suite).
- `Kroopt.Crypto.Real` installs derived keys into the arena under handles and
  seals/opens records by handle with the per-record nonce (RFC 8446 §5.3).

### Added — RFC 8448 validation (`kroopt-keyschedule-test`, 20 checks)

- The whole chain matches the RFC 8448 §3 "Simple 1-RTT Handshake" trace exactly
  (empty hash, Early Secret, X25519 from both sides, derived secrets, Handshake
  and Master Secrets, all traffic secrets, traffic keys/IVs, Finished key),
  computed through the native HACL* object code — plus a real-key arena AEAD
  round-trip with tamper rejection and stale-handle behaviour. Wired into CI.

### The honest boundary (next milestone)

- Not yet driven by `Kroopt.Core.step`: the core's `CryptoOp`s are too abstract
  to express a real schedule (no salt/IKM, no label/input handle, no AEAD key
  reference). Wiring it requires enriching those shapes and re-proving the
  operation-id correlation and no-emit/no-accept discipline over them, while
  keeping handle opacity. See `docs/src/key-schedule.md`.



## [0.13.0-dev] — M12 native crypto binding: HACL* primitives callable and KAT-verified through Lean — 2026-06-11

- The vendored HACL* generated C files are
  in fact under the **MIT** license
  (per their retained per-file headers,
  Copyright (c) 2016-2020 INRIA, CMU and
  Microsoft Corporation);
  the kremlin headers are **Apache-2.0**. `NOTICE` states this accurately.
- Added `Kroopt/Native/hacl/LICENSE` reproducing the full MIT text and the
  Apache-2.0 reference next to the vendored sources, a repository-root
  `THIRD-PARTY-NOTICES.md` with upstream/version/subset/no-modifications
  provenance, and a `docs/src/third-party.md` page. The vendored files remain
  verbatim with headers intact, which is what MIT requires.

### Changed — interface-first decoupling (depend on interfaces, not implementations)

- The transport dependency is now an explicit abstract interface,
  `Kroopt.Conn.Transport` (a typeclass: `recv`/`send`/`enableWrite`/
  `disableWrite`/`closeConnection` over a generation-protected `FdKey`). The
  interpreter (`drainOutbound`, `execAction`, `execActions`, `driveEvents`) is
  now **generic over `[Transport τ]`** and names no concrete transport.
  `FakeTransport` is the in-model instance; a real I/O reactor such as iotakt is
  simply another instance of the same interface.
- Removed concrete-project coupling from kroopt's contracts: **jemmet** (which
  depends on kroopt, never the reverse) no longer appears in any code contract —
  it survives only as an example consumer in prose. **iotakt** appears only as an
  example `Transport` instance. The upward plaintext adapter was renamed
  `PlainIotaktConn` → `PlaintextConn` to reflect that it is a plaintext (non-TLS)
  connection, not an iotakt-specific type.
- This reshapes the deferred transport work: rather than "wire kroopt to iotakt,"
  it becomes "provide an iotakt adapter as one `Transport` instance" — the same
  generic interpreter drives it unchanged.

Historical RFC documents under `rfcs/` retain their original iotakt/jemmet
framing as dated design records; the *contracts* (code and the boundary docs) are
now interface-first.



The first **native crypto** milestone (v0.3 binding). Vendors a portable-C subset
of HACL* (Project Everest), builds it through Lake, and calls the verified
primitives from Lean over a thin FFI — proving the real crypto path works
end-to-end, offline and reproducibly, inside the Lean build. This is the
primitives layer; wiring it into the stateful TLS key schedule is scoped as the
next step (a provider-arena refactor), documented honestly below.

### Added — vendored HACL* subset (`Kroopt/Native/hacl/`)

- A portable-C subset of HACL* covering exactly the `TLS_CHACHA20_POLY1305_SHA256`
  suite with X25519 and Ed25519: SHA-256/384, X25519 (public + ECDH with
  low-order rejection), ChaCha20-Poly1305, HKDF/HMAC-SHA256, Ed25519. No vale
  assembly (AES paths omitted) — pure portable C, reproducible on any C11
  compiler. License attribution added to `NOTICE` (Apache-2.0).

### Added — FFI glue and Lean wrappers

- `Kroopt/Native/kroopt_ffi.c`: boring buffer marshalling between Lean
  `ByteArray`s and the HACL* primitives; no crypto logic of its own.
- `Kroopt.Crypto.Hacl`: Lean wrappers — deterministic primitives as pure
  `@[extern]`, `randomBytes` as `IO` (OS CSPRNG via `getrandom`). Lives in the
  trusted `Crypto` zone; never imported by the pure verified core (deps gate
  unchanged: 33 pure-zone files clean).

### Added — build wiring and KATs

- `extern_lib krooptCrypto` in `lakefile.lean` compiles the vendored C + glue
  into `libkroopt_crypto.a`; `kroopt-hacl-test` links it (`--gc-sections` drops
  the unused agile-HMAC SHA-1/Blake2 variants).
- `Tests.Hacl` (14 checks): SHA-256 (FIPS 180-4), X25519 (RFC 7748), HKDF
  (RFC 5869 TC1), HMAC (RFC 4231 TC1), AEAD and Ed25519 round-trips with
  tamper/forgery rejection, CSPRNG length and non-constancy — all run **through
  the FFI** over the real HACL* object code.

### Documentation

- `docs/src/native-crypto.md`: the binding, the primitive map, and the honest
  boundary — why a *pure, handle-returning* `CryptoProvider.submit` cannot thread
  real key material through the key schedule, and what the next-step
  provider-arena refactor must do while preserving handle opacity for the proofs.

### Unchanged

- 78 machine-checked public theorems; all three proof gates green (hygiene,
  deps, axiom audit — no `sorryAx`, axioms within `{propext, Quot.sound,
  Classical.choice}`). The verified core and its proofs are untouched: this
  milestone adds a trusted native seam beside them, it does not modify them.
- The pure Lean core still builds with no C toolchain; only the FFI library and
  its KAT executable require a C compiler.

## [0.12.0-dev] — M11 cross-cutting hardening: resource budgets, scope control, threat model, axiom gate — 2026-06-11

Cross-cutting hardening milestone (RFC 016, 017, 019, 022). Adds the resource-
budget model with proved DoS bounds, deferred-feature scope control, the threat
model, and a third proof gate (axiom audit) wired into CI.

### Added — resource budgets (`Kroopt.Core.Budget`, RFC 019)

- `ResourceLimits` (configured ceilings) and pure charge primitives
  (`chargeHandshakeBytes`, `chargeExtensions`, `chargeProgressStep`,
  `checkRecordSize`, `chargePendingCiphertext`) returning typed
  `ResourceLimitError`.
- `Kroopt.Proofs.Budget` — six theorems: an accepted charge never exceeds its
  ceiling (`*_bounded`), over-limit input is rejected (`*_rejects_over`), and
  charges account exactly. The DoS bound is proved, not asserted.

### Added — proof gates and CI (RFC 022)

- `scripts/check-axioms.sh` — the semantic gate: `#print axioms` for every public
  theorem, asserting no `sorryAx` and axioms within
  `{propext, Quot.sound, Classical.choice}`. Audits 78 public theorems/lemmas.
- `.github/workflows/ci.yml` — runs build, all test suites, the fuzzer, and all
  three gates (hygiene, dependency, axiom) on push and PR.

### Added — scope control + threat model (RFC 016, 017)

- `Tests/Hardening.lean` (`kroopt-hardening-test`) — 12 checks: budget
  accept/reject/bound behaviour, and deferred-feature scope control (a ClientHello
  with no `supported_versions`, only TLS 1.2, or no key_share is refused — no
  silent downgrade, no HRR).
- Docs: `threat-model.md` (adversary + threat→defense map), `resource-budgets.md`,
  `deferred-scope.md`, `proof-gates.md`.

## [0.11.0-dev] — M10 jemmet integration + end-to-end HTTPS acceptance — 2026-06-11

Eleventh implementation milestone (RFC 015), closing the v0.x acceptance target.
jemmet consumes kroopt through one uniform connection abstraction, and a full
HTTPS request is served end-to-end through the modeled stack.

### Added — integration surface (`Kroopt.Conn.Uniform`)

- `PlainConn` — the uniform connection abstraction jemmet depends on
  (`recv`/`send`/`flush`/`close`/`negotiatedProtocol`/`isConnected`). `TlsConn`
  implements it as exactly its public API; `PlainIotaktConn` is the plaintext
  (`:80`) adapter. One jemmet handler path serves both.
- `TlsErrorView` + `redactError` — the typed, redacted failure view jemmet may
  log (category, alert, config generation, SNI *length*); no field for secrets,
  plaintext, or raw attacker bytes by construction.
- `Metrics` — bounded, non-secret operational counters (handshake success/failure,
  alerts, ALPN selections, resource-budget failures).

### Changed

- `TlsConn.recv` is now self-driving: when nothing is buffered it pulls and
  decrypts one record from the transport before retrying, so a single `recv`
  reads the next record off the wire — matching the plaintext adapter and the
  uniform `PlainConn` contract.

### Added — acceptance tests

- `Tests/E2EHttps.lean` (`kroopt-https-test`) — 12 checks: an HTTPS request
  served end-to-end through `TlsConn` (handshake → app-data record → jemmet
  handler → response on the wire); the **same** handler serving a plaintext
  connection; ALPN handoff; plaintext/garbage on the TLS listener never reaching
  the handler as application bytes; no plaintext before `connected`; redacted
  error views; metrics.

### Notes

- No new core theorems: M10 is interop/E2E, classed TESTED. Real iotakt sockets
  and curl/OpenSSL/browser interop are the deferred v0.3 binding — the
  action-mapping is identical, so the real adapter adds no protocol logic.

## [0.10.0-dev] — M9 alerts, close_notify, and terminal policy — 2026-06-11

Tenth implementation milestone (RFC 013). Makes alert mapping and close behaviour
explicit and proved: a single centralized alert mapping, explicit per-mode close
states, truncation distinguished from clean close, and terminal discipline
proved.

### Added — centralized alert mapping (`Kroopt.Core.Alert`, pure)

- `alertForProtocolError`, `alertForParseError`, `alertForCryptoFailure`,
  `alertLevel` — the single deterministic mapping from error class to alert.
  Internal/secret-bearing crypto failures map to no detailed alert; adversarial
  ones map to `bad_record_mac`. Record-layer parse failures now route through this
  mapping rather than hardcoding `decode_error`.

### Changed — explicit per-mode close (RFC 013 §3, §5, §7)

- `step`'s `appClose` distinguishes **graceful** (`closing`/`sentCloseNotify`),
  **fatal** (`failed`/`fatalSent`, emits the alert as the only post-failure
  write), and **abortive** (`closed`/`transportClosed`, no alert). Repeated close
  is idempotent. Transport EOF before close_notify remains a truncation failure,
  never a clean close.

### Added — proofs (`Kroopt.Proofs.Closure`, 7 theorems)

- `failAlert_no_emit`, `failAlert_no_accept`, `failAlert_only_alert_write`
  (the fatal path's only wire effect is its alert), `appClose_no_emit`,
  `alertForParseError_is_fatal`, `alertForParseError_not_closeNotify`,
  `alertForProtocolError_fatal_unless_close`. The three alert-mapping facts use no
  axioms at all. The M0 action-discipline proofs were updated for the refined
  `appClose` and still hold. ~52 total.

### Added — tests

- `Tests/Close.lean` (`kroopt-close-test`) — 16 checks: graceful/fatal/abortive
  close, EOF truncation, inbound close_notify, post-terminal idempotence
  (`appClose`/`appSend`), no buffered plaintext after fatal close, the alert
  mapping, and `TlsConn.close` idempotence through the public API.

## [0.9.0-dev] — M8 SNI/ALPN configuration + server certificate presentation — 2026-06-11

Ninth implementation milestone (RFC 011 / 012). Replaces the hardcoded suite
selection with a real, immutable, validated server-configuration model: an
SNI→endpoint table, ALPN negotiation, and certificate presentation with config
lint — all as pure, deterministic, **proved** functions, then wired into the
live handshake.

### Added — configuration model (`Kroopt.Core.Config`, `Kroopt.Core.Cert`, pure)

- `ServerConfig` / `ValidatedServerConfig` with `validateServerConfig` — a total,
  deterministic validator that stamps a `ConfigGeneration`, rejects ambiguous SNI
  routes, and lints every endpoint's cert/key/suites. Immutable; reload produces a
  new generation (RFC 011 §6).
- `selectEndpoint` — deterministic SNI resolution: exact preferred over wildcard
  (single leftmost label), default fallback, no callbacks (RFC 011 §4, §8).
- `negotiateAlpn` — client/endpoint intersection by policy
  (server-/client-preference, require-overlap).
- `Cert`: `CertificateChainHandle` (opaque DER + minimal leaf metadata),
  `PrivateKeyHandle` (behind a secret handle), `validateEndpointCertKey` (config
  lint), `selectSignatureScheme` (CertificateVerify scheme selection).

### Added — proofs (`Kroopt.Proofs.Config`, 7 theorems, propext-only)

- `negotiateAlpn_offered_and_allowed` — **ALPN safety**: a negotiated protocol is
  always in both the client and endpoint lists; kroopt never selects an unoffered
  protocol (RFC 011 §8).
- `selectEndpoint_none_uses_default`, `validateServerConfig_rejects_ambiguous`,
  `validateServerConfig_preserves_generation`, `selectSignatureScheme_sound`
  (no scheme downgrade), `validateEndpointCertKey_rejects_mismatch`. ~45 total.

### Changed — handshake wiring (additive)

- `NegotiationState` gains `selectedSni` / `selectedAlpn` / `selectedCert`; `State`
  carries an immutable `serverConfig`; `onClientHello` records the SNI/ALPN/cert
  selection. Additive only — all M0–M7 theorems hold unchanged.
- `TlsConn.server` accepts a `ValidatedServerConfig`; `TlsConn.negotiatedAlpn` and
  `selectedCert` accessors added.

### Added — tests

- `Tests/Config.lean` (`kroopt-config-test`) — 17 checks: exact/wildcard SNI,
  default fallback, ALPN intersection by policy and no-overlap, generation
  stamping, ambiguous-config rejection, cert/key lint (compatible/mismatch/empty/
  oversized), and signature-scheme selection.

## [0.8.0-dev] — M7 TlsConn API + non-blocking interpreter — 2026-06-11

Eighth implementation milestone (RFC 010). Adds the runtime layer: the public
`TlsConn` API and the thin imperative interpreter that executes the core's
`OutputAction`s over the transport and crypto provider and feeds results back as
events. The transport is a pure, deterministic fake for this milestone (the real
iotakt binding is a thin deferred adapter, v0.3); the interpreter and API carry
no protocol logic.

### Added — runtime layer (`Kroopt.Conn`)

- `Conn.Transport` — the transport abstraction (the generic non-blocking
  capabilities kroopt requires: `recv`/`send`/`enableWrite`/`disableWrite`/
  `closeConnection`, a generation-protected `FdKey`) and a pure `FakeTransport`
  with scriptable partial writes and EOF. No TLS-specific transport API.
- `Conn.Interpreter` — `execAction` (dispatches on the `OutputAction` variant
  alone; **does not take the core `State`**, so it structurally cannot make a
  protocol decision), `drainOutbound` (partial-write-safe), and the fuel-bounded
  `driveEvents` loop (never spins on `wouldBlock`).
- `Conn.TlsConn` — `server`/`recv`/`send`/`flush`/`close`/`progress`/`metadata`
  with the mandated semantics: `wrote n` = plaintext ownership (not delivery),
  `wouldBlock` consumes zero, `recv` returns authenticated plaintext only after
  `connected`.

### Added — tests, docs

- `Tests/Conn.lean` (`kroopt-conn-test`) — 13 checks: a **full handshake driven
  through the public `TlsConn` API** to `connected`, the write/flush/read
  semantics, partial-write ordering, `wouldBlock`-consumes-zero, progress-budget
  termination, and stale-crypto-result rejection at the runtime boundary.
- `docs/src/tlsconn-interpreter.md`; theorem-inventory note (M7 is interpreter
  *faithfulness*, classed TESTED — the proved guarantees stay in force because the
  interpreter cannot branch on protocol state).

## [0.7.0-dev] — M6 crypto provider, FFI contract, operation-id correlation — 2026-06-11

Seventh implementation milestone (RFC 008 / 009). Adds the crypto provider
trusted boundary and — the verification-first contribution — the **operation-id
correlation guard** on returning crypto results. The native HACL\*/EverCrypt shim
is contracted with its build deferred until HACL\* is vendored (Requirements Open
Question 1); the deterministic fake provider stands in, and the correlation
guarantee holds regardless of provider.

### Added — crypto provider model (`Kroopt.Crypto.Provider`, RFC 008)

- `CryptoCapabilities`, `RequiredCrypto`, `CapabilityError`, and
  `validateCapabilities` — a total, deterministic config-time check that the
  configured suites/groups/signature schemes/hashes are supported and a usable
  random source exists. Capability mismatch is a configuration error, never a
  silent downgrade.
- `CryptoProvider` (synchronous interface) and `fakeProvider` — a deterministic,
  purpose-aware fake satisfying the same interface the real shim will.

### Added — operation-id correlation (the headline)

- `handleCryptoResult` now checks `pendingOps.contains op` before processing a
  result; a stale / duplicate / forged operation id is dropped with no effect.
- `Kroopt.Core.Proofs.stale_crypto_result_rejected` — a non-outstanding op id
  leaves the state unchanged and emits no actions; `stale_crypto_result_no_plaintext`
  is the no-plaintext corollary. Both `propext`-only.
- All M2–M5 safety theorems re-checked over the guarded handler;
  `aead_open_failure_no_plaintext` now carries an explicit "operation outstanding"
  hypothesis (a stale failure is dropped instead).

### Added — native FFI contract (RFC 009), tests, docs

- `Kroopt/Native/kroopt.h` — the C shim contract (one function per primitive /
  secret-handle op, explicit lengths, status codes, documented ownership);
  `kroopt_hacl_shim.c` a documented placeholder pending the HACL\* build.
- `Tests/Crypto.lean` (`kroopt-crypto-test`) — 11 checks: capability validation
  (incl. rejection and no-entropy), the deterministic fake provider, and a
  runtime cross-check of the correlation guard (outstanding processed, stale
  dropped, duplicate is a no-op).
- `docs/src/crypto-ffi-contract.md`; theorem inventory and proof-assumptions
  updated. ~38 theorems total.

## [0.6.0-dev] — M5 live handshake through `step`, fakes, end-to-end — 2026-06-11

Sixth implementation milestone (RFC 014). Wires the M4 handshake transition
functions into the live `step` dispatcher and drives the **full synthetic
handshake end-to-end through `step`** against a fake transport and a
deterministic fake crypto provider. This closes the v0.1 synthetic-core line
(M1–M5): the protocol now runs as it will in production, with only the provider
and sockets faked. Still no real cryptography.

### Added — ClientHello parser (`Kroopt.Parse.Handshake`, RFC 006 §5)

- `parseClientHello` validates a ClientHello on the bounds-safe `Reader`
  primitives (reusing the proved `takeCountedItems`): handshake header, the
  legacy fields, cipher suites, and extensions, requiring TLS 1.3 in
  `supported_versions`, an X25519 `key_share`, an acceptable cipher suite, and no
  duplicate extensions. Returns a `WireBound` carrying the exact consumed bytes.

### Changed — handshake wired into the live handlers

- A plaintext handshake record now routes through `handshakeOnPlaintextRecord`
  (ClientHello in `start`, client Finished in `sentServerFinished`); a gating
  crypto result routes through `handshakeOnGatingResult` (ECDHE / signature /
  verify). `step` and its proof keep their shape — dispatch lives in the record
  handlers (`Kroopt.Core.RecordPath`).

### Added — proofs (the headline: safety survives the live handshake)

- `handshakeOnPlaintextRecord_no_emit` / `_no_accept` / `_no_aeadOpen`,
  `handshakeOnGatingResult_no_emit` / `_no_accept`, and the per-transition
  no-emit/no-accept/no-aeadOpen family.
- Every M2/M3 safety theorem re-checked unchanged over the live handshake:
  `no_plaintext_emit_unless_connected`, `accept_plaintext_only_connected`,
  `buffered_plaintext_authenticated`, `aead_open_failure_no_plaintext`,
  `aeadOpen_uses_read_keys`, `successful_open_increments_read_seq` — all still
  `sorry`/`axiom`-free (`propext`, some `Quot.sound`). ~36 theorems total.

### Added — fakes, end-to-end harness, fuzz

- `Tests/EndToEnd.lean` (`kroopt-e2e-test`) — a deterministic fake crypto
  provider and fake transport, a driver loop over `step`, and 12 checks: a real
  ClientHello byte sequence driven to `connected` with completion reported and no
  plaintext emitted, plus negative traces (malformed ClientHello, early
  application data, bad client Finished) that fail cleanly with no plaintext.
- `Tests/Fuzz.lean` extended with ClientHello and record-reassembly targets
  (RFC 014 §7); buffers widened to 0–255 bytes.

### Added — docs

- `docs/src/end-to-end.md`; expanded theorem inventory and proof-assumptions
  (incl. a note on the fake provider and the synthetic `verifyFailed →
  bad_record_mac` alert-code detail).

## [0.5.0-dev] — M4 handshake state model + transcript binding — 2026-06-11

Fifth implementation milestone (RFC 006 + RFC 007). Adds the TLS 1.3 **server**
handshake state machine (no HelloRetryRequest) and the **exact-wire-byte**
transcript, with the legal-transition and exact-byte-binding proofs. Still no
real crypto and no sockets: the synthetic handshake drives the transition
functions directly with fake crypto results.

### Added — transcript model (`Kroopt.Core.Transcript`, RFC 007)

- `WireBound` binds a parsed value to its exact consumed bytes; `appendParsed`
  commits those bytes, never a reconstruction.
- `HandshakeMessageType`, `TranscriptEvent`/`TranscriptEventMeta`,
  `appendFramed`/`appendParsed`, `snapshot`, `TranscriptSnapshot`,
  `TranscriptBoundInput` + `makeCertificateVerifyInput`/`makeFinishedInput`.

### Added — handshake state model (`Kroopt.Core.Handshake`, RFC 006)

- `ValidClientHello`; `legalEdge` (the allowed phase graph); `installEpoch`;
  `hsFail`; and the five transition functions `onClientHello`, `onEcdheDone`,
  `onCertVerifySigned`, `onClientFinishedBytes`, `onClientFinishedVerified`,
  driving `start → … → connected` via gating crypto actions.

### Added — proofs (`Kroopt.Proofs.Handshake`, `Kroopt.Proofs.Transcript`)

- `onClientHello_legal` … `onClientFinishedVerified_legal` — every transition
  moves along a `legalEdge` (no skipped/out-of-order phases).
- `connected_requires_finished_verified` — `connected` is reachable only from
  `requestedClientFinishedVerify` and only when the client Finished verified.
- `appendFramed_binds_exact_bytes`, `appendParsed_uses_wire_bytes` — exact-byte
  binding; `appendFramed_preserves_order`, `appendFramed_increments_count` —
  ordering; `snapshot_eventCount`, `snapshot_then_append_is_before` — the
  snapshot-before-append discipline for Finished/CertificateVerify.
- `takeCountedItems_bounds` — the fuel-bounded item combinator is bounds-safe
  (composition lemma deferred from M1, now discharged).
- All machine-checked, no `sorry`/`axiom`/`unsafe`; `#print axioms` shows only
  `propext` (two on no axioms).

### Added — tests, docs

- `Tests/Handshake.lean` (`kroopt-handshake-test`) — 10 checks: the full
  synthetic handshake to `connected`, the legal phase order, completion
  reporting, the seven-message transcript in order, exact ClientHello byte
  binding, and negative traces (out-of-order ECDHE, bad Finished, duplicate
  ClientHello).
- `docs/src/handshake.md`, `docs/src/transcript.md`; expanded theorem inventory
  and proof-assumptions.

### Changed

- `Core.Transcript` rewritten from the M0 stub to the full RFC 007 model. The
  gates now cover the handshake and transcript modules and their proofs (25
  pure-zone files).

## [0.4.0-dev] — M3 nonce, sequence, epoch, key separation — 2026-06-11

Fourth implementation milestone (RFC 005). Proves the record layer's
cryptographic discipline — the part where a kroopt bug, not a HACL\* bug, would
destroy security: AEAD nonce reuse, sequence wrap, or read/write/epoch key
confusion. Built over the M2 record path; still no real crypto and no sockets.

### Added — nonce / key-epoch model (`Kroopt.Core.Nonce`)

- `KeyEpochId` — a non-secret key-epoch identity (conn, direction, epoch,
  generation) for correlating nonces, proofs, and logs without secret bytes.
- `RecordNonce` / `deriveNonce` — the nonce modeled as the public IV-base
  identity plus the sequence value (the data the uniqueness argument needs).
- `seqBytesBE`, `paddedSeqBytes`, `nonceBytes` — the concrete
  `iv_base XOR left_pad(seq)` byte realization for the interpreter and KATs.

### Added — proofs (`Kroopt.Proofs.Nonces`, `Kroopt.Proofs.KeySeparation`)

- `SeqNo.next_some_succ` / `next_none_overflow` — increment is exactly `+1`;
  `none` only at the `UInt64` ceiling (no wrapped value is produced).
- `successful_seal_increments_write_seq` / `successful_open_increments_read_seq`
  — an accepted seal/open advances that direction's sequence by exactly one.
- `no_crypto_on_write_seq_overflow` — **no silent wrap**: at the ceiling a send
  requests no crypto and fails.
- `nonce_unique_within_epoch` — distinct sequences derive distinct nonces for a
  fixed IV base (depends on no axioms at all).
- `aeadSeal_uses_write_keys` / `aeadOpen_uses_read_keys` — directional and epoch
  key separation: seal ops carry write/application metadata, open ops carry
  read/application metadata.
- All machine-checked, no `sorry`/`axiom`/`unsafe`; `#print axioms` shows only
  `propext` (one theorem none, one also `Quot.sound`).

### Added — tests, docs

- `Tests/Nonce.lean` (`kroopt-nonce-test`) — 12 checks: sequence increment and
  ceiling overflow, nonce uniqueness (modeled and concrete bytes), the
  direction/epoch metadata on emitted seal/open ops, and stale/early
  crypto-result behaviour; all passing.
- `docs/src/nonce-sequence.md`; expanded theorem inventory and proof-assumptions.

### Changed

- `Core.Record` gained the `SeqNo.next` increment/overflow lemmas. The gates now
  cover the nonce model and its proofs (22 pure-zone files).

## [0.3.0-dev] — M2 TLS 1.3 record model — 2026-06-11

Third implementation milestone (RFC 004). Adds the TLS 1.3 record model — the
outer/inner content-type distinction, the read/write record paths as core
actions, and the *no unauthenticated plaintext* proof — on top of the M0 core and
M1 parser. Still no real crypto and no sockets: AEAD seal/open are *requested* by
the core and their results fed back as events, exactly as the interpreter will
later drive them.

### Added — record model (`Kroopt.Core.Record`, `Kroopt.Parse.Record`)

- `ContentType` with wire-byte `toByte`/`ofByte` (unknown bytes decode to the
  explicit `invalid`, never a real type).
- `BoundedBytes max` — a byte string whose length bound is a field, so an
  over-length record body is unconstructable; record size limits are enforced
  *by construction*.
- `TLSPlaintext` / `TLSInnerPlaintext` / `TLSCiphertext` — the three record
  shapes keeping the outer `application_data` vs real inner content type
  distinct.
- Record framing: `takeRecordHeader` (rejects oversize length at the header,
  before allocation), `tryTakeRecord` (returns "need more" until a full record is
  buffered — reassembly), `parseInnerPlaintext` (strip padding, read inner type;
  safe list ops, no unchecked indexing), and `classifyCcs` (accept only the
  `0x01` compatibility CCS).

### Added — record path (`Kroopt.Core.RecordPath`, wired into `step`)

- Inbound: reassemble → frame → request `aeadOpen` → on success validate inner
  type and buffer application content → deliver via the existing connected
  `recv` path; auth failure is fatal with no plaintext.
- Outbound: connected `send` fragments to ≤ 2¹⁴, requests `aeadSeal`, and
  acknowledges ownership with `acceptPlaintextBytes`.
- Sequence numbers advance per direction with overflow checked before use; the
  core requests crypto and never calls it.

### Added — proofs (`Kroopt.Proofs.RecordPath`)

- `buffered_plaintext_authenticated` / `buffered_plaintext_provenance` — **no
  unauthenticated plaintext**: buffered application plaintext arises only from a
  successful `aeadOpened` result in `connected` state.
- `aead_open_failure_no_plaintext` — open failure emits no plaintext and is
  terminal.
- Handler no-emit / no-accept lemmas; the M0 `no_plaintext_emit_unless_connected`
  re-proved over the extended `step`, plus `accept_plaintext_only_connected`.
- All machine-checked, no `sorry`/`axiom`/`unsafe`; `#print axioms` shows only
  `propext` (some also `Quot.sound`).

### Added — tests, docs

- `Tests/Record.lean` (`kroopt-record-test`) — 19 checks: header parse, oversize
  reject, reassembly split points, inner-type validation, CCS accept/reject, and
  fake AEAD-open success (buffers plaintext) vs failure (buffers none, goes
  terminal); all passing.
- `docs/src/record-model.md`; expanded theorem inventory and proof-assumptions.

### Changed

- `Core.State` gained record buffers (`inboundCiphertext`, `outboundCiphertext`)
  and an op-id counter; `step`'s M0 placeholder arms became real record
  transitions. The proof-hygiene and dependency gates now cover the record
  modules (19 pure-zone files).

## [0.2.0-dev] — M1 bounds-safe parser foundation — 2026-06-11

Second implementation milestone (RFC 003). Adds the pure parsing/framing
foundation with bounds-safety proofs, on top of the M0 core. Still no crypto and
no sockets. (Per the roadmap, the released `v0.1` "synthetic handshake and record
core" line is reached once M1–M5 all land; these `0.x.0-dev` tags are internal
per-milestone snapshots.)

### Added — parser foundation (`Kroopt.Parse`)

- `Reader` — a byte cursor carrying its own `offset ≤ input.size` proof, so
  out-of-bounds readers are unconstructable (*bounds-safety by construction*).
- `UInt24` — a dedicated 24-bit wrapper for handshake lengths (RFC 003 §9.2), in
  place of an unchecked `UInt32` cast.
- Primitives — `takeBytes`, `takeU8`/`U16`/`U24`/`U32` (big-endian), `takeLen`
  (8/16/24-bit prefixes), `remaining`, `atEnd`, `expectEnd`.
- `takeVectorBytes` — length-prefixed byte vector with a `maxLen` budget check
  plus the remaining-input check; the framer the record/extension parsers build
  on.
- `takeCountedItems` — fuel-bounded item combinator (no unbounded recursion over
  attacker-controlled counts).
- `ParseError` — internal typed parse errors with positions/sizes but no raw
  bytes, plus `toPublic` projecting onto the redacted `Kroopt.ParseError`.

### Added — proofs (`Kroopt.Parse.Proofs`, module `Kroopt.Proofs.ParserBounds`)

- `reader_in_bounds`, `takeBytes_bounds`/`_mono`, `takeU8`/`U16`/`U24`/`U32_bounds`,
  `takeLen_bounds`, `takeVectorBytes_bounds`, and the umbrella `parser_bounds_safe`
  — every successful read advances the cursor monotonically, stays within the
  buffer, and preserves the buffer. All machine-checked, no `sorry`/`axiom`/
  `unsafe`; verified via `#print axioms` to depend only on `propext` (some also
  `Quot.sound`).

### Added — tests, fuzzing, docs

- `Tests/Parse.lean` (`kroopt-parse-test`) — 18 unit + negative checks (decode,
  truncation, over-budget length, trailing bytes, fuel exhaustion); all passing.
- `Tests/Fuzz.lean` (`kroopt-parse-fuzz`) — deterministic bounded smoke fuzzer
  asserting the reader invariant across pseudo-random buffers (50k iterations,
  zero violations).
- `docs/src/parser.md` and an expanded theorem inventory / proof-assumptions
  register.

### Changed

- The proof-hygiene and module-dependency gates now cover `Kroopt/Parse`.
- `Kroopt.Parse` depends only on `Kroopt.Error`, keeping it a pure sibling of the
  core (enforced by `scripts/check-deps.sh`).

## [0.1.0-dev] — M0 verified-core skeleton — 2026-06-11

First implementation milestone (RFC 001, 002, 022, 024). Establishes the
pure-core/interpreter architecture with machine-checked safety properties, ahead
of any real crypto or sockets.

### Added — verified core (`Kroopt.Core`)

- `Error` — typed, redaction-safe error and alert taxonomy (all enums; no
  secret-bearing fields), with a coarse `TlsError.category` for logging.
- `Id` — `ConnId` (value + generation), `OperationId`, `ConfigGeneration`.
- `Common` — `CloseMode`, `TimeoutKind`.
- `CipherSuite` — `HashAlgorithm`, `CipherSuite` (+ bound hash), `NamedGroup`,
  `SignatureScheme`.
- `Record` — `Direction`, `Epoch`, `SeqNo` with an overflow-checked `next` that
  returns `none` at the maximum (no silent wrap; RFC 005 §7.2), `EpochState`.
- `Crypto` — crypto-as-action shapes: non-printable `SecretKeyHandle`,
  `RecordCryptoMeta`, `CryptoOpKind`, `CryptoOp`/`CryptoResult`, and the
  pending-op correlation table. Secret-bearing types derive no
  `Repr`/`BEq`/`Hashable` (RFC 018 §3.5).
- `Transcript` — `TranscriptDigestHandle`, `TranscriptState` (minimal M0 shape).
- `State` — `HandshakeState` (16 phases incl. `failed`), `CloseState`,
  `NegotiationState`, `BudgetState`, and the single authoritative `State` with
  `initial` and a redacted diagnostic summary. `State` derives no `Repr`
  (transiently holds authenticated plaintext).
- `Event` / `Action` — `InputEvent` and `OutputAction`, with the classifier
  predicates the proofs quantify over (`isPlaintextEmit`, etc.).
- `Step` — the `step : State → InputEvent → Except TlsError (State × List
  OutputAction)` transition function (M0 shape: correct discipline, no real TLS
  logic yet).

### Added — proofs (`Kroopt.Proofs`)

- `step_deterministic`, `terminal_absorbing`, `terminal_no_error`,
  `no_plaintext_emit_unless_connected` (*no early plaintext*), and
  `no_plaintext_after_terminal`. All machine-checked, no `sorry`/`axiom`/
  `unsafe`; verified via `#print axioms` to depend only on `propext`.

### Added — tests, gates, docs

- `Tests/Model.lean` — deterministic model test driving `step` directly (9
  checks, all passing).
- `scripts/check-hygiene.sh` — RFC 022 proof-hygiene gate (no forbidden
  constructs in the strict zones).
- `scripts/check-deps.sh` — RFC 022 module-dependency gate (verified core may
  not import the interpreter, crypto provider, native shim, or iotakt).
- `docs/src/` — mdbook docs: introduction, boundary, theorem inventory, and the
  proof-assumptions register.

### Project

- Incorporated the ROADMAP and full RFC set (managed under the lifecycle policy)
  into the repository. RFCs remain `Proposed`; their M0 slices are implemented
  but the RFCs are not yet fully realized, so they stay in `rfcs/proposed/`.
- Lake package builds standalone on a clean Lean install — no mathlib, no C
  toolchain, no network reactor (RFC 024 `core` profile).
