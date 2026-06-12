# RFC 033 — Real-Client Handshake Processing

**Project.** kroopt  
**Status.** Proposed  
**Type.** Implementation RFC  
**Target milestone.** M36  
**Depends on.** RFC 004 (record model), RFC 006 (handshake state model), RFC 007 (transcript), RFC 003 (parser)  
**Touches.** `Kroopt/Core/RecordPath.lean`, `Kroopt/Core/Handshake.lean`, `Kroopt/Parse/Handshake.lean`, `Kroopt/Parse/Extensions.lean`, new `Kroopt/Core/HandshakeReasm.lean`, `Kroopt/Proofs/{RecordPath,NoUnauthPlaintext,ParserBounds}.lean`  
**Canonical source.** kroopt fixed requirements §9, §10, §17.5; RFC 8446 §4, §5; architect reviews of 2026-06-12 (deep review blockers 2/5; RFC review RFC 033 amendments).  


> **Status note — partial (0.37.0-dev, M36 part 1).** The receive-side blocker
> (deep-review blocker #2) is fixed: the core now opens the protected client
> Finished **in-core** under the handshake epoch (`Core/RecordPath.lean`,
> `readMeta` is epoch-aware) and routes the opened inner message through the
> handshake model to `verifyFinished` → `connected`, never buffering application
> plaintext. A related epoch-modeling correction landed: the read epoch stays
> `handshake` through `sentServerFinished` and switches to `application` only when
> the client Finished verifies (`Core/Handshake.lean`). Proofs re-established:
> `buffered_plaintext_authenticated` (+ four `pendingPlainOut`-preservation
> lemmas), `KeySeparation.aeadOpen_uses_read_keys` (now `meta.epoch =
> s.readEpoch.epoch`), and `Nonces.successful_open_increments_read_seq`.
> **Still pending in this RFC:** the bounded handshake-message reassembler
> (`Core/HandshakeReasm.lean`, for fragmented/coalesced records), ClientHello
> strictness, and explicit CCS policy (see the part-2 note below for the updated
> list). This RFC stays in `proposed/` until those land. The current fix handles a
> client Finished that arrives complete in one record.
>
> **Status note — partial (0.38.0-dev, M36 part 2).** `signature_algorithms`
> overlap-selection landed (`Parse/Handshake.lean`): the ClientHello parser now reads
> the client's offered schemes (extension 0x000d) and selects Ed25519 only when the
> client actually offers it (`sigSchemeOfU16`/`selectSigScheme`, mirroring
> `selectSuite`), rather than presenting a hardcoded Ed25519 CertificateVerify the
> client never offered. A cert-authenticating server with no acceptable overlap — no
> `signature_algorithms`, or only RSA/ECDSA — is now rejected (RFC 8446 §4.2.3). This
> makes the constrained profile's interop limit explicit and honest: it rejects the
> RSA/ECDSA-only RFC 8448 §3 ClientHello (`Tests/Wire.lean` asserts this), since
> kroopt presents Ed25519 only.
> **Still pending in this RFC:** the bounded handshake-message reassembler
> (`Core/HandshakeReasm.lean`, for fragmented/coalesced records — deferred pending a
> clean `ByteArray.extract` size bound) and explicit `change_cipher_spec` policy. This
> RFC stays in `proposed/` until those land.
>
> **Status note — partial (0.40.0-dev, M36 part 4).** ClientHello strictness landed
> (`Parse/Handshake.lean`, RFC 8446 §4.1.2): the parser now rejects a ClientHello whose
> `legacy_version` is not 0x0303, and one whose `legacy_compression_methods` is anything
> other than the single null byte (compression is forbidden in TLS 1.3). Both fields
> were previously parsed and ignored.
>
> **Status note — partial (0.39.0-dev, M36 part 3).** Cipher-suite negotiation is now
> bound to suite *capability* (`Parse/Handshake.lean`): `suiteOfU16` maps only
> `TLS_CHACHA20_POLY1305_SHA256` (0x1303) — the suite the vendored provider can perform
> — so `selectSuite` will not negotiate an AES suite kroopt cannot complete, even when
> the client lists it first. This fixed a latent inconsistency the test harness had
> masked: the core was selecting AES-128-GCM from a `13 01 13 03` ClientHello while the
> ServerHello and key schedule used ChaCha20. The map widens when a real AES provider
> lands (RFC 035). With this, all three negotiated parameters — suite, group, and
> signature scheme — are selected from the client's offers and bound to what the server
> can actually present/perform.

---

## 1. Summary

Three things prevent kroopt from correctly processing a real external client's handshake,
independent of the correspondence work (RFC 031/032):

1. **Protected handshake records before `connected` are silently dropped.** In
   `Core/RecordPath.lean`, an outer `application_data` record is AEAD-opened only when
   `s.handshake.isConnected`; otherwise the handler returns `.ok (s, [])` (deferred to
   "M4"). A real client's encrypted Finished cannot drive `sentServerFinished → connected`;
   the test only works by opening it outside the core and feeding plaintext back.
2. **Handshake-message fragmentation/coalescing is not handled.** TLS handshake messages
   carry their own 4-byte header and may be fragmented across records or coalesced within
   one record. A path that only accepts a full message in one record is not robust for
   internet-facing input.
3. **ClientHello parsing is bounds-safe but not semantically strict** (ignores
   `signature_algorithms`/`supported_groups`, selects Ed25519 unconditionally, does not
   enforce key_share length or null-only compression, captures ALPN/SNI raw).

This RFC closes all three so the core can execute a TLS 1.3 server handshake driven by a
real client. It is core + proof work and a hard prerequisite for RFC 015/026 live interop.

## 2. Handshake-message reassembly (new `Core/HandshakeReasm.lean`)

Record reassembly from TCP bytes is **not** sufficient. Add a bounded handshake-message
assembler that delivers a complete message body to the parser only after the 4-byte
handshake-length field is satisfied, for **both**:

- plaintext ClientHello-era handshake records;
- protected handshake-epoch records (especially the client Finished).

Rules:

- a single record may carry multiple coalesced messages; deliver each in order;
- a message may span multiple records; buffer until complete;
- oversized (beyond the handshake-bytes budget, RFC 037), incomplete-beyond-budget, or
  out-of-order fragments fail deterministically with a typed alert;
- the assembler buffer is bounded and charged against the handshake-bytes budget.

## 3. Protected handshake records before `connected`

Replace the silent-drop branch with explicit routing:

```text
outer application_data, phase before connected:
  -> AEAD-open with read / handshake-epoch keys (core emits callCrypto aeadOpen)
  -> on the correlated aeadOpened result: parse TLSInnerPlaintext, strip padding
       inner handshake -> feed bytes to the handshake-message assembler (§2);
                          a completed message in sentServerFinished must be Finished
       inner alert      -> close / fail per level (warning vs fatal, §5)
       inner application_data before connected -> fatal unexpected_message
  -> on AEAD-open failure: fatal bad_record_mac, no plaintext (invariant preserved)
```

Constraints: use read **handshake-epoch** keys/IV and the read sequence (not the
application `readMeta`); route handshake-epoch `aeadOpened` results to the handshake
model, **never** to `pendingPlainOut`; sequence advances once per opened record. The
single application-plaintext-emitting site stays `connected`-gated, preserving the
no-early / no-unauthenticated-plaintext theorems.

## 4. ClientHello negotiation: select an overlap, do not reject on breadth

A real ClientHello offers many suites/groups/schemes kroopt does not support. kroopt must
**not** reject merely because unsupported values are offered. Instead:

- **ignore** unsupported offered cipher suites, groups, and signature schemes;
- **select** a supported overlap (the constrained profile: `TLS_CHACHA20_POLY1305_SHA256`,
  X25519, Ed25519);
- **reject** only if there is no acceptable overlap, or if an offered value that is
  *selected* is malformed.

Strictness details (in `Parse/Handshake.lean`, `Parse/Extensions.lean`, negotiation in
`Core/Handshake.lean`):

- handshake `length` checked against consumed body; extensions vector fully consumed,
  trailing bytes rejected; duplicate extensions rejected;
- `legacy_version` tolerated as the TLS 1.2 legacy value but **must not** drive version
  selection;
- `supported_versions` must be present and include TLS 1.3; honor the downgrade sentinel;
  reject ambiguous combinations;
- `legacy_session_id` echo policy defined for ServerHello (echo the client's id);
- `supported_groups` + `key_share`: select from offered, provider-supported groups;
  require a 32-byte X25519 `key_exchange`; no acceptable initial key share → clean failure
  (no HRR);
- `signature_algorithms`: require overlap with provider schemes; select from the
  negotiated set (not an unconditional Ed25519 assumption);
- legacy compression restricted to exactly null compression;
- SNI parsed to a validated value: maximum length, ASCII/IDNA policy, redacted/hashed in
  logs (no raw attacker blob);
- ALPN protocol IDs length-bounded and matched against the configured offers;
- explicit extension allow / ignore / reject table (in an appendix to this RFC);
- cipher-suite selection rejects suites outside `realCapabilities` (RFC 034) only after
  failing to find an overlap.

## 5. Inner-content and CCS policy before `connected`

- inner application data before `connected` → fatal `unexpected_message`;
- inner handshake message other than Finished while in `sentServerFinished` → fatal
  `unexpected_message`;
- inner post-handshake auth / KeyUpdate (unsupported) → fatal `unexpected_message`;
- multiple inner messages after reassembly → processed in order, each validated;
- inbound alert: parse level/description; **warning** vs **fatal** handled distinctly.

**CCS compatibility (explicit).** Real clients may send a TLS 1.3 middlebox-compatibility
ChangeCipherSpec. kroopt:

- accepts-and-ignores CCS only in the RFC-permitted boundary locations;
- does **not** contribute it to the transcript;
- does **not** advance handshake state;
- does **not** advance any AEAD sequence number;
- rejects CCS anywhere else (fatal `unexpected_message`).

## 6. Proof impact

- `Proofs/RecordPath.lean`: cover the new handshake-epoch open routing while preserving
  "no handler emits `emitPlaintext`" and "`pendingPlainOut` filled only by a `connected`
  application-inner-type `aeadOpened`."
- `Proofs/NoUnauthPlaintext.lean`: confirm the only path to application plaintext remains
  the authenticated, `connected`-gated one; the new handshake-record path cannot reach it.
- `Proofs/ParserBounds.lean`: extend bounds-safety to the assembler and the stricter
  extension/key_share parsing.

## 7. Captured-ClientHello replay tests (bridge to live interop)

Before any live socket, collect one or more real `openssl s_client` / `curl` ClientHello
byte captures (constrained: `-ciphersuites TLS_CHACHA20_POLY1305_SHA256 -groups X25519
-sigalgs ed25519`, plus a default broad ClientHello) and feed them through the pure/fake
path. Assert: the broad ClientHello negotiates the constrained overlap (not rejected for
breadth); the assembler handles fragmented and coalesced captures; malformed/rejected
captures map to deterministic alerts. Store sanitized captures as fixtures (coordinated
with RFC 036).

## 8. Acceptance criteria

1. The core advances `sentServerFinished → connected` on a real protected client Finished
   record, with no out-of-core workaround.
2. The handshake-message assembler handles fragmented and coalesced messages on both the
   plaintext and protected paths; over-budget/out-of-order fragments fail deterministically.
3. ClientHello negotiation selects the constrained overlap from a broad real ClientHello
   and is **not** rejected for offering unsupported values; the §4 strictness items and
   the extension table are enforced; the §17.5 negatives cover each case.
4. CCS, inner application-data-before-connected, non-Finished inner handshake, and
   warning/fatal alerts are handled by explicit deterministic policy (§5).
5. Captured-ClientHello replay tests (§7) pass through the pure/fake path.
6. `Proofs/{RecordPath,NoUnauthPlaintext,ParserBounds}.lean` build clean; axiom whitelist
   preserved; parser fuzz stays clean.

## 9. Risks

- **Touching the safety proofs.** The no-unauthenticated-plaintext invariant must be
  proven not to gain a second plaintext path; route handshake-epoch results to the
  handshake model only.
- **Input-space growth.** Honoring real client extensions + reassembly broadens input;
  pair every acceptance with a negative test and keep the fuzz target current (extend it
  to the assembler).
