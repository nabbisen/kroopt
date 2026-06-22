# Handshake state model

kroopt implements the TLS 1.3 **server** handshake without HelloRetryRequest
(RFC 006). A client must present, in its initial ClientHello, a usable `key_share`
for a group the listener's policy allows — x25519 or secp256r1 (RFC 039) — or the
handshake fails cleanly; there is no HRR round trip. This is
deliberate: HRR changes the transcript rules and multiplies proof and interop
surface, so the first release line ships a strict, small, server-side path.

## Phases and legal edges

`HandshakeState` carries the full TLS 1.3 server vocabulary (`start`,
`requestedEcdhe`, …, `requestedClientFinishedVerify`, `connected`, plus
`closing` / `closed` / `failed`). The allowed phase changes are captured by
`legalEdge`: a phase may stay put (record I/O, recv, flush leave it unchanged),
fail cleanly from any live phase, begin a close, or advance one step along the
server flight. Crucially, `connected` is reachable **only** from
`requestedClientFinishedVerify`.

Every transition function is proved to move along a `legalEdge`
(`onClientHello_legal` … `onClientFinishedVerified_legal`), and
`connected_requires_finished_verified` shows the single edge into `connected`
requires the client Finished to have verified. Since application data is
permitted only in `connected`, no application data flows before the client
Finished is checked.

## Transitions

The handshake is a sequence of small transition functions (RFC 006 §10):

- `onClientHello` (`start → requestedEcdhe`) — record the negotiated parameters,
  commit the exact ClientHello bytes to the transcript, request the ECDHE shared
  secret;
- `onEcdheDone` (`requestedEcdhe → requestedCertificateVerifySignature`) —
  install handshake keys, frame ServerHello / EncryptedExtensions / Certificate
  into the transcript, request the CertificateVerify signature over the snapshot;
- `onCertVerifySigned` (`… → sentServerFinished`) — commit CertificateVerify and
  the server Finished, install application keys, emit the flight tail;
- `onClientFinishedBytes` (`… → requestedClientFinishedVerify`) — snapshot the
  transcript *before* the client Finished and request its MAC verification;
- `onClientFinishedVerified` (`… → connected`) — on success, commit the client
  Finished and report completion; on failure, `decrypt_error`.

The operations whose **results gate** a phase change — ECDHE, the
CertificateVerify signature, the client-Finished verification — are real crypto
actions whose results re-enter as events. The key-schedule HKDF derivations are
modeled as synchronous key installation in this state-model milestone; the
provider-backed HKDF round-trips arrive with the crypto FFI (M6). Wiring the
transition functions into the live `step` event loop against the fake
transport/provider is M5.

## Signature-scheme overlap selection (RFC 033)

The ClientHello parser selects the negotiated parameters from the client's offers
rather than assuming them. Cipher suite and group already work this way
(`selectSuite` picks the first offered suite kroopt supports; group selection is
covered in **Named-group selection** below). Signature scheme now does too:
`offeredSigSchemes` reads the client's `signature_algorithms` (extension 0x000d) and
`selectSigScheme` picks the first that kroopt can *present* — in the constrained
profile, Ed25519 (0x0807) only. The server no longer hardcodes an Ed25519
CertificateVerify a client never offered.

A cert-authenticating server with no acceptable overlap is rejected: a ClientHello
with no `signature_algorithms`, or one offering only RSA/ECDSA, fails to parse
(RFC 8446 §4.2.3). This makes the constrained profile's interop boundary explicit —
kroopt cannot serve a client that does not offer Ed25519 (for example the RSA/ECDSA
RFC 8448 §3 ClientHello), and says so by rejecting rather than presenting a
certificate the client cannot verify.

### Suite selection is bound to capability, not breadth

The same overlap discipline applies to the cipher suite. `suiteOfU16` maps only the
suites kroopt can *perform* — in the constrained profile, `TLS_CHACHA20_POLY1305_SHA256`
(0x1303) — so `selectSuite` picks ChaCha20-Poly1305 when the client offers it and
rejects when it does not, regardless of which suites the client lists first. A client
that offers AES-128-GCM ahead of ChaCha20 still negotiates ChaCha20; a client that
offers only AES is rejected (kroopt would otherwise commit to a suite the vendored
provider cannot perform). All three negotiated parameters — suite, group, and signature
scheme — are thus selected from the client's offers and bound to what the server can
present or perform. The suite map widens when a real AES provider is introduced
(RFC 035).

### Named-group selection (RFC 039)

The negotiated ECDHE group is **not** inferred from parser reachability. The canonical
rule: *a negotiated group is the intersection of provider capability, endpoint policy,
and the client's `key_share`, ordered by a fixed server preference.* The three layers are
distinct: the **provider** declares which groups it can perform (validated against each
endpoint's policy at config load); each **endpoint** declares its `namedGroups` policy
(default `[x25519, secp256r1]`, x25519 preferred; a hardened listener sets `[x25519]`);
and the **client** offers `key_share` entries. The parser surfaces the client's recognized
offers (`findOfferedKeyShares`), and the verified core's total `selectGroup` walks the
server preference `[x25519, secp256r1]` and takes the first group that is both
endpoint-allowed and client-offered. No overlap is a clean `handshake_failure` (no HRR);
the core never falls back to an unauthorized group. This is proven, not conventional:
`selectGroup_authorized` shows any selected group is both allowed and offered, and
`ecdhe_op_matches_selected_group` / `no_disallowed_group_crypto_op` show the ECDHE crypto
op matches the recorded group and a disallowed group reaches neither selection nor a
crypto op.

`supported_groups`/`key_share` consistency (RFC 8446 §4.2.8) is enforced at parse: if the
ClientHello carries a present `supported_groups`, every offered `key_share` group must
appear in it (a contradiction is rejected as `illegal_parameter`); when `supported_groups`
is absent, `key_share` is authoritative for this constrained no-HRR profile. P-256
`key_share` validation is layered: the parser checks wire shape (65 bytes, `0x04` prefix)
and the provider performs on-curve point validation (HACL `Hacl_P256_ecp256dh_r`,
fail-closed), with any provider rejection a fatal handshake failure and no fabricated
shared secret.

**Alert mapping** is deterministic and non-leaking (RFC 013): no acceptable `key_share`
under no-HRR and a provider point rejection map to `handshake_failure`; a duplicate
`key_share` group, a group omitted from `supported_groups`, and a malformed P-256 point map
to `illegal_parameter`. A "selected-but-disallowed" group is a non-event — the gate makes it
unselectable, so there is no runtime state to alert on.

**Tracing** is redaction-safe (RFC 039 §4.9 / RFC 018): the opt-in `NegotiationTrace` carries
endpoint groups, client offered group ids, the selected group, and a rejection category — and
is bytes-free by construction (it has no `ByteArray` field), so raw `key_share` bytes and the
ClientHello blob can never appear in a trace.

### ClientHello strictness

Two TLS 1.3 invariants on legacy fields are enforced rather than ignored (RFC 8446
§4.1.2). `legacy_version` must be exactly 0x0303 — a TLS 1.3 client carries its real
version preference in `supported_versions`, and the legacy field is fixed by the
specification. `legacy_compression_methods` must be exactly the single null byte:
compression is forbidden in TLS 1.3, so any other value is rejected. Both fields were
previously parsed for length but their values were not checked.
