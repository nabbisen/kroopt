# Handshake state model

kroopt implements the TLS 1.3 **server** handshake without HelloRetryRequest
(RFC 006). A client must present an acceptable X25519 `key_share` in its initial
ClientHello, or the handshake fails cleanly — there is no HRR round trip. This is
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
(`selectSuite` picks the first offered suite kroopt supports; `findX25519Share`
takes the x25519 share among the offered key shares). Signature scheme now does too:
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
