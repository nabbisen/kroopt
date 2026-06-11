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
