# Handshake wire format (real serialization)

TLS 1.3 binds the handshake transcript to the **exact bytes on the wire**: the
key schedule derives traffic secrets, the CertificateVerify signature, and the
Finished MACs over `Transcript-Hash(messages)`, where `messages` is the verbatim
concatenation of the serialized handshake messages (RFC 8446 §4.4.1, §7.1). A TLS
peer only accepts our handshake if our serialized bytes hash to the same value its
own do.

Until now the synthetic handshake used **structural placeholder frames** — e.g.
`frameServerHello` stood in for a real ServerHello — which is fine for the
deterministic state-machine tests (both sides agree on the placeholder) but cannot
interoperate with a real peer. `Kroopt/Parse/Wire.lean` is the first piece of the
real wire layer: a pure, total serializer that is the counterpart to the
bounds-safe `Reader` parser.

## What it produces

`Wire` builds exact TLS 1.3 bytes from small, composable encoders — big-endian
integers, length-prefixed vectors (`u8Len`/`u16Len`/`u24Len`), the handshake
header (`type ‖ 24-bit length ‖ body`), and extensions. On top of those, the
whole server flight:

- `serverHello random sessionIdEcho cipherSuite group keyShare selectedVersion`
  — `legacy_version = 0x0303`, `key_share` + `supported_versions`, compression 0;
- `encryptedExtensions exts`;
- `certificate context entries` + `certificateEntry certData extensions` — the
  Certificate message (empty request context, a certificate_list of entries);
- `certificateVerify scheme signature`;
- `finished verifyData`.

Serialization has no over-read risk (it only appends), so these carry no proof
obligations; correctness is established by byte-exact tests against an
authoritative vector, in keeping with the trust matrix (wire interop is TESTED).

## Validation against RFC 8448 §3

`Tests.Wire` (`kroopt-wire-test`, 13 checks) validates against the **RFC 8448 §3
"Simple 1-RTT Handshake"** trace (vectors transcribed verbatim from
rfc-editor.org, provenance recorded in the test). Two kinds of check:

**Framing.** Every server-flight message — ServerHello, EncryptedExtensions,
Certificate, CertificateVerify, Finished — serializes **byte-for-byte** to the RFC
8448 bytes. RFC 8448 §3 uses an RSA certificate and an RSA-PSS CertificateVerify,
which the vendored HACL subset cannot produce; their crypto blobs (the 432-byte
cert DER, the 128-byte signature) are sliced from the RFC vector and fed back as
opaque inputs, so these checks validate the *framing*, not the RSA math.

**Real crypto KATs** (SHA-256 / HMAC are available):

1. `SHA-256(ClientHello ‖ serialized ServerHello)` equals the RFC 8448
   CH‥ServerHello transcript hash the key schedule derives handshake traffic
   secrets over.
2. The **server Finished MAC**, recomputed over the *serialized* flight, matches
   the trace: `finished_key = HKDF-Expand-Label(server_hs_traffic, "finished", "",
   32)` equals RFC 8448's value, and `verify_data = HMAC(finished_key,
   Transcript-Hash(CH ‖ SH ‖ EE ‖ Cert ‖ CertVerify))` equals the RFC 8448 server
   Finished `verify_data` (`9b 9b 14 1d …`). This ties the wire serializers, the
   transcript over real bytes, and the real Finished computation together against
   the authoritative vector.
3. The existing `parseClientHello` accepts the real RFC 8448 ClientHello and
   extracts its x25519 `key_share` — confirming the parser is not over-strict.

## Where this sits in the structural→real plan

The full server flight now serializes to exact RFC 8448 §3 wire bytes, and the
real server Finished MAC over that flight matches the trace. The remaining steps to
a real handshake, in order:

1. **Real signing** — produce the CertificateVerify signature with kroopt's own
   Ed25519 certificate key (the signed-content construction is already
   cross-validated against OpenSSL in `scripts/ed25519-interop.sh`); RSA stays out
   of scope (no `Hacl_Rsa` vendored).
2. **Wire the serializers into the live handshake transcript**, replacing the
   placeholder frames so the `step`-driven handshake commits real bytes and the
   provider hashes the real committed prefix (removing the `[snap.id]`
   placeholders at the CertificateVerify / application-secret / client-Finished
   sites in `Core/Handshake.lean`).
3. **Real records** (encrypt the server flight) and a **real iotakt socket
   transport** (RFC 010), then **OpenSSL/curl interop** (RFC 015 / 026).

The verified state machine is untouched by this increment: the 94 theorems and the
existing suites are unchanged; `Wire` is a pure-zone module plus one test.
