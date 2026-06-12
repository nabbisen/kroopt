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
header (`type ‖ 24-bit length ‖ body`), and extensions. On top of those:

- `serverHello random sessionIdEcho cipherSuite group keyShare selectedVersion`
  emits a ServerHello with `legacy_version = 0x0303`, the `key_share` and
  `supported_versions` extensions, and `legacy_compression_method = 0`.
- `encryptedExtensions`, `finished` — the simple-handshake server-flight tail.

Serialization has no over-read risk (it only appends), so these carry no proof
obligations; correctness is established by byte-exact tests against an
authoritative vector, in keeping with the trust matrix (wire interop is TESTED).

## Validation against RFC 8448 §3

`Tests.Wire` (`kroopt-wire-test`, 11 checks) validates against the **RFC 8448 §3
"Simple 1-RTT Handshake"** trace (vectors transcribed verbatim from
rfc-editor.org, with provenance recorded in the test):

1. `serverHello` of the RFC 8448 negotiated parameters serializes
   **byte-for-byte** to the trace's 90-octet ServerHello.
2. The decisive loop: `SHA-256(ClientHello ‖ serialized ServerHello)` equals the
   RFC 8448 **CH‥ServerHello transcript hash** (`86 0c 06 ed … ca d8`) — the same
   hash the trace derives `tls13 c hs traffic` / `s hs traffic` over, and the same
   hash the already-validated key schedule (`Tests.KeySchedule`,
   `Tests.RealProvider`) consumes. Real wire bytes in, real transcript hash out.
3. The existing `parseClientHello` accepts the real RFC 8448 ClientHello and
   extracts its x25519 `key_share` — confirming the parser is not over-strict
   against real-world ClientHellos.

## Where this sits in the structural→real plan

This closes the wire-bytes/transcript-hash join at the CH‥SH point. The remaining
steps to a real handshake, in order:

1. **Real server-flight bodies** — real Certificate (DER) and a CertificateVerify
   built over `Transcript-Hash(CH‥Certificate)`, plus a Finished over
   `Transcript-Hash(CH‥CertificateVerify)`.
2. **Wire the serializers into the live handshake transcript**, replacing the
   placeholder frames so the `step`-driven handshake commits real bytes and the
   provider hashes the real committed prefix (removing the `[snap.id]`
   placeholders at the CertificateVerify / application-secret / client-Finished
   sites in `Core/Handshake.lean`).
3. **Real records** (encrypt the server flight) and a **real iotakt socket
   transport** (RFC 010), then **OpenSSL/curl interop** (RFC 015 / 026).

The verified state machine is untouched by this increment: the 87 theorems and the
existing suites are unchanged; `Wire` is a new pure-zone module plus one test.
