# Real server-flight assembly

The verified core models the TLS 1.3 server flight with **abstract handles**: it
holds a `SecretKeyHandle` for the certificate key, a `CertificateChainHandle` for
the chain, snapshot ids for the transcript, and operation ids for crypto results.
It deliberately never holds the certificate DER, the server random, the
CertificateVerify signature, or the Finished MAC — those are real bytes that come
from the crypto provider and the configuration. Keeping them out of the core is
what lets the protocol logic stay pure and proven.

`Kroopt/Conn/Flight.lean` is the interpreter-side counterpart that supplies those
real bytes. It composes the M26/M27 wire serializers (`Kroopt.Parse.Wire`) with the
HACL primitives to produce the exact wire bytes of the server flight and the
transcript hashes that bind them (RFC 8446 §4.4):

- `transcriptHash messages` — `SHA-256` of the verbatim concatenation;
- `serverHelloMessage` / `serverFinishedMessage` — real ServerHello / Finished;
- `certVerifyContent` / `signCertVerify` / `verifyCertVerify` /
  `certificateVerifyMessage` — the real CertificateVerify path.

It lives in the impure `Conn` zone because it calls FFI crypto; the verified core
imports none of it.

## Real Ed25519 CertificateVerify

RFC 8448 §3 uses an RSA certificate, which the vendored HACL subset cannot
produce, so M27 validated the CertificateVerify *framing* with the RSA signature
treated as opaque. This module produces a **real** CertificateVerify with kroopt's
own Ed25519 certificate key:

1. `certVerifyContent` builds the RFC 8446 §4.4.3 signed content — 64 space octets,
   the context string `"TLS 1.3, server CertificateVerify"`, a `0x00` separator,
   then the handshake transcript hash (130 octets for SHA-256). This is the exact
   construction cross-validated against OpenSSL in `scripts/ed25519-interop.sh`
   (HACL signs / OpenSSL verifies, and vice versa), so the result is
   wire-interoperable.
2. `signCertVerify` signs it with HACL Ed25519; `certificateVerifyMessage` wraps
   the signature as a real CertificateVerify message (scheme `0x0807`).

`Tests.Flight` (`kroopt-flight-test`, 14 checks) anchors the key to the RFC 8032
§7.1 KAT, exercises the sign/verify round-trip, and confirms verification rejects
a wrong transcript hash and a wrong key. The ServerHello assembly and the server
`finished_key` / Finished MAC are anchored to RFC 8448 §3.

## Where this sits

With M26/M27 (byte-exact serializers + server-Finished KAT) and this assembler,
kroopt can now produce a complete, cryptographically self-consistent server flight
— a real Ed25519 CertificateVerify that verifies, and a real Finished MAC over the
real transcript. The remaining step to a live handshake is to call this assembler
from the `step`-driven interpreter: feed the real bytes into the transcript in
place of the structural placeholders in `Core/Handshake.lean`, and resolve the
core's transcript snapshots to these real hashes at the crypto seam. After that:
real record encryption, the iotakt socket transport (RFC 010), and OpenSSL/curl
interop (RFC 015 / 026).

The verified state machine is untouched by this increment: the 87 theorems and the
existing suites are unchanged; `Flight` is an impure-zone module plus one test.

## Typed handshake-output actions (RFC 032, in progress)

Historically the core emitted a four-byte structural *placeholder* for each server-flight
message (`#[8,0,0,0]` for EncryptedExtensions, and so on) and the byte-accurate message
was assembled outside the proof line by recognizing that first byte. RFC 032 replaces this
with typed actions that carry protocol *facts*: the core decides what (selected suite,
group, ALPN, certificate handle, epoch, ordering), and a single pure serializer realizes
the bytes, so no path branches on a message's first byte.

The first message converted is EncryptedExtensions. The core emits
`OutputAction.writeHandshake conn (.encryptedExtensions <selected ALPN>)`; the production
interpreter and the test drivers all call `Core.serializeHandshakeOut` to turn that typed
plan into wire bytes. The action-discipline classifiers treat `writeHandshake` as neither a
plaintext emit nor an ordinary transport write, so the safety lemmas carry over unchanged.

The remaining messages convert as their inputs become available to the core:
CertificateVerify next (the signature is already a core result, paired with the two-stage
request/write rule), then Certificate (the interpreter owns the DER behind the chain
handle), and finally ServerHello and Finished once the server share and Finished MAC are
surfaced as core crypto results. The transcript-over-real-handshake-bytes restatement and
the CI gate forbidding placeholder/first-byte dispatch land once every message is typed.
