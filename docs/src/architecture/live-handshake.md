# Live step-driven real handshake

M26–M28 built the wire serializers, the server-Finished KAT, and the server-flight
assembler. M29 connects them to the **verified core state machine**: it drives the
real `Kroopt.Core.step` through a server handshake against the **real** crypto
provider (real HACL X25519 / HKDF / Ed25519 / HMAC) with a **real transcript**
assembled by `Kroopt.Conn.Flight`, and runs it to `connected`.

`Tests/RealHandshake.lean` (`kroopt-realhandshake-test`) is a driver in the spirit
of the end-to-end fake-crypto driver, but with two substitutions at the seam the
core leaves abstract:

- **Real crypto.** Each `callCrypto` action is run against `RealProvider.submit`,
  threading a real `SecretArena`, instead of a fixed fake result.
- **Real transcript.** The core models transcript binding with abstract snapshots
  and commits a one-byte structural placeholder to the wire for each server-flight
  message. The driver recognises each placeholder by its message type
  (ServerHello = 2, EncryptedExtensions = 8, Certificate = 11, CertificateVerify =
  15, Finished = 20), assembles the **real** message bytes via `Flight`/`Wire`,
  appends them to a real transcript, and snapshots the bound hash. At the crypto
  ops it substitutes those real hashes: the handshake/application traffic secrets
  get the real `Transcript-Hash(CH‥SH)` / `Transcript-Hash(CH‥ServerFinished)`, the
  CertificateVerify gets the real signed content over `Transcript-Hash(CH‥Cert)`,
  and the Finished verification gets the real `Transcript-Hash(CH‥ServerFinished)`.

The driver captures the server ECDHE share from the ECDHE result, the
CertificateVerify signature from the signing result, and the server handshake-
traffic secret from the arena (to compute the Finished MAC the core models as a
placeholder).

## What it checks

The live core, on real crypto over real wire bytes, runs without error to
`sentServerFinished` and emits a complete real server flight (ServerHello,
EncryptedExtensions, Certificate, CertificateVerify, Finished — in that order, the
first being the real assembled ServerHello). The central end-to-end claim: the
handshake produces a **valid Ed25519 CertificateVerify over the real transcript** —
it verifies against the certificate public key and is rejected against a wrong
transcript hash. The server hs-traffic secret is captured and the Finished framing
is correct.

## Scope and honesty

This is a **self-consistent** handshake, not a replay of RFC 8448 §3. kroopt's
certificate is Ed25519, and the vendored HACL subset has no RSA or P-256, so the
ClientHello here offers `ed25519` in `signature_algorithms`; RFC 8448's ClientHello
offers only RSA/ECDSA, which kroopt cannot sign, so its transcript hashes cannot be
matched here. The certificate entry is an opaque placeholder DER (real certificate
provisioning is separate); it does not affect the CertificateVerify, which signs
the transcript hash.

The verified state machine is unchanged by this milestone: the 87 theorems and the
36 pure-zone files are untouched. `RealHandshake` is a driver in `Tests/` plus the
`Flight` module; the substitution lives entirely in the impure driver, exactly
where the production interpreter will host it.

## Reaching `connected`

The driver continues past the server flight: it captures the client handshake-
traffic secret as it is derived, computes a real client Finished —
`HMAC(finished_key(client_hs_traffic), Transcript-Hash(CH‥ServerFinished))` — and
feeds it back; the core verifies it and reaches `connected`. A negative control
confirms a wrong client Finished is rejected and `connected` is *not* reached.

A correctness fix enabled this: a TLS 1.3 server verifies the client's Finished
with the **read (client)** handshake-traffic secret, so the secret arena now keys
base secrets by `(direction, epoch)` (matching how installed record keys are keyed)
and `RealProvider.verifyFinished` looks up the read-direction handshake secret and
extracts the verify_data from the Finished message body. This lives in the Crypto
zone; the verified core and its 87 theorems are untouched.

## Remaining toward live interop

Real record encryption of the flight (the messages are assembled in the clear here,
not yet sealed with the handshake/application AEAD keys), the iotakt socket
transport (RFC 010), and OpenSSL/curl interop (RFC 015 / 026).
