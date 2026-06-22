# Certificate presentation and interop validation

> **Capability note.** For the authoritative current capability and security posture, see
> [current security state](../verification/current-security-state.md). Specific suite / group /
> signature mentions or "pending"/"deferred" wording on this page may predate the current capability
> matrix and are superseded there.


kroopt presents a server certificate as opaque DER (RFC 012): the verified core
holds an abstract `CertificateChainHandle`, never the bytes, and the interpreter
supplies the DER. The live handshake presents a **real, OpenSSL-parseable Ed25519
X.509 certificate** instead of a placeholder.

## The certificate

`scripts/gen-test-cert.sh` builds a self-signed Ed25519 certificate whose subject
public key is kroopt's certificate key — the RFC 8032 §7.1 Test 1 key that also
signs the CertificateVerify — by wrapping the raw seed as an RFC 8410 PKCS#8 key and
issuing a 100-year `CN=kroopt.test` cert with a matching `subjectAltName`. The
351-byte DER is embedded as `certDer` in `Tests/RealFixtures.lean`, so the
Certificate message in the live flight carries a certificate a real client can parse
and whose leaf key matches the CertificateVerify signature.

The live-handshake test confirms the Certificate message presents this real cert
(`0x30 0x82 …`, embedded at the expected offset) and that the handshake still reaches
`connected` with it.

## OpenSSL cross-validation

`scripts/ed25519-interop.sh` step 5 ties the certificate to the signature in the
OpenSSL-validated path, mirroring what a real peer does:

1. OpenSSL parses kroopt's certificate;
2. the leaf public key extracted from the certificate equals kroopt's signing key
   (the HACL Ed25519 public key for the cert seed);
3. OpenSSL verifies a kroopt-produced (HACL) CertificateVerify signature under that
   extracted leaf key.

So a client that extracts the key from kroopt's Certificate message would accept
kroopt's CertificateVerify. The earlier steps validate the HACL ↔ OpenSSL signing
path in both directions and tamper rejection.

## Operational certificate lint

Certificate **path validation** (anchors, revocation, peer name) is a client-role / mTLS concern and is
out of scope for the server profile — a TLS server *presents* a chain, it does not validate one. But a
misconfigured chain can still make clients fail even when the CertificateVerify signature is
cryptographically correct, so kroopt offers an **operator safety lint** at config validation: warnings,
not WebPKI validation. The lint surface (deterministic, local, no network):

- **leaf key ↔ private key match** — the leaf public key equals kroopt's signing key (enforced today; a
  mismatch is a hard config error, not a warning);
- **signature-scheme compatibility** — the leaf key type supports an advertised, presentable scheme;
- **chain order** — leaf first, then intermediates in issuing order;
- **chain size bound** — the presented chain stays within `maxCertChainBytes`;
- **expiry window** — `notBefore`/`notAfter` warnings when a caller supplies a time (no hidden clock);
- **SAN/CN** — a warning when configured hostnames do not appear in the leaf's SAN.

These are operator aids to catch deployment mistakes early; none of them is, or is described as,
certificate *validation*. (Review MEDIUM-3.)

## Scope

This provisions and validates the certificate kroopt presents. A full `openssl s_client` / `curl`
handshake against a running kroopt server is **live and tested** (see
[current security state](../verification/current-security-state.md)). Certificate path *validation*
(the client role / mTLS) remains out of scope per the requirements: a TLS server presents a chain, it
does not validate one.
