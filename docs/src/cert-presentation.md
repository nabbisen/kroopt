# Certificate presentation and interop validation

kroopt presents a server certificate as opaque DER (RFC 012): the verified core
holds an abstract `CertificateChainHandle`, never the bytes, and the interpreter
supplies the DER. The live handshake presents a **real, OpenSSL-parseable Ed25519
X.509 certificate** instead of a placeholder.

## The certificate

`scripts/gen-test-cert.sh` builds a self-signed Ed25519 certificate whose subject
public key is kroopt's certificate key — the RFC 8032 §7.1 Test 1 key that also
signs the CertificateVerify — by wrapping the raw seed as an RFC 8410 PKCS#8 key and
issuing a 100-year `CN=kroopt.test` cert with a matching `subjectAltName`. The
351-byte DER is embedded as `certDer` in `Tests/RealHandshake.lean`, so the
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

## Scope

This provisions and validates the certificate kroopt presents; it is not yet a full
`openssl s_client` / `curl` handshake against a running kroopt server, which is gated
behind productionizing the interpreter and the iotakt socket transport (RFC 010).
Certificate path *validation* (the client role / mTLS) remains out of scope per the
requirements: a TLS server presents a chain, it does not validate one.
