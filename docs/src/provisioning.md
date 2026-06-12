# Connection provisioning and a discovered Ed25519 defect (M19)

The real provider (`mkRealProvider`) closes over a `RealCryptoConfig` whose
ephemeral X25519 private key and certificate key pair were, until M19, injected by
tests. Production wiring needs two things the test path stubbed: a **fresh ephemeral
key pair per connection**, drawn from the OS CSPRNG and never reused; and
**certificate material loaded from configuration**, with the leaf public key
*derived* from the private seed rather than trusted from input.

`Kroopt.Crypto.Provision` supplies both. It is interpreter-side glue — the `Crypto`
zone, not the verified core — so it may draw entropy (`IO`) and call the HACL FFI.
It performs no DNS, no network access, no system-trust-store reads, and no peer
validation: it derives and presents a server certificate, exactly the server-role
scope.

## What it provides

`genEphemeralX25519 : IO (priv × pub)` draws 32 bytes from the OS CSPRNG
(`Hacl.randomBytes`) and derives the X25519 public — one fresh pair per connection.
`CertProvision` carries the Ed25519 signing seed, the opaque DER chain, and the
presented signature scheme. `Provision.lint` is a deterministic config lint (no
network, no clock): it checks the seed length and that the scheme is supported, and
returns the *derived* leaf public; `lintAgainstClaimed` additionally requires a
caller-supplied public key to equal the derived one, catching a mis-paired
certificate and key at load (RFC 011) before any connection is accepted.
`provisionRealConfig` ties these together: lint the certificate material, draw a
fresh ephemeral pair, and assemble a `RealCryptoConfig`, failing closed with a typed
`ProvisionError` if the material does not lint.

The provisioning test (`kroopt-provision-test`, 16 checks) confirms ephemeral
liveness (independent draws differ), well-formedness, X25519 determinism, the lint
branches (length, scheme, fail-closed, mismatch detection), and that a provisioned
certificate key signs and verifies against its derived public.

## A discovered defect: the vendored Ed25519 is not RFC 8032 compliant

Provisioning's KATs surfaced a real, previously-hidden defect. Strengthening the
crypto known-answer tests — the HACL suite only *size-checked* SHA-384, never
value-checked it — showed that **SHA-384 matches FIPS 180-4** and **X25519 matches
RFC 7748**, but the vendored HACL **Ed25519** does not match RFC 8032:

* `Hacl_Ed25519_sign(seed, "")` returns `6b66cdc2…`, not the RFC 8032 §7.1 Test 1
  signature `e5564300…`;
* `Hacl_Ed25519_secret_to_public(seed)` returns `bcd55c06…`, not the RFC 8032
  public `d75a9801…`.

The sign and derive paths are *self-consistent* — a signature produced by the
vendored Ed25519 verifies against the vendored public key — which is why every prior
round-trip test passed and the defect went unnoticed. But the outputs are
non-standard, so a real TLS 1.3 peer (OpenSSL, curl, a browser) would reject a
`CertificateVerify` signed this way. This is an **interop blocker**.

The defect is localised to the Ed25519 implementation: SHA-384/512 (its hash) and
Curve25519 (the shared field) are both confirmed correct here, and the FFI shim's
argument order matches the HACL header (`secret_to_public(pub, priv)`,
`sign(sig, priv, len, msg)`). The fault is in the vendored `Hacl_Ed25519.c` itself —
most likely a version mismatch with the rest of the vendored tree. Re-vendoring it
blind (the exact upstream HACL revision is not recorded) risks breaking the build,
so M19 *surfaces and tracks* the defect rather than fixing it under time pressure:

* the provisioning test ends with a **tripwire** asserting the current
  non-compliance, which flips to a failure the moment Ed25519 is corrected, forcing
  whoever fixes it to replace the tripwire with a real RFC 8032 KAT; and
* fixing the Ed25519 binding is recorded as the **top item** before real interop in
  the ROADMAP.

This is the verification-first method working as intended: a KAT that should have
existed from the start (SHA-384 by value, Ed25519 against RFC 8032) converted a
silent interop bug into a tracked, test-guarded finding.
