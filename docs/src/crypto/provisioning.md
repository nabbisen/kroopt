# Connection provisioning and Ed25519 vector discipline

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

The provisioning test (`kroopt-provision-test`, 20 checks) confirms ephemeral
liveness (independent draws differ), well-formedness, X25519 determinism, the lint
branches (length, scheme, fail-closed, mismatch detection), that a provisioned
certificate key signs and verifies against its derived public, and the Ed25519 /
SHA known-answer tests below.

## Ed25519 is RFC 8032 compliant — and a corrected false alarm

HACL\* Ed25519 reproduces the **RFC 8032 §7.1 Test 1** vectors byte-for-byte. For the
Test 1 secret seed `9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60`,
`secret_to_public` yields `d75a9801…` and `sign("")` yields `e5564300…` — the published
values. This is checked in `kroopt-provision-test` and cross-validated two further ways:
an independent RFC 8032 reference implementation agrees, and `scripts/ed25519-interop.sh`
shows HACL\* and **OpenSSL** signing and verifying each other's RFC 8446 §4.4.3
`CertificateVerify` signatures over a shared keypair (and both rejecting a tampered
transcript).

### What the earlier "defect" actually was

Milestones M19–M22 reported a non-RFC-8032 Ed25519 defect. **That was a false alarm — a
test-vector provisioning error, not a HACL\*, compiler, or Edwards-arithmetic defect.**
Architectural review found that the reproduction used a *non-RFC* seed
(`9d61…7e8f`) paired with RFC Test 1's *public key* (`d75a9801…`), which belongs to a
*different* seed (`9d61…7f60`). HACL\* was correct the whole time: it derived the right
public key (`bcd55c06…`) for the seed it was actually given.

Every "isolation" check from the earlier investigation was internally valid but operated
on the wrong seed, so it only ever confirmed HACL\*'s self-consistency — never an
independently-provisioned RFC vector. The corrected, independent verification:

| Seed | Ed25519 public (HACL\* = RFC reference = OpenSSL) |
|---|---|
| `9d61…7f60` (RFC 8032 Test 1) | `d75a9801…` ✔ matches the published RFC public |
| `9d61…7e8f` (non-RFC, local) | `bcd55c06…` ✔ correct for that seed |

No HACL re-vendor, no compiler workaround, and no trust-matrix downgrade are warranted.
Ed25519 remains **ASSUMED (inherited verified)** in the trust matrix, with the RFC 8032
KAT and the OpenSSL `CertificateVerify` interop as **TESTED** evidence.

### Vector-source discipline (the lesson encoded)

The root cause was trusting a remembered/published hex string over a verified library.
The rule we now follow: *when a verified or externally trusted primitive disagrees with an
expected value, first verify the vector provenance byte-for-byte before localizing the
defect into the primitive, compiler, or FFI.* To prevent recurrence:

* test vectors live in `Tests/Vectors/Ed25519Rfc8032.lean` with an explicit `source`
  label, algorithm, and hex fields;
* `wellFormed` pins component byte-lengths (seed 32, public 32, signature 64), so a
  mistyped or line-wrapped vector **fails** rather than silently matching a borrowed one;
* `seedsDistinct` guards specifically against re-mixing the RFC seed with the local
  regression seed;
* the local `9d61…7e8f` vector is retained only as a clearly-labelled non-RFC regression
  vector.

The corrected process is: **published-vector provenance → byte-length checks → independent
oracle → HACL KAT → FFI KAT → TLS `CertificateVerify` interop** — never skipping the first
step.

## Interop scope

`scripts/ed25519-interop.sh` validates the `CertificateVerify` signature *construction*
cross-library (HACL\* ↔ OpenSSL). A full `openssl s_client` / `curl` handshake against a
running kroopt server — real transcript hashing, the real server `Finished`, and a real socket
transport — is **live and tested**: see `scripts/tls-interop.sh` and
[current security state](../verification/current-security-state.md). (This page predates that work;
the cross-library signature check here remains the unit-level complement to the live interop.)
