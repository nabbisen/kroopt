# Postmortem — the Ed25519 "non-RFC-8032" false positive

**One line:** *The expected value was wrong; test-vector provenance is now mandatory.*

## What happened

Across M19–M22, kroopt reported that the vendored HACL\* Ed25519 was not RFC 8032
compliant, and an investigation "localised" the fault progressively into the FFI, then
the build, then gcc's compilation of HACL\*'s Edwards point arithmetic. A re-vendor and,
as a fallback, binding an *unverified* Ed25519 reference were proposed.

All of that was wrong. Architectural review found the reproduction had paired a
**non-RFC seed** (`9d61…7e8f`) with RFC 8032 §7.1 Test 1's **public key** (`d75a9801…`),
which belongs to a **different seed** (`9d61…7f60`). HACL\* had correctly derived the
right public key (`bcd55c06…`) for the seed it was actually given.

## Why the investigation didn't catch it

Every "isolation" step was internally valid but ran on the wrong seed, so each one only
confirmed HACL\*'s *self-consistency* — the clamped scalar matched an independent SHA-512
clamp, the base point and the `2d` constant matched, the standalone C reproduced the same
output. None of these touched the one thing that was actually wrong: the **expected
value's provenance**. Internal-consistency evidence was over-weighted; the provenance of
the published vector was never checked byte-for-byte.

## The corrected resolution

HACL\* on the correct RFC 8032 §7.1 Test 1 seed reproduces the published public key
*and* signature byte-for-byte, confirmed independently by an RFC 8032 reference
implementation and by OpenSSL (`scripts/ed25519-interop.sh`). No re-vendor, no compiler
workaround, no unverified fallback, no trust-matrix change: Ed25519 stays
**ASSUMED (inherited verified)** with KAT + interop as **TESTED** evidence.

## The rule we now follow

> When a verified or externally trusted primitive disagrees with an expected value, first
> verify the vector provenance byte-for-byte before localizing the defect into the
> primitive, compiler, or FFI.

Operationally, the order is: **published-vector provenance → byte-length checks →
independent oracle → HACL KAT → FFI KAT → TLS CertificateVerify interop.** The first step
is not optional.

## What changed in the repo

- The provision test asserts a **positive RFC 8032 §7.1 Test 1 KAT** (public + signature);
  the old "tripwire that expects failure" is removed.
- Test vectors live in `Tests/Vectors/Ed25519Rfc8032.lean` with an explicit `source`,
  algorithm, and **length assertions** (`wellFormed`), and the RFC seed is kept distinct
  from the non-RFC regression seed (`seedsDistinct`) so the two can never be re-mixed.
- Every published crypto KAT (`Tests/Hacl.lean`, `Tests/Provision.lean`) carries a source
  + section + input provenance comment; round-trip / self-consistency checks are labelled
  as such and never presented as standards conformance.
- The CertificateVerify OpenSSL interop is a **separate evidence layer**, not a substitute
  for the RFC vectors.

The security model was never affected: the verified core, the TLS state/record/key-schedule
proofs, and the HACL\*/EverCrypt trust boundary all stood throughout. This was a
test-governance failure, and the test process — not the crypto — is what was fixed.
