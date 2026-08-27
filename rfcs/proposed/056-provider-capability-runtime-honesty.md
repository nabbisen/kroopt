# RFC 056 — Provider Capability Runtime Honesty

**Project.** kroopt  
**Status.** Proposed  
**Type.** Blocking correctness/availability fix  
**Target milestone.** AR1; release `0.128.0`, with or before [RFC 045](045-endpoint-negotiation-policy-authorization.md) Slice 2  
**Requires completion of.** [RFC 008](../done/008-crypto-provider-capability-and-ffi-contract.md) (provider/FFI contract), [RFC 034](../done/034-provider-capability-honesty-and-entropy.md) (capability honesty)  
**Coordinates with.** [RFC 045](045-endpoint-negotiation-policy-authorization.md), which promotes AES-GCM to the preferred suite and therefore depends on this; [RFC 048](048-validated-construction-and-protected-epoch-fail-closed.md), which binds a capability digest into `ValidatedRuntime`  
**Touches.** `Kroopt/Crypto/Provider.lean`, `Kroopt/Crypto/RealProvider.lean`, `Kroopt/Native/kroopt_aesgcm.c`, `Kroopt/Native/kroopt.h`, `Tests/Capabilities.lean`, `Tests/RealProvider.lean`, trust matrix, current-security state  

## Review finding

Raised by the RFC 045 design review (2026-08-01,
`.git-exclude/reviewed/014-rfc045-ar1-design-architecture-review.md`, BF4). This is a newly discovered
defect: it is not one of the B1–B8 architecture-review findings and no existing RFC addresses it. It reopens
an uncovered acceptance gap in RFC 034, which `rfcs/README.md` permits without rewriting that RFC's history.

kroopt advertises a cipher suite it may be unable to perform:

- `Kroopt/Crypto/Provider.lean:126-132` — `realCapabilities` is a **static constant** advertising
  `[aes128GcmSha256, aes256GcmSha384, chacha20Poly1305Sha256]`.
- `Kroopt/Native/hacl/EverCrypt_AEAD.c:95-128` — `create_in_aes128_gcm` and `create_in_aes256_gcm` return
  `EverCrypt_Error_UnsupportedAlgorithm` unless **all five** of `has_aesni`, `has_pclmulqdq`, `has_avx`,
  `has_sse`, `has_movbe` hold at runtime. AES-GCM exists only through the Vale path; there is no portable
  fallback. ChaCha20-Poly1305 is unaffected — it is built from scalar C and is always available.
- No CPUID or `EverCrypt_AutoConfig2` predicate is exposed to Lean. The Lean layer never asks whether the
  hardware can perform what it advertises.

`validateServerConfigCapabilities` therefore validates an endpoint's AES-GCM policy against a claim that may
be false on the host, and the discrepancy surfaces only at the first AEAD seal — after ServerHello has
committed to the suite, where RFC 045 §5.2 correctly makes provider failure fatal with no retry.

This is concrete rather than theoretical. An Ivy Bridge Xeon E5 v2 has AES-NI, PCLMULQDQ, AVX and SSE but no
MOVBE; so do VMs running masked CPU models. On such a host the connection dies mid-handshake. Under today's
first-recognized-client-order behaviour the path is rarely reached; under RFC 045's AES-128-first preference
it becomes the default path, which is why this RFC gates that change.

## Decision

The real provider advertises only what the host can actually perform. Capability determination moves from a
compile-time constant to a startup probe, and the probe tests the **actual predicate** rather than mirroring
EverCrypt's feature list.

**Probe by construction attempt.** For each AES-GCM suite, the native shim calls
`EverCrypt_AEAD_create_in` with a throwaway key, records success or `UnsupportedAlgorithm`, and frees the
state. Mirroring the five CPUID predicates in kroopt would duplicate an upstream decision that an RFC 043
HACL\* bump could change; attempting the construction cannot drift. `EverCrypt_AutoConfig2_init` is forced
before the first probe, exactly as `kroopt_aesgcm.c:42` already does.

**Advertisement is the intersection.** `realCapabilities` becomes the *maximal* set the build could support.
Provider construction intersects it with the probe result and publishes the intersection as
`CryptoProvider.capabilities`. Because `validateServerConfigCapabilities` already consumes
`provider.capabilities`, an endpoint requiring AES-GCM on an incapable host then fails at **config
validation** with the existing `CapabilityError.unsupportedSuite`, before any listener or connection exists.
No new failure path is introduced; an existing one is made reachable at the right time.

**Hashes are unaffected.** SHA-256 and SHA-384 come from portable C (`Hacl_Hash_SHA2.c`) and are always
available, so `hashAlgorithms` needs no filtering. ChaCha20-Poly1305 is likewise always available, so the
advertised suite set is never empty and a ChaCha-only endpoint always validates.

**Construction becomes effectful.** `mkRealProvider` is currently pure
(`Kroopt/Crypto/RealProvider.lean:224`). Probing requires `IO`. This is a pre-1.0 public API change and is
intentional: a provider that has not been probed cannot make an honest capability claim. It is small and
should be coordinated with RFC 048, which reshapes construction anyway.

## Work breakdown

1. Add a native probe (`kroopt_aead_probe` or equivalent) that forces `EverCrypt_AutoConfig2_init`, attempts
   `EverCrypt_AEAD_create_in` for AES-128-GCM and AES-256-GCM with a throwaway key, frees each state, and
   returns a bitmask. Declare it in `kroopt.h` with explicit length/return contracts per RFC 008.
2. Expose the probe to Lean as a single total FFI call returning a typed result; no partial or panicking
   surface.
3. Rename the existing constant to express intent (`realCapabilitiesMax` or equivalent) and derive the
   published capability set as its intersection with the probe.
4. Make `mkRealProvider` return `IO CryptoProvider`; update call sites. The fake provider is unchanged and
   stays pure.
5. Cache the probe result per process; it cannot change during a run.
6. Record the probed set in the trace/diagnostic surface as suite ids only, consistent with RFC 020
   redaction rules.
7. Update the trust matrix and current-security state so the advertised AES-GCM rows state that
   advertisement is host-conditional.

## Acceptance criteria

1. On a host where AES-GCM construction fails, `provider.capabilities.suites` excludes both AES-GCM suites
   and includes ChaCha20-Poly1305.
2. An endpoint requiring AES-GCM on such a host is rejected at config validation with
   `CapabilityError.unsupportedSuite`, before any listener or connection state exists.
3. On a capable host, the advertised set is unchanged from today and every existing capability, KAT, live
   interop, and replay test passes without modification.
4. The probe is total, cached, and free of panics, partiality, and secret material; the throwaway key is not
   derived from any configured secret.
5. No handshake path can reach an AEAD seal for a suite absent from the published capability set.
6. Sanitizer lanes pass with the probe on the exercised path, including the free of each probed state.
7. Documentation states plainly that AES-GCM availability is host-conditional and that a configuration valid
   on one host may be refused on another — the intended fail-closed behaviour.

## Non-goals

- Adding a portable software AES-GCM fallback. The vendored HACL\* subset provides none, and adding one
  would mean shipping unaccelerated AES-GCM whose constant-time properties are not the ones RFC 043 anchors.
  Affected hosts negotiate ChaCha20-Poly1305, which is why the suite stays advertised.
- Probing named groups or signature schemes. X25519, P-256, Ed25519, and the hash and HKDF paths are
  portable C in this build and are not runtime-gated. If an upstream bump introduces a gated primitive in
  those families, this RFC's mechanism extends to it; that extension is not scoped here.
- Changing which suites the build *could* support — breadth remains
  [RFC 035](035-browser-grade-crypto-surface.md).
- Sealing validated construction against forgery, which remains
  [RFC 048](048-validated-construction-and-protected-epoch-fail-closed.md).
