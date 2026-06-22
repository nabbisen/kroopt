# Crypto provider and FFI contract

kroopt borrows primitive cryptography from HACL\*/EverCrypt but owns the call
boundary: operation selection, result correlation, the secret-handle lifecycle,
and error mapping (RFC 008, RFC 009). The verified core never calls a provider —
it emits `CryptoOp` actions, and the interpreter submits them to a provider and
feeds correlated `CryptoResult` events back.

## Operation-id correlation (proved)

The safety property that makes provider results trustworthy lives in the core: a
`CryptoResult` is processed only if its operation id is currently outstanding.
`handleCryptoResult` checks `pendingOps.contains op` before doing anything; a
result whose id is stale, duplicate, or forged is dropped with no effect. This is
`Kroopt.Core.Proofs.stale_crypto_result_rejected`: for a non-outstanding id the
state is unchanged and no actions are emitted — so a late or replayed provider
answer cannot buffer plaintext, advance a sequence number, or change phase. Each
pending op also records the expected kind, epoch, and direction (`PendingCryptoOp`)
for the interpreter's metadata checks.

## Capability negotiation (deterministic, config-time)

`Kroopt.Crypto.validateCapabilities` checks that every configured cipher suite,
group, signature scheme, and hash is supported by the provider, and that a usable
random source exists. Capability mismatch is a **configuration** error that
aborts validation — kroopt never silently downgrades a suite because a primitive
is missing (RFC 008 §3, §9). The first missing item is reported as a typed
`CapabilityError`.

## Provider interface and the fake provider

`Kroopt.Crypto.CryptoProvider` is a synchronous interface: `capabilities` plus a
`submit : OperationId → CryptoOp → Except CryptoError CryptoResult`. The initial
provider is synchronous, but because the core models crypto as actions/results,
an asynchronous provider stays possible later without touching the proofs
(RFC 008 §8.2). `Kroopt.Crypto.fakeProvider` is the deterministic, purpose-aware
fake used by the model, handshake, and end-to-end tests.

## The native shim (contract fixed, build deferred)

`Kroopt/Native/kroopt.h` fixes the C contract: one function per narrow primitive
or secret-handle operation, explicit lengths, status codes, and documented
ownership — no protocol decisions, negotiation, or logging in C (RFC 009 §3,
§10). AEAD authentication failure (`KROOPT_ERR_AUTH_FAILED`) is distinct from
internal failure so the TLS alert stays deterministic (RFC 009 §8). Durable
secrets live in a C-owned zeroizable arena referenced by generation-tagged
handles (RFC 009 §7).

The implementation (`kroopt_hacl_shim.c`) links HACL\*/EverCrypt and is compiled
into the Lake build once HACL\* is vendored or pinned as a system dependency
(RFC 009 §5; Requirements Open Question 1). When it lands it carries
known-answer tests for every primitive (release blockers, RFC 009 §6) and runs
under ASan/UBSan with warnings as errors (RFC 009 §9). Until then the fake
provider satisfies the same `CryptoProvider` interface, and the correlation
guarantee above already holds in the verified core regardless of which provider
is plugged in.

## Capability honesty and fail-closed entropy (RFC 034)

The real provider advertises only what the vendored HACL\* subset can perform —
`realCapabilities`: all three TLS 1.3 AEAD suites (`TLS_AES_128_GCM_SHA256`,
`TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`), SHA-256 and SHA-384,
X25519 **and secp256r1 (P-256)** key exchange, Ed25519, drawn from the OS CSPRNG. The
secp256r1 group is real: the provider computes a NIST-CAVP-validated P-256 ECDH shared
secret, and `scripts/tls-interop.sh` completes an OpenSSL `-groups P-256` handshake +
app-data round-trip on both drivers. In this default profile it does **not** advertise
ECDSA/RSA as signature schemes — even though the provider *implements* those primitives
(used by other certificate profiles) — so a `ServerConfig` requiring an out-of-profile
signature scheme is rejected at validation (`validateServerConfigCapabilities`) with a
typed `CapabilityError` — never accepted and failed at runtime, never silently
downgraded.

**Group policy is now load-bearing (RFC 039).** The group dimension follows the same
three-layer model the contract uses for suites and signature schemes: the **provider**
declares which groups it can perform; each **endpoint** declares a `namedGroups` policy
(default `[x25519, secp256r1]`, x25519 preferred; a hardened listener sets `[x25519]`); and
the **client** offers `key_share` entries. Config validation rejects an endpoint policy not
⊆ provider capability (a `CapabilityError.unsupportedGroup`, alongside `.emptyGroupPolicy`
and `.duplicateNamedGroup`), and the verified core selects the negotiated group as the
intersection of endpoint policy and client `key_share`, ordered by server preference — never
inferred from parser reachability. P-256 point validation is layered: the parser checks wire
shape (65 bytes, `0x04` prefix) while the provider performs on-curve validation inside
`Hacl_P256_ecp256dh_r` (fail-closed `none` on an off-curve point or point at infinity). With
a valid server ephemeral, such a `none` isolates the fault to the peer point, so the provider
classifies it as a typed `peerInvalidKeyShare` — the core fails the handshake with
`illegal_parameter` (attacker input, not a server fault), while a genuine provider/shim fault
(e.g. a bad server ephemeral) maps to `internal_error`; either way no `ecdheComplete` is
fabricated. The hash dimension is likewise **derived-and-enforced**: required hashes are
derived from the configured suites and validated against provider capability, not treated as
informational. `scripts/tls-interop.sh` additionally exercises an x25519-only listener that
refuses an OpenSSL `-groups P-256` client (RFC 039 §8.16).

Entropy fails **closed**. `Hacl.randomBytes` returns a typed `RandomResult`; the native
`getrandom` wrapper, on any failure, returns a zero-length buffer (never a zero-filled
buffer reported as success), which the wrapper turns into `RandomResult.error`. No caller
synthesises fallback entropy: `provisionRealConfig` fails closed with `entropyFailure`
rather than emit a zero or partial key. Deterministic randomness is confined to the
explicitly named fake/test provider; a `randomBytes` operation reaching the real provider
is a typed error, so deterministic bytes can never masquerade as real randomness.

## Sanitizer coverage (RFC 037 §7.5)

`scripts/sanitizer-check.sh` compiles the `kroopt_ffi.c` shim and the HACL\* sources it
calls under AddressSanitizer + UndefinedBehaviorSanitizer (system gcc — the Lean-bundled
clang carries no ASan runtime) and runs `Kroopt/Native/kroopt_sanitizer_harness.c`. The
harness links the Lean runtime so it hands the shim genuine `ByteArray`s, and checks two
things: tight **buffer bounds**, via direct HACL calls on exact-size malloc-backed buffers
(a deliberate one-byte under-allocation is caught as a heap-buffer-overflow — the negative
control), and **UB plus fail-closed behaviour** on the actual `kroopt_ffi_*` entry points,
with known-answer vectors (SHA-256, Ed25519 RFC 8032) confirming correct wiring and
adversarial inputs (wrong-size keys, sub-tag ciphertext, tampered tag) confirming the
length guards. A clean run partly discharges the FFI-boundary trust assumption (RFC
009/024): the shim and the primitive calls it issues read and write in bounds and exhibit
no undefined behaviour on key-schedule-shaped and adversarial inputs. Lean's own allocator
places `ByteArray` data outside ASan's redzones, so the malloc-backed half is what provides
the tight bounds coverage of the crypto I/O.
