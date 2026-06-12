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
`realCapabilities`: `TLS_CHACHA20_POLY1305_SHA256`, X25519, Ed25519, SHA-256, drawn
from the OS CSPRNG. It never claims AES-GCM, SHA-384, P-256, ECDSA, or RSA. A
`ServerConfig` requiring an out-of-profile suite or signature scheme is rejected at
validation (`validateServerConfigCapabilities`) with a typed `CapabilityError` — never
accepted and failed at runtime, and never silently downgraded.

Entropy fails **closed**. `Hacl.randomBytes` returns a typed `RandomResult`; the native
`getrandom` wrapper, on any failure, returns a zero-length buffer (never a zero-filled
buffer reported as success), which the wrapper turns into `RandomResult.error`. No caller
synthesises fallback entropy: `provisionRealConfig` fails closed with `entropyFailure`
rather than emit a zero or partial key. Deterministic randomness is confined to the
explicitly named fake/test provider; a `randomBytes` operation reaching the real provider
is a typed error, so deterministic bytes can never masquerade as real randomness.
