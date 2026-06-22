# Deferred features and scope control

kroopt's initial release line is deliberately narrow (RFC 016): TLS 1.3 only,
server role only, no HelloRetryRequest. Features that are deferred or excluded —
TLS 1.2, DTLS, QUIC, 0-RTT/early data, session tickets/resumption, KeyUpdate,
post-handshake auth, renegotiation, compression, mTLS, and the client role — are
not partially implemented and must not be silently activatable.

Scope is enforced, not just documented. A ClientHello that does not genuinely
offer TLS 1.3 is refused rather than downgraded: the parser requires a
`supported_versions` extension that lists 0x0304, so a ClientHello with no
`supported_versions`, or one offering only TLS 1.2 (0x0303), fails cleanly. The
absence of an acceptable X25519 `key_share` fails too (no HRR). These are
exercised by the hardening suite.

Feature gates must never silently change security semantics: enabling any
deferred feature is an explicit, RFC-gated change, not a build flag that flips a
default. Each deferred feature returns through its own future RFC (RFC 016's
descendants) with its own model, proofs, and tests.

## Deferred to stable/v1 — native traffic-secret arena migration

One hardening item is deliberately deferred past the pre-stable line rather than excluded:
moving **connection-lifetime traffic secrets** (the ECDHE shared secret, the HKDF
handshake/application traffic secrets, and the per-record AEAD keys/IVs) from the pure Lean
`SecretArena` onto the C-owned zeroizing arena (`Kroopt.Crypto.NativeSecret`). Today those
secrets are handle-scoped and logically invalidated on close, but their byte storage is
Lean-GC-managed, so their zeroization is **best-effort** (the server *private key* is already
C-owned and explicitly zeroized — the two postures are kept as distinct trust-matrix rows; see
`proof-assumptions.md` and `threat-model.md`).

This is deferred, not excluded, because real zeroization of those secrets requires an **IO
production interpreter**: the secret store/read/zeroize points sit inside the pure
`CryptoProvider.submit` / `Conn.Interpreter.driveEvents`, and making them effectful would
collapse the deterministic, replayable interpreter that the proofs and the RFC 031 correspondence
depend on. Per architect review the decision is:

* **Pre-stable line:** acceptable with documented best-effort traffic-secret zeroization (this
  posture). Continue protocol/interop work; do **not** weaken proof/runtime correspondence to
  migrate early.
* **Stable/v1 gate:** require the native traffic-secret arena (or an explicit owner-approved
  exception). Real traffic-secret zeroization is a v1 gate, not a pre-stable precondition.

The migration is sequenced **after RFC 031** (which must lock the pure proof/runtime
correspondence first, so the IO production interpreter has a fixed pure model to correspond to)
and is specified by **RFC 040** as a two-interpreter architecture — the pure interpreter remains
the executable model; an IO production interpreter backed by the native arena is shown to
correspond to it. Only once that lands may the trust matrix promote traffic-secret zeroization
from best-effort to tested native zeroization.

## RFC 040 stale-result checklist (standing requirement)

The synchronous model has no concurrency window — a crypto result re-enters `step` in the same
sequence it was requested, and the operation-id guard (`stale_crypto_result_rejected`) already covers
duplicates and results after terminal. An asynchronous IO production interpreter reopens that window, so
the following requirements are recorded **now** so they are not lost when RFC 040 is implemented. Each
must be discharged (proved or tested) before any async result path ships:

- a **duplicate** crypto result is a no-op;
- a **stale cross-generation** result (connection generation advanced) is dropped;
- a result **after terminal** state is dropped, never producing plaintext or actions;
- a provider **success after a local timeout** is dropped;
- a provider **failure after close** is dropped;
- **connection-generation reuse** cannot alias a new connection to an old result;
- **secret-handle generation reuse** cannot resolve a stale handle to a live secret;
- **operation-id wrap/reuse** cannot match a stale result to a new pending op;
- pending-op and secret state is **cleaned up on every terminal path**;
- **no plaintext** can ever derive from a stale result.

This list is the async counterpart to the synchronous guarantees already in the
[trust matrix](trust-matrix.md); it is a checklist for RFC 040, not a claim of current coverage. (Review
MEDIUM-6.)
