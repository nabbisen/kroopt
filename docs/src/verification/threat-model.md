# Threat model and abuse cases

This is the kroopt threat model (RFC 017): the adversary kroopt defends against,
and where each defense lives. kroopt sits at the internet-facing edge, so its
inputs are attacker-controlled by default.

## Adversary

A network attacker who can send arbitrary bytes to the TLS listener, fragment or
reorder them, open many connections, and replay or delay messages. kroopt does
**not** defend against a compromised host, a malicious configuration, or breaks
in the borrowed cryptographic primitives (those are HACL\*/EverCrypt's
responsibility and are ASSUMED, never claimed — see the trust matrix).

## Threats and defenses

| Threat | Defense | Where |
|---|---|---|
| Plaintext read before the handshake completes | `emitPlaintext` reachable only in `connected` | proved: `no_plaintext_emit_unless_connected` |
| Forged/again plaintext from a failed decrypt | plaintext only after a successful AEAD open | proved: record-path no-emit; `aead_open_failure_no_plaintext` |
| AEAD nonce reuse | per-direction sequence, overflow fatal | proved: nonce/seq theorems |
| Key/epoch/direction confusion | typed handles, separated counters | proved: key-separation theorems |
| Stale/replayed crypto result | operation-id correlation guard | proved: `stale_crypto_result_rejected` |
| Parser overrun / ambiguous parse | bounds-safe reader, strict extension handling | proved: parser-bounds; tested: fuzzer |
| Resource exhaustion (huge/fragmented input) | hard resource budgets | proved: `chargeHandshakeBytes_bounded` et al. |
| Event-loop spin on repeated wouldBlock | fuel-bounded progress, step budget | interpreter; `chargeProgressStep_bounded` |
| ALPN selecting an unoffered protocol | intersection-only negotiation | proved: `negotiateAlpn_offered_and_allowed` |
| Downgrade to TLS 1.2 / 0-RTT / tickets | strict `supported_versions`, deferred features off | tested: scope control |
| Truncation passed off as clean close | EOF-before-close_notify is fatal | proved/tested: close policy |
| Secret leakage via logs/errors | secret handles unprintable; redacted error view | construction; `redactError` |
| Server private key lingering after shutdown | C-owned native arena; `zeroize`/`release` volatile-wipe before free | tested: native wipe + ASan/UBSan (RFC 037 §3) |
| Connection traffic secrets lingering after a connection ends | terminal paths invalidate the arena generation (logical); byte storage is Lean-GC-managed | best-effort / tested: terminal-path leak checks (RFC 037 §3) |
| Unauthenticated bytes reaching jemmet as HTTP | TLS failure never degrades to plaintext | tested: E2E negatives |

Each "proved" row is a machine-checked theorem in `Kroopt.Proofs`; each "tested"
row is exercised by a deterministic suite or the fuzzer. The crypto math itself
is borrowed and trusted, not proved.

**Secret-memory honesty (RFC 037 §3) — two postures, kept distinct.** The **server private key**
is C-owned and explicitly zeroized: it lives only in the native arena (`Kroopt.Crypto.NativeSecret`),
is signed by handle, and is volatile-wiped on `release`/`zeroize` (the "server private key
lingering" row above is *tested C-owned zeroization*). **Connection-lifetime traffic secrets** are
different: the ECDHE shared secret and the HKDF traffic secrets and per-record keys live in a pure
`SecretArena` threaded through the interpreter; on every terminal path (`closeTransport`,
`failWithAlert`, `reportError`, an internal-invariant failure, an oversize-record failure) the
interpreter bumps the arena generation, which drops the stored bytes from the arena's reachable
state and invalidates every outstanding handle (a stale handle then resolves to `none`, never the
wrong secret). What it does **not** do is overwrite the underlying memory: dropped `ByteArray`s are
reclaimed by the runtime on its own schedule, and copies the borrowed crypto code made are outside
this model's reach. So the "connection traffic secrets lingering" row is *best-effort / tested
logical invalidation*, **not** memory zeroization, and **no production zeroization is claimed for
traffic secrets**. Real traffic-secret zeroization requires an IO production interpreter backed by
the C-owned arena; per architect review this is a **stable/v1 gate**, deferred behind RFC 031 and
tracked by RFC 040 (see `deferred-scope.md`). The two rows must not be blurred into one.
