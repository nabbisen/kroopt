# Threat model and abuse cases

This is the kroopt threat model (RFC 017): the adversary kroopt defends against,
and where each defense lives. kroopt sits at the internet-facing edge, so its
inputs are attacker-controlled by default.

## Adversary

A network attacker who can send arbitrary bytes to the TLS listener — **fragmenting, coalescing,
delaying, or truncating** them — open many connections, and replay or delay whole messages and
connections. The attacker cannot *reorder* the bytes within a delivered stream: TLS assumes a reliable,
in-order transport, and preserving that abstraction is the transport adapter's responsibility (iotakt),
below kroopt. kroopt does **not** defend against a compromised host, a malicious configuration, or
breaks in the borrowed cryptographic primitives (those are HACL\*/EverCrypt's responsibility and are
ASSUMED, never claimed — see the [trust matrix](trust-matrix.md)). Memory-disclosure exposures that stop
short of full host compromise — core dumps, swap, crash diagnostics — are classified separately under
[Secret-memory honesty](#secret-memory-honesty) below.

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
| Event-loop spin on repeated wouldBlock | fuel-bounded progress, step budget | interpreter; `driveEvents` fuel recursion (`maxProgressStepsPerCall`); tested progress-budget termination |
| Many concurrent *bounded* handshakes exhaust global CPU/memory | per-connection bounds + handshake/idle timeouts (kroopt); listener-wide admission, per-peer rate limits, global budgets (iotakt + jemmet) | per-conn proved/tested; **global DELEGATED** — see below |
| ALPN selecting an unoffered protocol | intersection-only negotiation | proved: `negotiateAlpn_offered_and_allowed` |
| Non-conformant ClientHello (`key_share` without `supported_groups`) | strict reject as `illegal_parameter` (RFC 8446 §4.2.8), not `key_share`-authoritative | tested: `noSgCH` replay (review HIGH-3) |
| Downgrade to TLS 1.2 / 0-RTT / tickets | strict `supported_versions`, deferred features off | tested: scope control |
| Truncation passed off as clean close | EOF-before-close_notify is fatal | proved/tested: close policy |
| Secret leakage via logs/errors | secret handles unprintable; redacted error view | construction; `redactError` |
| Server private key lingering after shutdown | C-owned native arena; `zeroize`/`release` volatile-wipe before free | tested: native wipe + ASan/UBSan (RFC 037 §3) |
| Connection traffic secrets lingering after a connection ends | terminal paths invalidate the arena generation (logical); byte storage is Lean-GC-managed | best-effort / tested: terminal-path leak checks (RFC 037 §3) |
| Unauthenticated bytes reaching jemmet as HTTP | TLS failure never degrades to plaintext | tested: E2E negatives |

Each "proved" row is a machine-checked theorem in `Kroopt.Proofs`; each "tested"
row is exercised by a deterministic suite or the fuzzer. The crypto math itself
is borrowed and trusted, not proved.

## Per-connection vs listener-wide DoS

kroopt proves and enforces *per-connection* bounds: every queue, parser vector, extension list, and
record fragment is bounded; progress loops are fuel-limited; and per-connection handshake and idle
timeouts bound how long a single slow or stalled peer can hold a slot. That is necessary but, for an
internet-facing edge, **not sufficient** — an adversary can open many connections and force many
*individually bounded* but collectively expensive handshakes.

The controls for that — listener-wide admission control, per-peer/IP rate limiting, accept-backlog
policy, maximum concurrent connections and concurrent handshakes, and a global CPU/memory budget across
connections — are **integration responsibilities of iotakt and jemmet, not kroopt.** kroopt owns
neither the accept loop nor the fd lifecycle, so it is structurally the wrong layer to enforce global
admission. This boundary is **declared explicitly rather than left implicit**: the layers that own
connection admission must provide the global controls; kroopt contributes the per-connection bounds and
timeouts they compose with. (Review finding HIGH-2.)

## Error and alert oracle posture

Error detail must never become an oracle for a peer or a co-tenant, so kroopt keeps four surfaces
deliberately distinct:

- **Peer-visible alerts** are protocol-determined, deterministic by error class, and bounded — the same
  malformed input always yields the same alert, carrying no internal detail.
- **Public app/operator errors** are coarse categories only (the eight-way `ErrorCategory`), never raw
  packet contents or fine-grained parser state.
- **Debug trace** is default-off, carries no raw bytes and no secrets (length-only byte events), and is
  a local/dev gate — never a production default.
- **Internal diagnostics** (typed local metrics, precise parser positions) stay in trusted local/dev
  context and are never exposed to peers.

This is why an internal-invariant failure maps to a *generic* fatal alert externally while retaining a
typed local category internally. (Review finding MEDIUM-5.)

## Secret-memory honesty

**Two postures, kept distinct (RFC 037 §3).** The **server private key**
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

**Memory-disclosure classification (review HIGH-4).** Best-effort *logical* invalidation of traffic
secrets does not defend against exposures that read process memory **without** full host compromise.
These are broader than the "compromised host" exclusion in the Adversary section — a core dump or a
swapped-out page can expose a still-resident traffic secret without the attacker ever holding the host:

- **core dumps** (a crash writes process memory, including live `ByteArray`s, to disk);
- **swap / paging** (a traffic secret paged out persists on the swap device);
- **crash diagnostics / minidumps** and debugger or `ptrace` inspection;
- **copies the borrowed crypto made** of key material outside the arena's reach.

For the **traffic-secret** posture these are **out of scope until the stable/v1 native arena lands** —
logical invalidation is all that is claimed. The **server private key** is not in this gap: it is
C-owned and volatile-wiped, so it is not left resident in a Lean-GC `ByteArray`. Operators wanting
defense-in-depth before v1 should disable core dumps and swap for the process and restrict
crash-diagnostic capture; this is the honest mitigation, not a kroopt-enforced guarantee.
