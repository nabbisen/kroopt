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
| Unauthenticated bytes reaching jemmet as HTTP | TLS failure never degrades to plaintext | tested: E2E negatives |

Each "proved" row is a machine-checked theorem in `Kroopt.Proofs`; each "tested"
row is exercised by a deterministic suite or the fuzzer. The crypto math itself
is borrowed and trusted, not proved.
