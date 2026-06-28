# Operator event and metric reference

This page is the operator-facing reference for what kroopt emits about a connection: the diagnostic
**event** surface that exists today, the **redaction** guarantee that bounds it, the typed **error
categories** a caller sees, and the **metric** counters — a small set driven internally today, with
export/histograms planned for v0.4. It is deliberately honest about that last distinction — events and
the wired counters are real; export and the broader catalogue are design.

## Events emitted today

kroopt's event surface is the `TraceEvent` taxonomy (RFC 036 §3), projected from the verified core's
authorized `OutputAction` stream by `Kroopt.Conn.traceOfAction` and rendered to one compact line each
by `TraceEvent.render`. It is **gated behind `debug_trace`** (the `RuntimeState.traceEnabled` flag),
**off by default**, and intended for diagnostics — not as a production audit-log stream. Every event is
**secret-free by construction**: each variant carries only ids, kinds, byte *lengths*, code points,
and categories, so no rendered line can carry plaintext, ciphertext, DER, a transcript digest, a
secret handle, or attacker-controlled bytes (`Tests.Trace`, including sentinel-leak negatives).

| Event (rendered) | Fires when | Carries |
|---|---|---|
| `transport-read` | the interpreter asks the transport for bytes | connection id |
| `transport-write` | ciphertext is queued for the transport | connection id, byte **length** (never bytes) |
| `handshake-out` | a server-flight message is emitted | connection id, sequence, message **type label** (ServerHello / EncryptedExtensions / CertificateVerify / Finished) |
| `certificate-out` | the server Certificate is emitted | connection id, sequence, DER **length** (never the chain) |
| `write-interest` | write readiness is registered or dropped | connection id, enabled flag |
| `crypto-call` | a crypto operation is requested | connection id, op id, op **kind** (ecdhe / hkdfExtract / aeadSeal / …) — never inputs or handles |
| `plaintext-emit` | authenticated application plaintext is delivered to the caller | connection id, **length** only |
| `plaintext-accept` | caller plaintext is accepted for sending | connection id, byte count |
| `handshake-complete` | the handshake reaches `connected` | connection id, negotiated cipher suite (public metadata) |
| `error` | a typed error is reported to the caller | connection id, error **category** only (see below) |
| `alert-classified` | the core classified a **fatal** alert for a failure (it is *not* a guaranteed wire send — the interpreter terminates on `failWithAlert`; only `close_notify` is transmitted) | connection id, alert description, level |
| `transport-close` | the transport is closed | connection id, close **mode** (graceful / fatal / abortive) |
| `secret-released` | a secret handle is released | nothing — the bare event |

Because the projection is total over the core's action variants, the event stream and the protocol's
authorized actions are the same set: an operator reading the trace is reading exactly what the core
decided, never a parallel narrative reconstructed by the interpreter.

## What no event ever contains

The redaction boundary is structural, not a runtime filter. No `TraceEvent` constructor has a field
that can hold any of: application plaintext; ciphertext or record bytes; certificate DER; raw
ClientHello or other attacker-controlled bytes; SNI values; transcript hashes/digests; crypto-operation
inputs or outputs; secret handles, keys, IVs, or traffic secrets. Secret-bearing types are themselves
unprintable by construction (non-`Repr`, non-serializable), so even a future event variant cannot
render one. This is the RFC 013 §9 / RFC 018 data-classification discipline applied to the event
surface: byte-bearing actions degrade to a length, secret references to a bare event or an op id.

## Error categories

When kroopt reports a failure to the caller (and in the `error` event), only a coarse, typed
**category** crosses the boundary — never the offending detail, position, or bytes. The categories are:

`protocol`, `parse`, `crypto`, `config`, `resourceLimit`, `transport`, `closed`, and `internal`
(an internal invariant failure, surfaced generically). jemmet consumes these to decide log level,
metric increment, and whether to suppress noisy attacker-caused parse errors — without ever receiving
secrets or raw handshake blobs. Internal invariant failures map to a generic external category while
retaining typed local detail for the project's own metrics.

These public categories are **intentionally coarse and stable**. Finer internal failure causes (the
specific unsupported version/group, the precise parse fault, and so on) remain implementation detail in
debug/trace metadata and are not part of the public API commitment — a coarse surface reduces oracle
signal and gives consumers a stable contract; TLS alert descriptions already carry protocol-level
failure semantics where a peer needs them.

## Metric surface (counters driven internally; no export yet)

kroopt now maintains a small set of **internal** operational counters that the live driver updates
during a real handshake (0.99.0-dev; RFC 020 §10.2): handshakes completed/failed, fatal alerts classified, resource
failures, and ALPN selected move as connections run. They live on internal runtime state — there is
**no public accessor and no export format**: histograms, aggregation, and an export/backend surface are
RFC 020 **v0.4** work. The broader catalogue below is the **planned** export surface, recorded so the
names are stable when emission/export lands; treat anything beyond the five wired counters as design.

| Metric | Status | Labels | Meaning |
|---|---|---|---|
| `kroopt_handshakes_completed_total` | wired (internal counter) | — | handshakes reaching `connected` |
| `kroopt_handshakes_failed_total` | wired (internal counter) | `reason` | handshakes ending in terminal failure |
| `kroopt_alerts_classified_total` | wired (internal counter) | `alert` | **fatal alerts classified** for a failure (not transmitted; see `alert-classified` and the fatal-alert-wire RFC) |
| `kroopt_resource_limit_failures_total` | wired (internal counter) | `kind` | budget exhaustion by limit |
| `kroopt_alpn_selected_total` | wired (internal counter) | — | handshakes where ALPN was negotiated |
| `kroopt_connections_started_total` | planned (v0.4) | — | connections wrapped by `TlsConn.server` |
| `kroopt_bytes_ciphertext_in_total` / `_out_total` | planned (v0.4) | — | ciphertext moved over the transport |
| `kroopt_bytes_plaintext_in_total` / `_out_total` | planned (v0.4) | — | plaintext exchanged with the caller |
| `kroopt_alerts_received_total` | planned (v0.4) | `alert` | alerts received |
| `kroopt_crypto_failures_total` | planned (v0.4) | `kind` | crypto-operation failures by kind |
| `kroopt_parser_failures_total` | planned (v0.4) | `kind` | parser rejections by kind |
| `kroopt_config_generation_current` | planned (v0.4) | — | the active validated-config generation |

The same redaction rule applies to both the wired counters and the planned surface: labels must never
carry raw SNI or other attacker-controlled values — `reason`/`kind`/`alert` are bounded enumerations,
not free-form strings.

## Operational posture

`debug_trace` is a diagnostic gate, not a production default: leave it off in production, matching the
`LogPolicy` that keeps raw handshake data and transcript digests out of production logs. The event
surface is what kroopt commits to today (tested, secret-free); the wired counters move internally but
are not yet exported; histograms/aggregation/export are the planned operability follow-on. Neither ever
exposes a secret, and that property is enforced by the type system,
not by reviewer vigilance alone.
