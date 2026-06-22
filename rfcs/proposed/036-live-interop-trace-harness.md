# RFC 036 — Live Interop Trace Harness and Captured-Client Replay

**Project.** kroopt  
**Status.** Proposed — **§3 trace facility (first slice) landed (0.89.0-dev):** a pure,
secret-free-by-construction trace projection `Kroopt.Conn.traceOfAction : OutputAction → Option
TraceEvent` plus `TraceEvent.render`, where every byte-bearing action projects to a *length* and
every secret reference to a bare event, so no rendered line can carry plaintext, ciphertext, DER, a
transcript digest, or a secret handle (`Tests.Trace`, 19 checks, including sentinel-leak negatives).
**Malformed/edge corpus landed (0.94.0-dev):** the captured-CH corpus now spans constrained + broad +
malformed (no key_share, duplicated `supported_versions`, only-unsupported group), each replaying to a
deterministic rejection (`failed illegal_parameter`, no partial flight) through the full pure/fake
path — acceptance criterion 1 is met (`Tests.Replay`, 18 checks). **GREASE tolerance verified
(0.95.0-dev):** unknown/reserved values alongside valid ones (a GREASE named group and a GREASE cipher
suite) are *ignored* per RFC 8701 (x25519 / aes128GcmSha256 selected, full flight) — a browser-grade
prerequisite, now tested. **Live curl + graceful close added (0.95.0-dev):** the interop harness now
drives a third independent client (curl HTTPS GET against the reactor `http` mode) and explicitly
observes a graceful `close_notify` (RFC 8446 §6.1), so the constrained live set covers handshake +
data + **close** + rejection across OpenSSL, Python, and curl. **Architect-approved close-out plan
(B / committed-canonical / +close +curl / verify-GREASE):** RFC 036 locks on criteria 1, 2, and 4;
durable live-transcript *archival* (committed kroopt-side secret-free canonical traces + ephemeral raw
client witnesses) is relocated to M38 as CI/milestone infrastructure. Remaining before lock: the
criterion-4 docs page (`docs/src/interop/constrained-vs-browser-grade.md`) and the in-RFC re-scope note
recording the M38 relocation. **`debug_trace` interpreter wiring landed (0.93.0-dev):**
the interpreter's action fold (`Conn.Interpreter.execActions`) now records a secret-free
`TraceEvent` line per executed action into `RuntimeState.trace` when `traceEnabled` is set — off by
default (never on in production), so a real handshake under the gate produces a populated trace
(crypto-op / handshake-message / certificate events) and produces none when off; verified in
`Tests.Replay`. **Committed real captures landed (0.92.0-dev):** genuine
TLS 1.3 ClientHello records from `openssl s_client` (broad + a `-ciphersuites CHACHA20`-constrained
one) and Python `ssl` (broad, carrying SNI `example.com`) are committed to `Tests.Replay` and
replayed through the verified path with deterministic assertions — the broad captures negotiate
aes256GcmSha384/x25519, the constrained capture honors the client's CHACHA20 constraint
(chacha20Poly1305Sha256/x25519), and a fragmented replay of a real capture reproduces the same
negotiation and flight.

### §2 captured-client replay bridge — first slice landed (0.90.0-dev)

`Tests.Replay` (`kroopt-replay-test`, 7 checks) replays real-shaped ClientHello captures through the
**pure parser + production interpreter over the fake transport** — the path live sockets use, minus
syscalls — with deterministic assertions: a constrained capture negotiates aes128GcmSha256/x25519 and
produces a server flight; the same capture split into 2 and 3 fragments yields a byte-identical
negotiation and flight (reassembly/coalescing); a broad capture that additionally offers
aes256GcmSha384 deterministically negotiates that suite (same client, different offer → different
selection); and a TLS-1.2-only capture is rejected cleanly with no negotiation and no flight (no
downgrade). Captures are sanitized (public randoms/key_shares only) and the server ephemeral is pinned
so the result is reproducible.
**Type.** Implementation RFC  
**Target milestone.** M38 (prep starts during M36 via captured-CH fixtures)  
**Depends on.** RFC 033 (real-client handshake), RFC 020 (observability/redaction), RFC 026 (interop matrix), RFC 015 (E2E acceptance)  
**Touches.** `scripts/`, `Tests/` fixtures, `docs/src/interop.md`, the trace/redaction facility  
**Canonical source.** kroopt fixed requirements §14, §17.7; architect RFC review (recommended RFC 036).  

---

## 1. Summary

Live TLS interop is where real ClientHello diversity, unknown extensions, CCS
compatibility records, timing, partial I/O, and alert differences surface. This RFC adds
the tooling to make that milestone diagnosable and reproducible, and a captured-client
replay bridge that exercises real client bytes through the pure/fake path **before** live
sockets. It may be folded into RFC 026 as an appendix, but is tracked explicitly because
the work is substantial. It is the diagnostic backbone of M38.

## 2. Captured-client replay (bridge, usable from M36)

- Collect real `openssl s_client` / `curl` ClientHello byte captures — both the
  constrained form (`-ciphersuites TLS_CHACHA20_POLY1305_SHA256 -groups X25519
  -sigalgs ed25519`) and a default broad ClientHello — plus a small corpus of
  malformed/edge captures.
- Replay them through the pure parser + fake-transport interpreter (RFC 033 §7), asserting
  deterministic negotiation (broad CH selects the constrained overlap), correct
  fragmentation/coalescing handling, and deterministic alert mapping for rejected captures.
- Store **sanitized** captures as committed test fixtures (no secrets; client randoms and
  key shares are public handshake values and may remain, but nothing secret is stored).

## 3. Trace facility (no secrets)

A `debug_trace`-gated facility records, without secret material:

- inbound record headers; handshake message types and lengths;
- extension IDs and accept/ignore/reject decisions;
- selected cipher suite, group, signature scheme, ALPN, SNI (redacted/hashed per RFC 020);
- state transitions; crypto op ids (not key material);
- transcript hash labels and lengths (not raw secrets);
- alert mapping; read/write readiness events; partial-write counts.

A separate, explicitly **unsafe, local-only** "test secrets export" mode may exist behind
a build flag for deep debugging; it must never be enabled in CI or release artifacts.

## 4. Live interop runs (M38)

- Drive kroopt over the production interpreter (RFC 031) and a simple IO/fake transport,
  then the iotakt adapter (RFC 010) once it lands.
- Capture `openssl s_client -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256
  -groups X25519 -sigalgs ed25519` and constrained `curl` transcripts; confirm successful
  handshake, ALPN/SNI behavior, application-data exchange, `close_notify` behavior, and
  deterministic rejection cases.
- Archive packet/record traces as diagnosis artifacts.

## 5. Constrained vs browser-grade separation

The harness explicitly distinguishes **"constrained OpenSSL/curl green"** (the M38 target)
from **"browser-grade green"** (post-M38, RFC 035). A passing constrained run must not be
reported as browser compatibility.

## 6. Acceptance criteria

1. A captured-CH corpus (constrained + broad + malformed) is committed and replays through
   the pure/fake path with deterministic results.
2. The no-secrets trace facility exists, is `debug_trace`-gated, and applies RFC 020
   redaction; no secrets appear in any default or CI artifact.
3. M38 live runs capture and archive constrained OpenSSL/curl transcripts with the
   expected handshake, data exchange, close, and rejection behaviors.
4. Documentation distinguishes constrained from browser-grade interop.

## 7. Risk

Live runs are timing- and environment-sensitive; the captured-replay bridge de-risks them
by catching most negotiation/parsing failures offline first. Keep the corpus current as
client behavior evolves.
