# RFC 041 — Fatal-alert wire transmission

**Status.** Proposed — *plaintext (`initial`-epoch) transmission landed in 0.111.0-dev;
the protected (`handshake`/`application`-epoch) seal paths remain, after which this RFC
moves to `done/`.*
**Tracks.** Making fatal TLS alerts observable by the peer (RFC 8446 §6). Closes the
fidelity gap identified in the 0.107–0.109 implementation review: kroopt currently
*classifies* fatal alerts but does not transmit an alert record.
**Touches.** `Kroopt/Error.lean` (an `AlertDescription` encoder), `Kroopt/Core/Step.lean`
and/or `Kroopt/Core/RecordPath.lean` (emitting an alert record as a core action),
`Kroopt/Conn/Interpreter.lean` (the `failWithAlert` handler), `Kroopt/Proofs/*`
(terminal-write discipline), `Tests/*` (wire-level alert tests), and the alert/close docs.

## Summary

Today the interpreter terminates on the `failWithAlert` action **without writing an alert
record**: `| .failWithAlert _ _ => (terminate rt, tr, [])`. The only alert kroopt puts on the
wire is `close_notify` (description 0), on graceful close; there is no outbound
`AlertDescription → byte` encoder. Consequently every fatal failure —
`no_application_protocol` (120), `handshake_failure` (40), `decode_error` (50),
`bad_record_mac` (20), … — is *classified* (recorded in `closeState := fatalSent _`,
surfaced as a typed `reportError`, counted by `alertsClassified`, traced as
`alert-classified`) and the connection then terminates. A peer observes connection
termination, not a standards-shaped fatal alert.

This is acceptable as a security posture (failing closed leaks nothing), but it does not
satisfy the RFC 8446 §6.2 expectation that a fatal error is signalled with an alert, and it
makes kroopt's behaviour less diagnosable for peers and operators. This RFC defines the
design to transmit fatal alerts where possible, for **all** fatal alerts (not only ALPN
`no_application_protocol`), while preserving every existing safety property.

This is a self-contained follow-up; it does **not** change any negotiation policy. The ALPN
strict no-overlap policy (0.109) already fails before any server flight; this RFC only adds a
best-effort outbound alert record on that and every other fatal edge.

## Motivation

- **Standards alignment.** RFC 8446 §6 defines `Alert` records and §6.2 expects a fatal
  alert before closing on most error conditions. Mainstream peers log the received alert;
  its absence shows up only as an opaque connection reset.
- **Integration honesty.** The 0.109 review withheld "complete A1" precisely because alert
  120 is not transmitted. jemmet (and any consumer who needs the peer to *observe*
  `no_application_protocol`) cannot rely on the current behaviour.
- **Operator diagnosis.** A transmitted alert tells the *other* side why the handshake
  failed; today only kroopt's own logs carry the reason.

## Non-goals

- No change to which alert each error *class* maps to (`Kroopt.Core.Alert` is unchanged).
- No change to negotiation, parsing, or the no-overlap/`hsFail` policy.
- No retransmission, alert acknowledgement, or post-alert read draining beyond what TLS 1.3
  requires (a fatal alert is immediately terminal).

## Design

### 1. Alert description encoder

Add the inverse of `AlertDescription.ofByte`:

```lean
def AlertDescription.toByte : AlertDescription → UInt8
```

Total, the exact inverse of `ofByte` on the descriptions kroopt produces (e.g.
`closeNotify → 0`, `handshakeFailure → 40`, `badRecordMac → 20`, `decodeError → 50`,
`illegalParameter → 47`, `noApplicationProtocol → 120`, …). A round-trip lemma
`ofByte (toByte a) = some a` for every constructor is the encoder's acceptance proof, and the
existing `alertNoApplicationProtocolRoundTrips120` test becomes a genuine encode+decode
round-trip rather than a decode + level check.

### 2. Alert record construction (a core action, not interpreter logic)

The alert that goes on the wire must be decided by the **core** (so the proof/runtime
correspondence holds) and merely executed by the interpreter. Replace the information-free
`failWithAlert` action's wire effect with a core-emitted alert **record**:

- **Before any write keys are installed** (initial epoch — the ALPN no-overlap case, and most
  early handshake failures): the alert is a **plaintext** `Alert` record
  (`TLSPlaintext`, content type `alert`, body `[level, description] = [2, toByte a]` for a
  fatal alert).
- **After application (or handshake) write keys are installed**: the alert is a **protected**
  record sealed under the current write epoch, exactly like any other outbound record (one
  AEAD `seal`, sequence number advances per the existing record discipline).
- **If write keys are required but unavailable / sealing is not possible**: emit no record and
  terminate (the current behaviour), rather than sending a malformed or unprotected alert in a
  protected epoch.

The core therefore emits, on a fatal edge, either a `writeTransport`/seal action carrying the
alert record followed by `closeTransport`, or (when no record can be formed) just
`closeTransport` — never application plaintext, never a secret.

### 3. Interpreter behaviour

`failWithAlert` stops being a silent `terminate`. The interpreter executes the core-authorized
alert record exactly as it executes any other authorized outbound bytes: append to the
outbound queue, attempt `Transport.send`, then close. It performs **no** protocol decision and
constructs **no** alert bytes itself — it only drains what the core authorized.

### 4. Partial write / backpressure

A fatal alert is best-effort (RFC 013 §… alert-delivery policy already says so). The drain
follows the existing partial-write pattern: if the transport returns `wouldBlock`, the alert
bytes remain queued and the connection still proceeds to terminate within the close budget
(`closeNotifyTimeoutMs`-style bound). Delivery is never allowed to block termination or to
reopen application data flow.

### 5. Interaction with `reportError` and `terminate`

`reportError` (the typed, redacted error to the caller) and `closeState := fatalSent _` are
unchanged — they are kroopt-internal classification and remain the source of truth for metrics
and the consumer. The new alert record is the *peer-facing* counterpart. Ordering on a fatal
edge: emit the alert record (best-effort send), `reportError`, `closeTransport`/`terminate`.
The `alertsClassified` counter and `alert-classified` trace event are renamed/retired to
`alertsSent` / `alert-out` **only once this RFC lands** (so the names regain their accurate
meaning); until then they stay as classification names.

## Proof obligations

1. **Terminal-write discipline.** After a terminal state, the *only* permitted outbound write
   is the single fatal-alert record (and the existing `close_notify` on graceful close); no
   application plaintext is emitted or accepted after the alert. Extends the existing
   `failAlert_*` / closure theorems from "only `failWithAlert`+`reportError` actions" to "the
   added write is exactly the alert record."
2. **No secret / no plaintext in the alert.** The alert record body is `[level, description]`
   with `description = toByte a` (public) — it contains no key material, transcript, or
   attacker-controlled bytes. (When protected, it is sealed like any record; the *plaintext*
   carries only the two public bytes.)
3. **No flight on the no-overlap edge.** Unchanged and still proved: ALPN `noOverlap` produces
   no ServerHello / random / application data — now plus exactly one alert record.
4. **Encoder round-trip.** `ofByte (toByte a) = some a` for every produced description.

## Tests

- `no_application_protocol` writes a fatal alert record with byte 120 when the failure occurs
  before write keys are installed.
- `handshake_failure` / `illegal_parameter` / `decrypt_error` / `bad_record_mac` similarly
  write their correct description byte.
- A failure *after* application keys are installed writes a **protected** alert record.
- After the alert, no further application data is accepted or emitted (terminal).
- If the alert write cannot complete (`wouldBlock` / no keys), the connection still terminates
  safely and no malformed/unprotected alert is sent in a protected epoch.
- Live interop: a peer (OpenSSL `s_client`) observing a forced fatal handshake failure logs
  the expected alert.

## Acceptance criteria

1. `AlertDescription.toByte` exists with the round-trip proof.
2. Fatal alerts are transmitted best-effort for all fatal edges, plaintext or protected per
   the installed write epoch, decided by the core and only drained by the interpreter.
3. All proof obligations above discharge; the axiom audit stays within the allowed set with no
   `sorryAx`.
4. The wire-level alert tests and a live-interop observation pass.
5. The alert/close and metric/trace docs are updated to state that fatal alerts are now
   transmitted, and the `alertsClassified`/`alert-classified` names are revised to `alertsSent`
   / `alert-out` (or kept, if the project prefers to distinguish "classified" from "sent" for
   the unprotected-impossible case).

## Open questions

1. Whether to keep a distinct `alertsClassified` counter (alerts the core produced) separate
   from an `alertsSent` counter (alerts actually drained to the transport), since best-effort
   delivery means the two can differ under backpressure.
2. Whether a fatal alert in a protected epoch should be flushed synchronously before close or
   may be abandoned under severe backpressure (TLS permits either; pick the simpler safe one).

## References

- RFC 8446 §6 (Alert protocol), §6.2 (Error alerts).
- kroopt RFC 013 (alerts, close, terminal policy).
- 0.107–0.109 implementation review (fidelity point 5.1).
