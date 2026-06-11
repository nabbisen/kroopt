# Alerts, close_notify, and terminal policy

M9 makes the close and alert behaviour explicit and proved (RFC 013). TLS close
semantics are security-sensitive: kroopt must not emit plaintext after close,
must not accept application writes after a fatal alert, and must never let a
transport truncation masquerade as a clean close.

## Centralized, deterministic alert mapping

Every failure routes its alert through one place — `Kroopt.Core.Alert`. The
alert that goes on the wire is a documented function of the error *class* and
nothing else: no secret, no attacker-controlled bytes, no fine-grained parser
detail leaks through the choice of alert. `alertForParseError` and
`alertForProtocolError` are total and deterministic; `alertForCryptoFailure`
returns `none` for genuinely internal failures so the connection aborts without
disclosing why, while an adversarial bad tag maps to `bad_record_mac`.

Two facts are proved: a parse error is **always fatal** and **never**
`closeNotify` (`alertForParseError_is_fatal`, `alertForParseError_not_closeNotify`),
and a protocol error is fatal unless it is precisely "peer sent close_notify"
(`alertForProtocolError_fatal_unless_close`). So a malformed input can never be
mistaken by the peer for a clean shutdown.

## Explicit close states and per-mode close

The connection's `CloseState` is explicit: `open`, `sentCloseNotify`,
`receivedCloseNotify`, `transportEofBeforeCloseNotify`, `fatalSent`,
`fatalReceived`, `transportClosed`. The three application close modes are
distinct (RFC 013 §5): **graceful** moves to `closing`/`sentCloseNotify` and
asks the interpreter to send close_notify best-effort before closing; **fatal**
moves to `failed`/`fatalSent` and emits the alert — which is the only
post-failure transport write permitted; **abortive** moves straight to
`closed`/`transportClosed` with no alert. Repeated close is idempotent: once a
close is in progress the transport close is simply re-issued without regressing
the state.

## Truncation is not a clean close

Transport EOF before a close_notify is a *truncation failure*, not graceful
end-of-stream (RFC 013 §6): in `connected` state it moves to `failed` with
`transportEofBeforeCloseNotify`, and `recv` surfaces it as an error rather than a
clean `eof`. A peer close_notify, by contrast, is an authenticated inbound alert
record that moves to `receivedCloseNotify`; after the buffered plaintext drains,
`recv` returns `eof`.

## Terminal discipline, proved

After any terminal transition the state is absorbing — no further plaintext is
emitted or accepted, and nothing but the optional fatal alert is written. The new
proofs complement the M0 action-discipline theorems: `failAlert_no_emit`,
`failAlert_no_accept`, and `failAlert_only_alert_write` (the fatal path's only
wire effect is its alert), and `appClose_no_emit` (beginning a close, in any
mode, emits no application plaintext).
