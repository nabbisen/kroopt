# RFC 013 — Alerts, close_notify, and Terminal Policy

**Project.** kroopt  
**Status.** Implemented (0.24.0-dev)  
**Type.** Implementation RFC  
**Target milestone.** M9  
**Depends on.** RFC 004, RFC 006, RFC 010  
**Touches.** `Kroopt/Core/Alert.lean`; close handling in `Kroopt/Conn/`; `Kroopt/Proofs/Closure.lean`  
**Canonical source.** kroopt fixed requirements and external design.  

---

## 1. Summary

This RFC defines alert mapping, graceful close, fatal termination, transport EOF handling, and terminal-state behavior. TLS close semantics are security-sensitive: kroopt must not emit plaintext after close, must not accept application writes after fatal alerts, and must distinguish graceful `close_notify` from transport truncation.

## 2. Goals

- Define typed alert policy.
- Define graceful close and abortive close behavior.
- Define terminal states and allowed actions.
- Define deterministic error mapping for malformed inputs.
- Define logging redaction for failures.

## 3. State model

```lean
inductive CloseState where
  | open
  | sentCloseNotify
  | receivedCloseNotify
  | bidirectionalClose
  | transportEofBeforeCloseNotify
  | fatalSent AlertDescription
  | fatalReceived AlertDescription
  | transportClosed

inductive TerminalKind where
  | graceful
  | fatal
  | truncation
  | localAbort
  | internalError
```

`HandshakeState.closed` and `HandshakeState.failed` should include enough detail for diagnostics while preserving redaction.

## 4. Alert policy

Define a central mapping:

```lean
def alertForParseError : ParseError -> AlertDescription
def alertForPolicyError : PolicyError -> AlertDescription
def alertForCryptoFailure : CryptoError -> Option AlertDescription
def alertForUnexpectedMessage : HandshakeState -> ContentType -> AlertDescription
```

The mapping must be deterministic and documented. Internal errors may abort without sending a detailed alert if sending could leak information or is impossible.

## 5. Graceful close

Application close intent:

1. Core emits close_notify alert record.
2. Pending ciphertext is flushed within budget.
3. Interpreter calls iotakt closeConnection according to policy.
4. State becomes terminal.

Inbound close_notify:

- no further inbound application plaintext is emitted;
- application may be informed of graceful peer close;
- local close_notify may be sent if not already sent;
- transport close follows policy.

## 6. Transport EOF

Transport EOF before close_notify is a truncation condition unless the state is already terminal in a way that permits EOF. In connected state, EOF without close_notify must not be treated as graceful end-of-stream.

## 7. Terminal action discipline

After terminal state:

- no `emitPlaintext`;
- no application `send` acceptance;
- no new crypto operations except cleanup/release if modeled;
- no ordinary `writeTransport` except previously decided fatal alert/close_notify flushing under strict policy;
- repeated `close` is idempotent.

## 8. Logging and error views

Public errors expose:

- category;
- alert description if sent/received;
- phase;
- redacted peer info;
- config generation;
- no raw secrets;
- no full attacker-controlled messages.

## 9. Security considerations

- Bad AEAD open is fatal and emits no plaintext.
- Bad Finished is fatal.
- Oversize records are fatal.
- Unexpected post-handshake messages are fatal or cleanly rejected by policy.
- A peer close without close_notify is not silently accepted as graceful.

## 10. Tests

- Local graceful close.
- Peer close_notify.
- Simultaneous close behavior.
- EOF before close_notify.
- Fatal alert received.
- Fatal alert sent on parse error.
- Post-terminal send/recv/flush idempotence.
- Redacted error formatting.

## 11. Proof obligations

- Terminal-after-close theorem.
- No plaintext after fatal alert.
- No accepted application send after terminal.
- Optional fatal alert is the only allowed post-failure transport write.

## 12. Acceptance criteria

- Alert mapping is centralized.
- Close states are explicit.
- EOF/truncation is distinguished from graceful close.
- Terminal behavior is proven and tested.
