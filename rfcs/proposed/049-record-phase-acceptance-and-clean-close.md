# RFC 049 — Record-Phase Acceptance and Clean-Close Semantics

**Project.** kroopt  
**Status.** Proposed  
**Type.** Blocking protocol/security fix  
**Target milestone.** AR1  
**Requires completion of.** [RFC 004](../done/004-tls13-record-model.md), [RFC 006](../done/006-handshake-state-model-no-hrr.md), [RFC 013](../done/013-alerts-close-and-terminal-policy.md), [RFC 033](../done/033-real-client-handshake-processing.md), [RFC 041](../done/041-fatal-alert-wire-transmission.md)  
**Touches.** record parser/path, close state, public `TlsConn.recv`, proofs and negative tests  

## Review finding

Architecture review B5 found that several plaintext/protected record and inner-content combinations are
silently ignored even though the supported profile requires fatal rejection. Plaintext alerts can be
accepted after protection is required, record legacy version is not enforced, and the public graceful EOF
result is not reliably reachable.

## Decision

The core owns an explicit total acceptance matrix indexed by handshake phase, read epoch, outer record type,
and authenticated inner content type. Every cell is `accept`, narrowly `ignore` where RFC 8446 permits it
(compatibility CCS window only), or `fail(alert)`. No default ignore branch exists.

`close_notify` produces a durable clean-peer-close state. Buffered authenticated plaintext drains first;
then `TlsConn.recv` returns `.eof` idempotently without later reclassifying the close as truncation.

## Total acceptance matrix

`fatal` means a deterministic fatal alert where the epoch permits transmission, followed by terminal state
and no plaintext release. The implementation must encode this as a total core function; the table is its
review contract, not an illustrative subset.

| Core phase / read epoch | Outer record and authenticated inner type | Decision |
|---|---|---|
| awaiting ClientHello / initial | plaintext `handshake` containing exactly the expected ClientHello | accept |
| awaiting ClientHello / initial | well-formed plaintext fatal `alert` | accept as terminal peer alert; release no plaintext |
| awaiting ClientHello / initial | plaintext `close_notify`, CCS, application data, protected record, or any other type | fatal `unexpected_message` |
| ClientHello accepted through peer Finished / handshake | protected `application_data` with expected handshake inner message | accept |
| ClientHello accepted through peer Finished / handshake | protected `application_data` with fatal-alert inner type | accept as terminal peer alert |
| ClientHello accepted through peer Finished / handshake | protected close-notify, application-data inner type, KeyUpdate, post-handshake auth, or unexpected handshake message | fatal `unexpected_message` |
| ClientHello accepted through peer Finished / handshake | plaintext handshake or alert | fatal `unexpected_message` |
| ClientHello accepted through peer Finished / handshake | exact compatibility CCS (`0x01`) in the RFC 8446 window | ignore; the only ignore cell |
| ClientHello accepted through peer Finished / handshake | malformed/out-of-window CCS or any other outer type | fatal `unexpected_message` |
| connected / application | protected application-data inner type | accept and release authenticated plaintext |
| connected / application | protected `close_notify` | enter clean-peer-close; drain already-buffered plaintext, then `.eof` |
| connected / application | protected fatal alert | accept as terminal peer alert; release no later plaintext |
| connected / application | protected handshake (including KeyUpdate/post-handshake auth), CCS inner type, or unknown inner type | fatal `unexpected_message` |
| connected / application | any plaintext handshake, alert, CCS, application-data misuse, or other outer type | fatal `unexpected_message` |
| clean-closing | already-authorized buffered plaintext | drain only; do not accept new application plaintext |
| clean-closing | any new record | fatal if output remains legal, otherwise terminal error; `.eof` is retained |
| fatal/closed | any input | terminal idempotent no-op with no parsing, output, state revival, or plaintext |

The record legacy version is `0x0303` for TLS 1.3 records, except the first ClientHello record may use
`0x0301` as permitted by RFC 8446. Every other value fails before phase dispatch. Fragmentation/reassembly
may split an expected handshake message across valid records but cannot change the matrix decision for its
eventual message type.

## Work breakdown

1. Define the acceptance matrix and deterministic alert mapping in the core.
2. Validate TLS 1.3 record `legacy_record_version` and size before phase dispatch.
3. Reject unexpected post-handshake messages, including KeyUpdate and post-handshake auth.
4. Reject plaintext handshake/alert records after protection becomes mandatory.
5. Reject protected records in unsupported pre-connected phases.
6. Make inbound fatal alerts one-way terminal and clean close-notify a distinct EOF path.
7. Prove terminal/no-plaintext properties across every rejection cell.

## Acceptance criteria

1. Negative tests cover every matrix cell relevant to the supported profile.
2. KeyUpdate, unexpected handshake, plaintext alert after ServerHello, bad legacy version, and premature
   protected application data fail with specified alerts and no plaintext.
3. The compatibility CCS exception is accepted only in its exact permitted window and shape.
4. Public `TlsConn.recv` returns `.eof` after authenticated close-notify and buffered data drain.
5. Truncation without close-notify remains an error.
6. Core proofs and live external-client graceful-close tests are canonical-gate evidence.

## Non-goals

KeyUpdate, post-handshake authentication, half-close extensions, and TLS 1.2 remain unsupported.
