import Kroopt.Error

/-!
# Kroopt.Core.Alert

The single, centralized, deterministic mapping from internal error categories to
TLS `AlertDescription`s (RFC 013 §4). Every failure path routes its alert through
one of these functions, so the alert sent on the wire is a documented function of
the error class and nothing else — no secret, no attacker-controlled bytes, no
high-resolution parser detail leaks through the choice of alert (RFC 013 §8, §9).

Two safety facts about this mapping are proved in `Kroopt.Proofs.Closure`:

* error alerts are always **fatal** — a parse/protocol error never produces the
  benign `closeNotify` (which would mislead the peer into thinking the connection
  closed cleanly);
* internal/secret-bearing crypto failures map to **no** detailed alert (the
  connection aborts without disclosing why).
-/

namespace Kroopt.Core

open Kroopt (AlertDescription AlertLevel ProtocolError ParseError CryptoError ResourceLimitError)

/-- The level of an alert. In TLS 1.3 only `closeNotify` (and the rarely used
`userCanceled`) are warnings; every other alert is fatal. -/
def alertLevel : AlertDescription → AlertLevel
  | .closeNotify  => .warning
  | .userCanceled => .warning
  | _             => .fatal

/-- Map a protocol error to its alert (RFC 013 §4, external design §13.4).
Deterministic and total. -/
def alertForProtocolError : ProtocolError → AlertDescription
  | .unsupportedVersion            => .protocolVersion
  | .unsupportedCipherSuite        => .handshakeFailure
  | .unsupportedGroup              => .handshakeFailure
  | .unsupportedSignatureScheme    => .handshakeFailure
  | .missingRequiredExtension      => .missingExtension
  | .duplicateExtension            => .illegalParameter
  | .illegalMessageForState        => .unexpectedMessage
  | .unexpectedPostHandshakeMessage => .unexpectedMessage
  | .badFinished                   => .decryptError
  | .closeNotifyReceived           => .closeNotify
  | .sequenceOverflow              => .internalError

/-- Map a parser error to its alert (RFC 013 §4). Categories only — never the
offending bytes. Deterministic and total; no parse error is benign. -/
def alertForParseError : ParseError → AlertDescription
  | .truncated         => .decodeError
  | .trailingBytes     => .decodeError
  | .lengthOverflow    => .decodeError
  | .valueOutOfRange   => .illegalParameter
  | .oversizedRecord   => .recordOverflow
  | .malformedVector   => .decodeError
  | .malformedExtension => .decodeError
  | .invalidContentType => .unexpectedMessage
  | .invalidDer        => .decodeError

/-- Map a crypto failure to an alert, if any (RFC 013 §4). Adversarial outcomes
(a bad AEAD tag / bad Finished) map to `badRecordMac`; genuinely internal
failures abort with **no** detailed alert, so nothing about key state leaks. -/
def alertForCryptoFailure : CryptoError → Option AlertDescription
  | .authFailed           => some .badRecordMac
  | .unsupportedOperation => some .handshakeFailure
  | .invalidHandle        => none
  | .randomFailed         => none
  | .providerInternal     => none

/-- The alert for an unexpected message in a given phase (RFC 013 §4). The phase
is not currently needed to choose the alert, but the signature documents the
intent and leaves room for refinement. -/
def alertForUnexpectedMessage : AlertDescription := .unexpectedMessage

/-- Map a resource-budget exhaustion to an alert (RFC 013 §4, external design §13.4).
Budget exhaustion is attacker-induced rather than a protocol-negotiation outcome; the
alert is uniformly the generic `internalError` so it leaks neither which budget was hit
nor any high-resolution detail (consistent with `sequenceOverflow`). Always fatal. -/
def alertForResourceLimit : ResourceLimitError → AlertDescription
  | _ => .internalError

end Kroopt.Core
