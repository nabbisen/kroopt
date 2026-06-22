/-!
# Kroopt.Error

Public error and alert taxonomy (RFC 013 §13, RFC 002).

Every error here is a plain enumeration. By construction these types carry **no**
secret material, no plaintext, and no raw attacker-controlled bytes — only
coarse categories (RFC 018 data classification; RFC 020 redaction). That keeps
`TlsError` safe to log, return to a consumer, and derive `Repr` on.
-/

namespace Kroopt

/-- TLS 1.3 alert descriptions kroopt may send or receive. The set is
deliberately small: kroopt maps internal failures onto a few generic alerts so
the wire behaviour leaks no high-resolution parser detail (RFC 013 §4). -/
inductive AlertDescription where
  | closeNotify
  | unexpectedMessage
  | badRecordMac
  | recordOverflow
  | handshakeFailure
  | illegalParameter
  | decodeError
  | decryptError
  | protocolVersion
  | missingExtension
  | unsupportedExtension
  | internalError
  | userCanceled
  deriving DecidableEq, Repr, Inhabited

/-- Alert level. In TLS 1.3 almost every alert is fatal; `closeNotify` is the
sole routine warning. -/
inductive AlertLevel where
  | warning
  | fatal
  deriving DecidableEq, Repr, Inhabited

/-- Protocol-level failures: illegal messages, unsupported parameters, MAC
failures, sequence overflow. Attacker-influenced but not secret. -/
inductive ProtocolError where
  | unsupportedVersion
  | unsupportedCipherSuite
  | unsupportedGroup
  | unsupportedSignatureScheme
  | missingRequiredExtension
  | duplicateExtension
  | illegalMessageForState
  | unexpectedPostHandshakeMessage
  | badFinished
  | closeNotifyReceived
  | sequenceOverflow
  deriving DecidableEq, Repr, Inhabited

/-- Parser failures. Categories only; never the offending bytes (RFC 003 §10). -/
inductive ParseError where
  | truncated
  | trailingBytes
  | lengthOverflow
  | valueOutOfRange
  | oversizedRecord
  | malformedVector
  | malformedExtension
  | invalidContentType
  | invalidDer
  deriving DecidableEq, Repr, Inhabited

/-- Crypto-provider failures. `authFailed` (AEAD open / bad Finished) is an
expected adversarial outcome and is kept distinct from internal failures so the
alert mapping is deterministic (RFC 008 §7). -/
inductive CryptoError where
  | authFailed
  | unsupportedOperation
  | invalidHandle
  | randomFailed
  | providerInternal
  deriving DecidableEq, Repr, Inhabited

/-- Configuration-validation failures (RFC 011, 021). -/
inductive ConfigError where
  | noCipherSuite
  | certKeyMismatch
  | emptyChain
  | oversizedDer
  | ambiguousSni
  | invalidAlpn
  | capabilityMissing
  deriving DecidableEq, Repr, Inhabited

/-- Resource-budget exhaustion (RFC 019). Treated as a security failure, not a
routine backpressure event. -/
inductive ResourceLimitError where
  | handshakeBytes
  | clientHelloBytes
  | extensionCount
  | extensionBytes
  | recordSize
  | pendingCiphertext
  | pendingCryptoOps
  | progressSteps
  | handshakeTimeout
  deriving DecidableEq, Repr, Inhabited

/-- Transport-layer failures surfaced from the transport. `eofBeforeCloseNotify` is the
truncation condition that must never be treated as a clean close (RFC 013 §6). -/
inductive TransportError where
  | eofBeforeCloseNotify
  | resetByPeer
  | brokenPipe
  | generic
  deriving DecidableEq, Repr, Inhabited

/-- The single public error category exposed to dependents (RFC 013 §1). Typed,
coarse, and redaction-safe. -/
inductive TlsError where
  | protocol (e : ProtocolError)
  | parse (e : ParseError)
  | crypto (e : CryptoError)
  | config (e : ConfigError)
  | resourceLimit (e : ResourceLimitError)
  | transport (e : TransportError)
  | closed
  | internalInvariantFailure
  deriving DecidableEq, Repr, Inhabited

namespace TlsError

/-- Coarse public category string for redacted logging (RFC 020 §6). Never
includes payloads. -/
def category : TlsError → String
  | protocol _              => "protocol"
  | parse _                 => "parse"
  | crypto _                => "crypto"
  | config _                => "config"
  | resourceLimit _         => "resource_limit"
  | transport _             => "transport"
  | closed                  => "closed"
  | internalInvariantFailure => "internal_error"

end TlsError

end Kroopt
