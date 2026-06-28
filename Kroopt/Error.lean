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
  | noApplicationProtocol
  | internalError
  | userCanceled
  deriving DecidableEq, Repr, Inhabited

/-- Decode a TLS alert *description* byte (RFC 8446 §6) to a known `AlertDescription`;
`none` for an unrecognised code. Used to record an inbound peer alert; the close-notify
code (`0`) is handled by the caller before this is consulted. -/
def AlertDescription.ofByte : UInt8 → Option AlertDescription
  | 0   => some .closeNotify
  | 10  => some .unexpectedMessage
  | 20  => some .badRecordMac
  | 22  => some .recordOverflow
  | 40  => some .handshakeFailure
  | 47  => some .illegalParameter
  | 50  => some .decodeError
  | 51  => some .decryptError
  | 70  => some .protocolVersion
  | 80  => some .internalError
  | 90  => some .userCanceled
  | 109 => some .missingExtension
  | 110 => some .unsupportedExtension
  | 120 => some .noApplicationProtocol
  | _   => none

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
  | noApplicationProtocol
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
  /-- A peer-supplied key_share that passed wire-shape parsing but was rejected by the
  crypto provider (e.g. an off-curve / point-at-infinity P-256 point). This is attacker-
  controlled handshake input, **not** a server fault, so it maps to `illegal_parameter`
  rather than `internal_error` (RFC 039 §4.8). -/
  | peerInvalidKeyShare
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
