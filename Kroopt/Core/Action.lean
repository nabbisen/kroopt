import Kroopt.Error
import Kroopt.Core.Id
import Kroopt.Core.Common
import Kroopt.Core.CipherSuite
import Kroopt.Core.Crypto

/-!
# Kroopt.Core.Action

The output actions the pure core emits (RFC 002 §3, requirements §7.3).

Every side effect visible outside the core is one of these actions; the
interpreter executes them in order and never decides protocol behaviour itself
(RFC 002 §5). The classifier predicates at the bottom (`isPlaintextEmit`,
`isOrdinaryTransportWrite`, `isCryptoCall`) are what the structural proofs in
`Kroopt.Proofs` quantify over.

No `Repr` is derived: actions carry `ByteArray` (plaintext / ciphertext) and
`SecretKeyHandle`, which must not be printable (RFC 018).
-/

namespace Kroopt.Core

open Kroopt (TlsError AlertDescription)

/-- Public handshake-completion metadata reported to the application (RFC 006 §8).
SNI/ALPN byte values are added at M8; M0 reports the cryptographic selection. -/
structure HandshakeInfo where
  suite : CipherSuite
  configGen : ConfigGeneration
  deriving Repr, Inhabited

/-- Actions the core asks the interpreter to perform (RFC 002 §3). -/
inductive OutputAction where
  /-- Read from the transport. -/
  | readTransport (conn : ConnId)
  /-- Queue ciphertext the core has authorised for transport write. -/
  | writeTransport (conn : ConnId) (b : ByteArray)
  /-- Register write interest with iotakt. -/
  | enableWriteInterest (conn : ConnId)
  /-- Drop write interest (queue empty). -/
  | disableWriteInterest (conn : ConnId)
  /-- Perform a crypto operation; the result re-enters as `cryptoResult`. -/
  | callCrypto (conn : ConnId) (op : OperationId) (request : CryptoOp)
  /-- Deliver authenticated application plaintext to the caller. -/
  | emitPlaintext (conn : ConnId) (b : ByteArray)
  /-- Acknowledge ownership of `n` plaintext bytes accepted from the caller. -/
  | acceptPlaintextBytes (conn : ConnId) (n : Nat)
  /-- Report the handshake completed, with negotiated metadata. -/
  | reportHandshakeComplete (conn : ConnId) (info : HandshakeInfo)
  /-- Report a typed, redacted error to the caller. -/
  | reportError (conn : ConnId) (e : TlsError)
  /-- Fail terminally and (best-effort) send a fatal alert. -/
  | failWithAlert (conn : ConnId) (a : AlertDescription)
  /-- Close the transport through iotakt. -/
  | closeTransport (conn : ConnId) (mode : CloseMode)
  /-- Release (and best-effort zeroize) a secret handle. -/
  | releaseSecret (handle : SecretKeyHandle)

namespace OutputAction

/-- An action that delivers application plaintext to the caller. The central
proof target: this must never appear unless the core is `connected`
(RFC 002 §7, RFC 015 §15.1). -/
def isPlaintextEmit : OutputAction → Bool
  | emitPlaintext _ _ => true
  | _                 => false

/-- An ordinary (non-alert) transport write. After a terminal transition the
only permitted transport write is a pre-decided fatal alert / close_notify, not
an ordinary `writeTransport` (RFC 013 §7). -/
def isOrdinaryTransportWrite : OutputAction → Bool
  | writeTransport _ _ => true
  | _                  => false

/-- A crypto request. Used to state direction/epoch-consistency obligations
(RFC 005 §7.4–§7.5). -/
def isCryptoCall : OutputAction → Bool
  | callCrypto _ _ _ => true
  | _                => false

/-- Whether an action accepts caller plaintext into kroopt ownership. Gated to
`connected` alongside `emitPlaintext` (RFC 002 §7). -/
def isPlaintextAccept : OutputAction → Bool
  | acceptPlaintextBytes _ _ => true
  | _                        => false

@[simp] theorem isPlaintextEmit_emit (c : ConnId) (b : ByteArray) :
    isPlaintextEmit (emitPlaintext c b) = true := rfl

@[simp] theorem isPlaintextEmit_readTransport (c : ConnId) :
    isPlaintextEmit (readTransport c) = false := rfl

@[simp] theorem isPlaintextEmit_writeTransport (c : ConnId) (b : ByteArray) :
    isPlaintextEmit (writeTransport c b) = false := rfl

@[simp] theorem isPlaintextEmit_failWithAlert (c : ConnId) (a : AlertDescription) :
    isPlaintextEmit (failWithAlert c a) = false := rfl

@[simp] theorem isPlaintextEmit_reportError (c : ConnId) (e : TlsError) :
    isPlaintextEmit (reportError c e) = false := rfl

@[simp] theorem isPlaintextEmit_closeTransport (c : ConnId) (m : CloseMode) :
    isPlaintextEmit (closeTransport c m) = false := rfl

end OutputAction

end Kroopt.Core
