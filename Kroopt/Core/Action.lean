import Kroopt.Error
import Kroopt.Core.Id
import Kroopt.Core.Common
import Kroopt.Core.CipherSuite
import Kroopt.Core.Crypto
import Kroopt.Core.Cert

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

/-- A typed server-flight handshake message: the core supplies the protocol *facts*
and the interpreter realizes the byte layout (RFC 032 §3–4). The byte fields are
representation-level (e.g. an ALPN protocol id) so this stays in the low-level action
module without importing the config/negotiation layer. Slice 1 covers
EncryptedExtensions; the remaining server-flight messages migrate as their
crypto-result plumbing lands. -/
inductive HandshakeOut where
  /-- ServerHello carrying the server Random, the server's x25519 key_share, and the
  negotiated cipher suite / group / selected version as wire code points. All values are
  core-held (RFC 032): the Random is drawn via a core `randomBytes` op, the share comes from
  the ECDHE result, and the suite/group are the core's negotiation result. -/
  | serverHello (random : ByteArray) (share : ByteArray)
                (suite : UInt16) (group : UInt16) (version : UInt16)
  /-- EncryptedExtensions carrying the negotiated ALPN protocol id, if any. -/
  | encryptedExtensions (alpn : Option ByteArray)
  /-- CertificateVerify carrying the negotiated signature scheme (wire code point) and
  the signature produced by the core's `signCertificateVerify` crypto result. -/
  | certificateVerify (scheme : UInt16) (signature : ByteArray)
  /-- Finished carrying the server Finished verify_data computed by the core's
  `computeServerFinished` crypto op (RFC 8446 §4.4.4). -/
  | finished (verifyData : ByteArray)

/-- Actions the core asks the interpreter to perform (RFC 002 §3). -/
inductive OutputAction where
  /-- Read from the transport. -/
  | readTransport (conn : ConnId)
  /-- Queue ciphertext the core has authorised for transport write. -/
  | writeTransport (conn : ConnId) (b : ByteArray)
  /-- Emit a typed server-flight handshake message; the interpreter serializes it
  (RFC 032). No production path dispatches on the message's first byte. -/
  | writeHandshake (conn : ConnId) (epoch : Epoch) (seq : UInt64) (msg : HandshakeOut)
  /-- Emit the server Certificate from a configured chain *handle* (RFC 032 §4). The
  core holds only the opaque handle; the interpreter resolves it to DER and serializes,
  so the DER never enters the pure core. -/
  | writeCertificate (conn : ConnId) (epoch : Epoch) (seq : UInt64) (chain : CertificateChainHandle)
  /-- Register write interest with the transport. -/
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
  /-- Close the transport. -/
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

@[simp] theorem isPlaintextEmit_writeHandshake (c : ConnId) (e : Epoch) (s : UInt64) (m : HandshakeOut) :
    isPlaintextEmit (writeHandshake c e s m) = false := rfl

@[simp] theorem isOrdinaryTransportWrite_writeHandshake (c : ConnId) (e : Epoch) (s : UInt64) (m : HandshakeOut) :
    isOrdinaryTransportWrite (writeHandshake c e s m) = false := rfl

@[simp] theorem isPlaintextEmit_writeCertificate (c : ConnId) (e : Epoch) (s : UInt64) (h : CertificateChainHandle) :
    isPlaintextEmit (writeCertificate c e s h) = false := rfl

@[simp] theorem isOrdinaryTransportWrite_writeCertificate (c : ConnId) (e : Epoch) (s : UInt64) (h : CertificateChainHandle) :
    isOrdinaryTransportWrite (writeCertificate c e s h) = false := rfl

/-- If an action is classified as a plaintext emit, it is literally an
`emitPlaintext`. Lets proofs reduce "emits plaintext" to a membership fact about
that one constructor. -/
theorem isPlaintextEmit_eq_true {a : OutputAction} (h : a.isPlaintextEmit = true) :
    ∃ (c : ConnId) (b : ByteArray), a = emitPlaintext c b := by
  cases a <;> first | exact ⟨_, _, rfl⟩ | simp [isPlaintextEmit] at h

end OutputAction

end Kroopt.Core
