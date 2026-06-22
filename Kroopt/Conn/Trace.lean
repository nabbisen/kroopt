import Kroopt.Core.Action
import Kroopt.Core.Alert
import Kroopt.Error

/-!
# Kroopt.Conn.Trace — the no-secrets trace facility (RFC 036 §3)

The diagnostic backbone of the live-interop milestone (M38). A `debug_trace`-gated
facility turns the core's authorized `OutputAction` stream into a stream of
**`TraceEvent`** values for diagnosis and archival.

The single load-bearing property is **secret-freedom by construction**: a
`TraceEvent` constructor can hold only *public* protocol data — connection ids,
crypto-op ids and kinds, byte *lengths*, wire code points, alert descriptions,
and close/error *categories*. There is no constructor that can carry plaintext,
ciphertext, certificate DER, a transcript digest, a secret handle, or any
secret bytes. The projection `traceOfAction` therefore cannot leak a secret even
in principle: every byte-bearing action (`writeTransport`, `writeCertificate`,
`emitPlaintext`) projects to a *length*, and every secret reference
(`releaseSecret`, the `callCrypto` request's secret inputs) projects to a bare
event or an op-id, never the bytes.

This facility is emit-only and side-effect-free here; wiring it into the
interpreter behind the `debug_trace` build gate (never on by default, per the
production `LogPolicy`) is a downstream step. Raw attacker-controlled SNI is
never rendered raw — it reaches a trace only after RFC 020 redaction/hashing,
which is upstream of this module.
-/

namespace Kroopt.Conn

open Kroopt (AlertDescription AlertLevel TlsError)
open Kroopt.Core
  (OutputAction HandshakeOut CryptoOpKind CloseMode ConnId Epoch CipherSuite)

/-- A diagnosable event derived from one core-authorized `OutputAction`. Every
field is public: ids, kinds, byte *lengths*, code points, categories. No field
can hold secret bytes, plaintext, DER, a transcript digest, or a secret handle —
secret-freedom is a property of this type's shape, not of a redaction pass. -/
inductive TraceEvent where
  /-- The interpreter was asked to read from the transport. -/
  | transportRead     (conn : ConnId)
  /-- Ciphertext queued for write — its *length* only, never the bytes. -/
  | transportWrite    (conn : ConnId) (length : Nat)
  /-- A typed server-flight handshake message — its *type label* only, never the
  serialized bytes (which include public randoms/shares but are summarized here). -/
  | handshakeOut      (conn : ConnId) (epoch : Epoch) (seq : UInt64) (msg : String)
  /-- The server Certificate — the DER *length* only, never the chain bytes. -/
  | certificateOut    (conn : ConnId) (epoch : Epoch) (seq : UInt64) (derLength : Nat)
  /-- Write interest registered (`true`) or dropped (`false`). -/
  | writeInterest     (conn : ConnId) (enabled : Bool)
  /-- A crypto operation requested — its *op id* and *kind* only, never the
  request's inputs or secret handles. -/
  | cryptoCall        (conn : ConnId) (op : UInt64) (kind : CryptoOpKind)
  /-- Authenticated application plaintext delivered to the caller — its *length*
  only. The plaintext bytes themselves can never enter a trace. -/
  | plaintextEmit     (conn : ConnId) (length : Nat)
  /-- `n` plaintext bytes accepted from the caller for sending. -/
  | plaintextAccept   (conn : ConnId) (n : Nat)
  /-- The handshake completed — the negotiated cipher suite (public metadata). -/
  | handshakeComplete (conn : ConnId) (suite : CipherSuite)
  /-- A typed error reported to the caller — its *category* only, never detail
  or attacker-controlled bytes. -/
  | errorReported     (conn : ConnId) (category : String)
  /-- A fatal/`close_notify` alert mapped for sending — description + level. -/
  | alertOut          (conn : ConnId) (desc : AlertDescription) (level : AlertLevel)
  /-- The transport was closed in the given mode. -/
  | transportClose    (conn : ConnId) (mode : String)
  /-- A secret handle was released — the *event* only, never the handle or bytes. -/
  | secretReleased
  deriving Repr, Inhabited

namespace TraceEvent

/-- Stable label for a server-flight message type. Type only — no bytes. -/
def hsOutLabel : HandshakeOut → String
  | .serverHello ..         => "ServerHello"
  | .encryptedExtensions .. => "EncryptedExtensions"
  | .certificateVerify ..   => "CertificateVerify"
  | .finished ..            => "Finished"

/-- Stable label for a crypto-op kind. -/
def cryptoKindLabel : CryptoOpKind → String
  | .randomBytes           => "randomBytes"
  | .ecdhe                 => "ecdhe"
  | .hkdfExtract           => "hkdfExtract"
  | .hkdfExpand            => "hkdfExpand"
  | .installTrafficKeys    => "installTrafficKeys"
  | .aeadSeal              => "aeadSeal"
  | .aeadOpen              => "aeadOpen"
  | .signCertificateVerify => "signCertificateVerify"
  | .verifyFinished        => "verifyFinished"
  | .computeServerFinished => "computeServerFinished"

/-- Stable label for a close mode. -/
def closeModeLabel : CloseMode → String
  | .graceful => "graceful"
  | .fatal _  => "fatal"
  | .abortive => "abortive"

/-- Top-level error *category* — never the offending detail or bytes (RFC 013 §9). -/
def errorCategory : TlsError → String
  | .protocol _                 => "protocol"
  | .parse _                    => "parse"
  | .crypto _                   => "crypto"
  | .config _                   => "config"
  | .resourceLimit _            => "resourceLimit"
  | .transport _                => "transport"
  | .closed                     => "closed"
  | .internalInvariantFailure   => "internal"

private def alertLevelLabel : AlertLevel → String
  | .warning => "warning"
  | .fatal   => "fatal"

end TraceEvent

open TraceEvent in
/-- Project one core-authorized `OutputAction` to a `TraceEvent`, if it is
trace-worthy. **Secret-free by construction**: every byte-bearing action maps to
a length, every secret reference to a bare event or an op-id. `recordMetric`
flows on the separate metric channel and is not traced here. -/
def traceOfAction : OutputAction → Option TraceEvent
  | .readTransport c              => some (.transportRead c)
  | .writeTransport c b           => some (.transportWrite c b.size)
  | .writeHandshake c e s msg     => some (.handshakeOut c e s (hsOutLabel msg))
  | .writeCertificate c e s der   => some (.certificateOut c e s der.size)
  | .enableWriteInterest c        => some (.writeInterest c true)
  | .disableWriteInterest c       => some (.writeInterest c false)
  | .callCrypto c op req          => some (.cryptoCall c op.value req.kind)
  | .emitPlaintext c b            => some (.plaintextEmit c b.size)
  | .acceptPlaintextBytes c n     => some (.plaintextAccept c n)
  | .reportHandshakeComplete c i  => some (.handshakeComplete c i.suite)
  | .reportError c e              => some (.errorReported c (errorCategory e))
  | .failWithAlert c a            => some (.alertOut c a (Kroopt.Core.alertLevel a))
  | .closeTransport c m           => some (.transportClose c (closeModeLabel m))
  | .releaseSecret _              => some .secretReleased

/-- Render a `TraceEvent` to a single compact, secret-free diagnostic line. -/
def TraceEvent.render : TraceEvent → String
  | .transportRead c          => s!"transport-read conn={c.value}"
  | .transportWrite c n        => s!"transport-write conn={c.value} len={n}"
  | .handshakeOut c _ seq msg  => s!"handshake-out conn={c.value} seq={seq} msg={msg}"
  | .certificateOut c _ seq n  => s!"certificate-out conn={c.value} seq={seq} der-len={n}"
  | .writeInterest c en        => s!"write-interest conn={c.value} enabled={en}"
  | .cryptoCall c op k         => s!"crypto-call conn={c.value} op={op} kind={cryptoKindLabel k}"
  | .plaintextEmit c n         => s!"plaintext-emit conn={c.value} len={n}"
  | .plaintextAccept c n       => s!"plaintext-accept conn={c.value} n={n}"
  | .handshakeComplete c s     => s!"handshake-complete conn={c.value} suite={repr s}"
  | .errorReported c cat       => s!"error conn={c.value} category={cat}"
  | .alertOut c d l            => s!"alert-out conn={c.value} desc={repr d} level={alertLevelLabel l}"
  | .transportClose c m        => s!"transport-close conn={c.value} mode={m}"
  | .secretReleased            => "secret-released"

/-- Project and render an action stream to a secret-free trace. -/
def traceActions (acts : List OutputAction) : List String :=
  acts.filterMap (fun a => (traceOfAction a).map TraceEvent.render)

end Kroopt.Conn
