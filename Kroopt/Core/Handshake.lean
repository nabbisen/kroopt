import Kroopt.Core.State
import Kroopt.Core.Event
import Kroopt.Core.Action

/-!
# Kroopt.Core.Handshake

The TLS 1.3 **server** handshake state model, no HelloRetryRequest (RFC 006).
Clients must present an acceptable X25519 `key_share` in the initial ClientHello
or the handshake fails cleanly.

The handshake is a sequence of small transition functions (RFC 006 §10), each
moving the phase forward along a legal edge and either requesting the next crypto
operation or framing the next flight. The crypto operations that *gate* a phase
change (ECDHE, the CertificateVerify signature, the client-Finished
verification) are requested as actions and their results re-enter as events; the
key-schedule HKDF derivations are modeled as synchronous key installation in this
state-model milestone (the provider-backed HKDF round-trips arrive with the
crypto FFI at M6).

Safety-relevant structure, exploited by `Kroopt.Proofs.Handshake`:
* every transition moves along a `legalEdge` (no skipped/closed-out-of-order
  phases);
* `connected` is reachable **only** from `requestedClientFinishedVerify` via
  `onClientFinishedVerified` — i.e. only after the client Finished verified;
* no handshake transition emits application plaintext.
-/

namespace Kroopt.Core

open Kroopt (TlsError AlertDescription)

/-- A validated ClientHello: the negotiated parameters the parser/policy checker
produced (RFC 006 §5). Holding one is evidence the mandatory checks passed —
TLS 1.3 offered, an acceptable suite, an X25519 `key_share` present, a compatible
signature scheme, no duplicate extensions, no early data. -/
structure ValidClientHello where
  selectedSuite : CipherSuite
  selectedGroup : NamedGroup
  clientShare : ByteArray
  selectedSigScheme : SignatureScheme
  sni : Option ByteArray
  alpn : List ByteArray

/-! ## Legal phase edges (RFC 006 §4) -/

/-- The allowed handshake-phase transitions. A phase may stay put (record I/O,
recv, flush leave the phase unchanged), fail cleanly from any live phase, begin a
close, or advance one step along the server flight. `connected` is reachable only
from `requestedClientFinishedVerify`. -/
def legalEdge (a b : HandshakeState) : Bool :=
  (a == b)
  || (!a.isTerminal && (match b with | .failed _ => true | _ => false))
  || (!a.isTerminal && b == .closing)
  || (a == .closing && b == .closed)
  || (a == .start && b == .requestedEcdhe)
  || (a == .requestedEcdhe && b == .derivedHandshakeSecrets)
  || (a == .derivedHandshakeSecrets && b == .requestedCertificateVerifySignature)
  || (a == .requestedCertificateVerifySignature && b == .sentServerFinished)
  || (a == .sentServerFinished && b == .requestedClientFinishedVerify)
  || (a == .requestedClientFinishedVerify && b == .connected)

/-! ## Frame builders (synthetic)

Representative framed bytes for each server-flight message. The exact bytes are
what enter the transcript; the binding proof (RFC 007) cares that the transcript
stores them verbatim, not their specific shape. Real wire framing lands with the
crypto/interop milestones. -/

def frameServerHello (_vch : ValidClientHello) : ByteArray := ByteArray.mk #[2, 0, 0, 0]
def frameEncryptedExtensions : ByteArray := ByteArray.mk #[8, 0, 0, 0]
def frameCertificate : ByteArray := ByteArray.mk #[11, 0, 0, 0]
def frameCertificateVerify (_sig : ByteArray) : ByteArray := ByteArray.mk #[15, 0, 0, 0]
def frameServerFinished : ByteArray := ByteArray.mk #[20, 0, 0, 0]

/-- The handshake-step result type (same as `Step.StepResult`). -/
abbrev HsResult := Except TlsError (State × List OutputAction)

/-- Fail the handshake terminally with an alert (no plaintext on this path). -/
def hsFail (s : State) (a : AlertDescription) (e : TlsError) : HsResult :=
  .ok ({ s with handshake := .failed a, closeState := .fatalSent a,
                pendingPlainOut := none },
       [ OutputAction.failWithAlert s.connId a, OutputAction.reportError s.connId e ])

/-- Install epoch keys for a direction (synthetic: marks the epoch installed and
resets the sequence; the real HKDF-derived handles arrive at M6). -/
def installEpoch (e : Epoch) : EpochState :=
  { epoch := e, seq := SeqNo.zero, keysInstalled := true }

/-! ## Transitions (RFC 006 §10) -/

/-- `start → requestedEcdhe`. Record the negotiated parameters, commit the exact
ClientHello bytes to the transcript, and request the ECDHE shared secret. -/
def onClientHello (s : State) (vch : ValidClientHello) (chWire : ByteArray) : HsResult :=
  if s.handshake = .start then
    let ep := selectEndpoint s.serverConfig vch.sni
    let alpn := ep.bind (fun e =>
      negotiateAlpn s.serverConfig.alpnMode (vch.alpn.map AlpnProtocol.mk) e.allowedAlpn)
    let cert := ep.map (·.chain)
    let s := { s with
      negotiated := { selectedSuite := some vch.selectedSuite
                      selectedGroup := some vch.selectedGroup
                      selectedSigScheme := some vch.selectedSigScheme
                      selectedSni := vch.sni
                      selectedAlpn := alpn
                      selectedCert := cert }
      transcript := s.transcript.appendFramed .clientHello .read chWire }
    let (oid, s) := s.allocOp .ecdhe .handshake (some .read)
    .ok ({ s with handshake := .requestedEcdhe },
         [OutputAction.callCrypto s.connId oid (CryptoOp.ecdheX25519 vch.clientShare)])
  else
    hsFail s .unexpectedMessage (.protocol .illegalMessageForState)

/-- `requestedEcdhe → derivedHandshakeSecrets`. Frame ServerHello (committing it to
the transcript), install the handshake epoch, and **start the handshake-key stage
of the key schedule**: record the ECDHE shared-secret handle and request the
Early-Secret extraction. The rest of the stage is pumped by `onHsScheduleResult`.
(The transcript context is the core's abstract snapshot reference; the provider
resolves it to the real hash in the real-transcript milestone.) -/
def onEcdheDone (s : State) (secret : SecretKeyHandle) : HsResult :=
  if s.handshake = .requestedEcdhe then
    let sh := frameServerHello { selectedSuite := s.negotiated.selectedSuite.getD .aes128GcmSha256
                                 selectedGroup := s.negotiated.selectedGroup.getD .x25519
                                 clientShare := ByteArray.mk #[]
                                 selectedSigScheme := s.negotiated.selectedSigScheme.getD .ed25519
                                 sni := none, alpn := [] }
    let ts := s.transcript.appendFramed .serverHello .write sh
    let (snap, ts) := ts.snapshot
    let hsTh := ByteArray.mk #[snap.id.toUInt8]
    let s := { s with transcript := ts
                      readEpoch := installEpoch .handshake
                      writeEpoch := installEpoch .handshake }
    let suite := s.negotiated.selectedSuite.getD .aes128GcmSha256
    let (ksd, earlyOp) := KeyScheduleDriver.startPostEcdhe suite
                            KeyScheduleDriver.emptyHashSha256 hsTh secret
    let (oid, s) := s.allocOp earlyOp.kind .handshake (some .write)
    .ok ({ s with handshake := .derivedHandshakeSecrets, keySched := some ksd },
         [ OutputAction.writeTransport s.connId sh,
           OutputAction.callCrypto s.connId oid earlyOp ])
  else
    hsFail s .unexpectedMessage (.protocol .illegalMessageForState)

/-- `derivedHandshakeSecrets → derivedHandshakeSecrets` (pumping) or
`→ requestedCertificateVerifySignature` (stage done). Feed the awaited schedule
result to the orchestrator and emit the next schedule op; when the handshake-key
stage reaches its pause, frame EncryptedExtensions / Certificate and request the
CertificateVerify signature over the transcript snapshot. -/
def onHsScheduleResult (s : State) (r : CryptoResult) : HsResult :=
  if s.handshake = .derivedHandshakeSecrets then
    match s.keySched with
    | none => hsFail s .internalError (.protocol .illegalMessageForState)
    | some ksd =>
      match KeyScheduleDriver.advance ksd r with
      | .error e => hsFail s .internalError e
      | .ok (ksd, op :: _) =>
          let (oid, s) := s.allocOp op.kind .handshake (some .write)
          .ok ({ s with keySched := some ksd },
               [OutputAction.callCrypto s.connId oid op])
      | .ok (ksd, []) =>
          if ksd.phase = .handshakeKeysInstalled then
            let ee := frameEncryptedExtensions
            let cert := frameCertificate
            let ts := s.transcript.appendFramed .encryptedExtensions .write ee
            let ts := ts.appendFramed .certificate .write cert
            let (snap, ts) := ts.snapshot
            let s := { s with transcript := ts, keySched := some ksd }
            let (oid, s) := s.allocOp .signCertificateVerify .handshake (some .write)
            let scheme := s.negotiated.selectedSigScheme.getD .ed25519
            .ok ({ s with handshake := .requestedCertificateVerifySignature },
                 [ OutputAction.writeTransport s.connId ee,
                   OutputAction.writeTransport s.connId cert,
                   OutputAction.callCrypto s.connId oid
                     (CryptoOp.signCertificateVerify scheme
                       (ByteArray.mk #[snap.id.toUInt8])) ])
          else
            .ok ({ s with keySched := some ksd }, [])
  else
    hsFail s .unexpectedMessage (.protocol .illegalMessageForState)

/-- `requestedCertificateVerifySignature → sentServerFinished`. Commit the framed
CertificateVerify and server Finished to the transcript, install application
keys, and emit the server flight tail. -/
def onCertVerifySigned (s : State) (sig : ByteArray) : HsResult :=
  if s.handshake = .requestedCertificateVerifySignature then
    let cv := frameCertificateVerify sig
    let ts := s.transcript.appendFramed .certificateVerify .write cv
    let ts := ts.appendFramed .finished .write frameServerFinished
    let s := { s with transcript := ts
                      readEpoch := installEpoch .application
                      writeEpoch := installEpoch .application }
    .ok ({ s with handshake := .sentServerFinished },
         [ OutputAction.writeTransport s.connId cv,
           OutputAction.writeTransport s.connId frameServerFinished ])
  else
    hsFail s .unexpectedMessage (.protocol .illegalMessageForState)

/-- `sentServerFinished → requestedClientFinishedVerify`. Take the transcript
snapshot *before* committing the client Finished and request its MAC
verification. -/
def onClientFinishedBytes (s : State) (cfWire : ByteArray) : HsResult :=
  if s.handshake = .sentServerFinished then
    let (snap, ts) := s.transcript.snapshot
    let s := { s with transcript := ts, pendingClientFinished := some cfWire }
    let (oid, s) := s.allocOp .verifyFinished .application (some .read)
    .ok ({ s with handshake := .requestedClientFinishedVerify },
         [ OutputAction.callCrypto s.connId oid
             (CryptoOp.verifyFinished s.transcript.hashAlg
               (ByteArray.mk #[snap.id.toUInt8]) cfWire) ])
  else
    hsFail s .unexpectedMessage (.protocol .illegalMessageForState)

/-- `requestedClientFinishedVerify → connected`. On a successful verification,
commit the client Finished to the transcript and report completion. A
verification failure is fatal (`decrypt_error`) — `connected` is unreachable
without it. -/
def onClientFinishedVerified (s : State) (verified : Bool) (cfWire : ByteArray) : HsResult :=
  if s.handshake = .requestedClientFinishedVerify then
    if verified then
      let s := { s with transcript := s.transcript.appendFramed .finished .read cfWire }
      .ok ({ s with handshake := .connected },
           [ OutputAction.reportHandshakeComplete s.connId
               { suite := s.negotiated.selectedSuite.getD .aes128GcmSha256
                 configGen := s.configGen } ])
    else
      hsFail s .decryptError (.protocol .badFinished)
  else
    hsFail s .unexpectedMessage (.protocol .illegalMessageForState)

/-- Route a returning crypto result that *gates* a handshake phase change to the
right transition (RFC 006 §7, §10). The pending op is cleared first. ECDHE,
the CertificateVerify signature, and the client-Finished verification each
advance exactly one phase; an unexpected result for the current phase is ignored
(the op is already cleared). This dispatch emits no application plaintext. -/
def handshakeOnGatingResult (s0 : State) (op : OperationId) (r : CryptoResult) : HsResult :=
  let s := s0.clearOp op
  match r with
  | .ecdheComplete _ h =>
      if s.handshake = .requestedEcdhe then onEcdheDone s h else .ok (s, [])
  | .signature sig =>
      if s.handshake = .requestedCertificateVerifySignature then onCertVerifySigned s sig
      else .ok (s, [])
  | .verified =>
      if s.handshake = .requestedClientFinishedVerify then
        onClientFinishedVerified s true (s.pendingClientFinished.getD (ByteArray.mk #[]))
      else .ok (s, [])
  | .randomBytes _ => .ok (s, [])
  | .hkdfSecret _ =>
      if s.handshake = .derivedHandshakeSecrets then onHsScheduleResult s r else .ok (s, [])
  | .keysInstalled =>
      if s.handshake = .derivedHandshakeSecrets then onHsScheduleResult s r else .ok (s, [])
  | .aeadSealed _ => .ok (s, [])
  | .aeadOpened _ => .ok (s, [])
  | .verifyFailed => .ok (s, [])
  | .failed _ => .ok (s, [])

/-- Route a plaintext handshake record to the right transition by phase
(RFC 006 §5, §10). In `start` it is the ClientHello (parsed and validated); in
`sentServerFinished` it is the client Finished. Other phases ignore it. Parsing
is the caller's responsibility (it lives above the import boundary); this takes
an already-parsed `ValidClientHello` for the ClientHello case. Emits no
application plaintext. -/
def handshakeOnClientHello (s : State) (vch : ValidClientHello) (chWire : ByteArray) : HsResult :=
  onClientHello s vch chWire

end Kroopt.Core
