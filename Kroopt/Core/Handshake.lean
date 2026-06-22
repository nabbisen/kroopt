import Kroopt.Core.State
import Kroopt.Core.Event
import Kroopt.Core.Action
import Kroopt.Parse.Wire
import Kroopt.Core.Alert
import Kroopt.Core.Budget

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

/-- The TLS `SignatureScheme` wire code point (RFC 8446 §4.2.3). The constrained profile
negotiates Ed25519 only; the other rows are correct for when the suite list widens. -/
def sigSchemeToU16 : SignatureScheme → UInt16
  | .ed25519              => 0x0807
  | .ecdsaSecp256r1Sha256 => 0x0403
  | .rsaPssRsaeSha256     => 0x0804

/-- Cipher-suite wire code point (RFC 8446 §B.4). -/
def cipherSuiteToU16 : CipherSuite → UInt16
  | .aes128GcmSha256       => 0x1301
  | .aes256GcmSha384       => 0x1302
  | .chacha20Poly1305Sha256 => 0x1303

/-- Named-group wire code point (RFC 8446 §4.2.7). -/
def namedGroupToU16 : NamedGroup → UInt16
  | .x25519   => 0x001d
  | .secp256r1 => 0x0017

/-- Realize a typed server-flight handshake message into its wire bytes (RFC 032 §3).
A single pure serializer is the one source of byte layout: the interpreter and the
test drivers all call it, so no production path recognizes a message by its first
byte. Slice 1 covers EncryptedExtensions (ALPN); slice 2 adds CertificateVerify. -/
def serializeHandshakeOut : HandshakeOut → ByteArray
  | .serverHello random share suite group version =>
      Kroopt.Parse.Wire.serverHello random (ByteArray.mk #[]) suite group share version
  | .encryptedExtensions alpn =>
      let exts := match alpn with
        | none   => ByteArray.mk #[]
        | some p => Kroopt.Parse.Wire.extension 0x10
                      (Kroopt.Parse.Wire.u16Len (Kroopt.Parse.Wire.u8Len p))
      Kroopt.Parse.Wire.encryptedExtensions exts
  | .certificateVerify scheme signature =>
      Kroopt.Parse.Wire.certificateVerify scheme signature
  | .finished verifyData =>
      Kroopt.Parse.Wire.finished verifyData

/-- Serialize the server Certificate message (RFC 032 §5). The core holds only an opaque
chain handle, not the DER; until RFC 031 threads configured DER through, both the emitted
`writeCertificate` action and this transcript contribution serialize an empty chain, so the
two agree by construction. -/
def serializeServerCertificate (_chain : CertificateChainHandle) : ByteArray :=
  Kroopt.Parse.Wire.certificate (ByteArray.mk #[]) (ByteArray.mk #[])

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
  || (a == .start && b == .requestedServerRandom)
  || (a == .requestedServerRandom && b == .requestedEcdhe)
  || (a == .requestedEcdhe && b == .derivedHandshakeSecrets)
  || (a == .derivedHandshakeSecrets && b == .requestedCertificateVerifySignature)
  || (a == .requestedCertificateVerifySignature && b == .requestedServerFinishedMac)
  || (a == .requestedServerFinishedMac && b == .sentCertificateVerify)
  || (a == .sentCertificateVerify && b == .sentServerFinished)
  || (a == .sentServerFinished && b == .requestedClientFinishedVerify)
  || (a == .requestedClientFinishedVerify && b == .connected)

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
    -- RFC 037 §4: charge the ClientHello message bytes against the ClientHello budget in
    -- the core before negotiating (proven in `Kroopt.Proofs.Budget`). This is tighter than
    -- the cumulative total-handshake-bytes budget charged in `RecordPath` and bounds a single
    -- oversized initial flight. Limits are the standard RFC 019 ceilings.
    match chargeClientHelloBytes ResourceLimits.standard s.budgets chWire.size with
    | .error e => hsFail s (alertForResourceLimit e) (.resourceLimit e)
    | .ok b' =>
    let s := { s with budgets := b' }
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
                      selectedCert := cert
                      serverShare := none
                      clientShare := some vch.clientShare
                      serverRandom := none }
      transcript := s.transcript.appendFramed .clientHello .read chWire }
    let (oid, s) := s.allocOp .randomBytes .handshake (some .write)
    .ok ({ s with handshake := .requestedServerRandom },
         [OutputAction.callCrypto s.connId oid (CryptoOp.randomBytes 32)])
  else
    hsFail s .unexpectedMessage (.protocol .illegalMessageForState)

/-- `requestedServerRandom → requestedEcdhe`. Record the drawn server Random and request
the ECDHE shared secret over the client's key_share (RFC 032: the random is now a core
value, sourced from the CSPRNG before ServerHello is assembled). -/
def onServerRandomDone (s : State) (random : ByteArray) : HsResult :=
  if s.handshake = .requestedServerRandom then
    let s := { s with negotiated := { s.negotiated with serverRandom := some random } }
    let (oid, s) := s.allocOp .ecdhe .handshake (some .read)
    .ok ({ s with handshake := .requestedEcdhe },
         [OutputAction.callCrypto s.connId oid
            (CryptoOp.ecdheX25519 (s.negotiated.clientShare.getD (ByteArray.mk #[])))])
  else
    hsFail s .unexpectedMessage (.protocol .illegalMessageForState)

/-- `requestedEcdhe → derivedHandshakeSecrets`. Build the typed ServerHello, commit its
**serialized bytes** to the transcript (RFC 032 §5 — the transcript is over serialized
handshake messages, not placeholders), install the handshake epoch, and **start the
handshake-key stage of the key schedule**: record the ECDHE shared-secret handle and request
the Early-Secret extraction. The rest of the stage is pumped by `onHsScheduleResult`. -/
def onEcdheDone (s : State) (serverShare : ByteArray) (secret : SecretKeyHandle) : HsResult :=
  if s.handshake = .requestedEcdhe then
    let shMsg : HandshakeOut :=
      .serverHello (s.negotiated.serverRandom.getD (ByteArray.mk #[]))
                   serverShare
                   (cipherSuiteToU16 (s.negotiated.selectedSuite.getD .chacha20Poly1305Sha256))
                   (namedGroupToU16 (s.negotiated.selectedGroup.getD .x25519))
                   0x0304
    let ts := s.transcript.appendFramed .serverHello .write (serializeHandshakeOut shMsg)
    let (snap, ts) := ts.snapshot
    let hsTh := ts.prefixBytes snap
    let s := { s with transcript := ts
                      negotiated := { s.negotiated with serverShare := some serverShare }
                      readEpoch := installEpoch .handshake
                      writeEpoch := installEpoch .handshake }
    let suite := s.negotiated.selectedSuite.getD .aes128GcmSha256
    let (ksd, earlyOp) := KeyScheduleDriver.startPostEcdhe suite
                            KeyScheduleDriver.emptyHashSha256 hsTh secret
    let (oid, s) := s.allocOp earlyOp.kind .handshake (some .write)
    .ok ({ s with handshake := .derivedHandshakeSecrets, keySched := some ksd },
         [ OutputAction.writeHandshake s.connId .initial 0 shMsg,
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
            let eeMsg : HandshakeOut :=
              .encryptedExtensions (s.negotiated.selectedAlpn.map (·.bytes))
            let certHandle := s.negotiated.selectedCert.getD default
            let ts := s.transcript.appendFramed .encryptedExtensions .write
                        (serializeHandshakeOut eeMsg)
            let ts := ts.appendFramed .certificate .write
                        (serializeServerCertificate certHandle)
            let (snap, ts) := ts.snapshot
            let s := { s with transcript := ts, keySched := some ksd }
            let (oid, s) := s.allocOp .signCertificateVerify .handshake (some .write)
            let scheme := s.negotiated.selectedSigScheme.getD .ed25519
            .ok ({ s with handshake := .requestedCertificateVerifySignature },
                 [ OutputAction.writeHandshake s.connId .handshake 0 eeMsg,
                   OutputAction.writeCertificate s.connId .handshake 1 certHandle,
                   OutputAction.callCrypto s.connId oid
                     (CryptoOp.signCertificateVerify scheme
                       (ts.prefixBytes snap)) ])
          else
            .ok ({ s with keySched := some ksd }, [])
  else
    hsFail s .unexpectedMessage (.protocol .illegalMessageForState)

/-- `requestedCertificateVerifySignature → requestedServerFinishedMac`. Commit the framed
CertificateVerify to the transcript and request the server Finished verify_data — a MAC over
the transcript hash **through CertificateVerify**, computed by the core's
`computeServerFinished` op (the verify_data is a core value, not interpreter-assembled). -/
def onCertVerifySigned (s : State) (sig : ByteArray) : HsResult :=
  if s.handshake = .requestedCertificateVerifySignature then
    let cvMsg : HandshakeOut :=
      .certificateVerify (sigSchemeToU16 (s.negotiated.selectedSigScheme.getD .ed25519)) sig
    let ts := s.transcript.appendFramed .certificateVerify .write (serializeHandshakeOut cvMsg)
    let (snap, ts) := ts.snapshot
    let cvTh := ts.prefixBytes snap
    let s := { s with transcript := ts }
    let (oid, s) := s.allocOp .computeServerFinished .handshake (some .write)
    .ok ({ s with handshake := .requestedServerFinishedMac },
         [ OutputAction.writeHandshake s.connId .handshake 2 cvMsg,
           OutputAction.callCrypto s.connId oid
             (CryptoOp.computeServerFinished s.transcript.hashAlg cvTh) ])
  else
    hsFail s .unexpectedMessage (.protocol .illegalMessageForState)

/-- `requestedServerFinishedMac → sentCertificateVerify`. The server Finished verify_data
has been computed; commit the framed Finished to the transcript, derive the application keys
(the schedule resumes over the transcript hash **through Finished**), and emit the typed
Finished action carrying the verify_data. -/
def onServerFinishedMac (s : State) (verifyData : ByteArray) : HsResult :=
  if s.handshake = .requestedServerFinishedMac then
    match s.keySched with
    | none => hsFail s .internalError (.protocol .illegalMessageForState)
    | some ksd =>
      let ts := s.transcript.appendFramed .finished .write
                  (serializeHandshakeOut (.finished verifyData))
      let (snap, ts) := ts.snapshot
      let apTh := ts.prefixBytes snap
      match KeyScheduleDriver.resumeApplication ksd apTh with
      | .error e => hsFail s .internalError e
      | .ok (ksd, op :: _) =>
          let s := { s with transcript := ts }
          let (oid, s) := s.allocOp op.kind .application (some .write)
          .ok ({ s with handshake := .sentCertificateVerify, keySched := some ksd },
               [ OutputAction.writeHandshake s.connId .handshake 3 (.finished verifyData),
                 OutputAction.callCrypto s.connId oid op ])
      | .ok (_, []) => hsFail s .internalError (.protocol .illegalMessageForState)
  else
    hsFail s .unexpectedMessage (.protocol .illegalMessageForState)

/-- `sentCertificateVerify → sentCertificateVerify` (pumping) or
`→ sentServerFinished` (stage done). Feed the awaited schedule result to the
orchestrator and emit the next op; when the application-key stage reaches
`complete`, install the application epoch and move to `sentServerFinished`. -/
def onApScheduleResult (s : State) (r : CryptoResult) : HsResult :=
  if s.handshake = .sentCertificateVerify then
    match s.keySched with
    | none => hsFail s .internalError (.protocol .illegalMessageForState)
    | some ksd =>
      match KeyScheduleDriver.advance ksd r with
      | .error e => hsFail s .internalError e
      | .ok (ksd, op :: _) =>
          let (oid, s) := s.allocOp op.kind .application (some .write)
          .ok ({ s with keySched := some ksd },
               [OutputAction.callCrypto s.connId oid op])
      | .ok (ksd, []) =>
          if ksd.phase = .complete then
            -- Server Finished sent: the server's *write* switches to application keys,
            -- but the *read* epoch stays handshake — the client Finished is still sealed
            -- under the client handshake-traffic key (RFC 8446 §4.4.4). Read switches to
            -- application only once that Finished verifies (→ `connected`).
            .ok ({ s with handshake := .sentServerFinished, keySched := some ksd
                          readEpoch := installEpoch .handshake
                          writeEpoch := installEpoch .application }, [])
          else
            .ok ({ s with keySched := some ksd }, [])
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
               (ts.prefixBytes snap) cfWire) ])
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
      .ok ({ s with handshake := .connected
                    readEpoch := installEpoch .application },
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
  | .ecdheComplete srv h =>
      if s.handshake = .requestedEcdhe then onEcdheDone s srv h else .ok (s, [])
  | .signature sig =>
      if s.handshake = .requestedCertificateVerifySignature then onCertVerifySigned s sig
      else .ok (s, [])
  | .verified =>
      if s.handshake = .requestedClientFinishedVerify then
        onClientFinishedVerified s true (s.pendingClientFinished.getD (ByteArray.mk #[]))
      else .ok (s, [])
  | .randomBytes b =>
      if s.handshake = .requestedServerRandom then onServerRandomDone s b else .ok (s, [])
  | .finishedMac vd =>
      if s.handshake = .requestedServerFinishedMac then onServerFinishedMac s vd else .ok (s, [])
  | .hkdfSecret _ =>
      if s.handshake = .derivedHandshakeSecrets then onHsScheduleResult s r
      else if s.handshake = .sentCertificateVerify then onApScheduleResult s r
      else .ok (s, [])
  | .keysInstalled =>
      if s.handshake = .derivedHandshakeSecrets then onHsScheduleResult s r
      else if s.handshake = .sentCertificateVerify then onApScheduleResult s r
      else .ok (s, [])
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
