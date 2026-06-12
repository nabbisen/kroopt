import Kroopt.Core.State
import Kroopt.Core.Event
import Kroopt.Core.Action
import Kroopt.Parse.Record
import Kroopt.Core.Handshake
import Kroopt.Parse.Handshake
import Kroopt.Core.Alert

/-!
# Kroopt.Core.RecordPath

The record-layer transitions of the verified core (RFC 004 §5, §6). These are
pure functions from state to `(state, actions)`; they decide *what* the record
layer does and request crypto as actions — they never call crypto (RFC 004 §11).

The safety-critical structure, exploited by the proofs in
`Kroopt.Proofs.RecordPath`:

* **No handler emits `emitPlaintext`.** Decrypted application plaintext is placed
  into the one-record `pendingPlainOut` buffer and delivered later by the
  `appRecvRequested` path in `step`. So the *only* emitter of application
  plaintext remains a single, `connected`-gated site (preserving the M0 *no
  early plaintext* theorem).
* **`pendingPlainOut` is filled only by `handleCryptoResult` on a successful
  `aeadOpened` result whose inner content type is `applicationData`, in
  `connected` state.** That is the *no unauthenticated plaintext* guarantee at
  the buffer level (RFC 004 §10, RFC 015 §15.1): buffered plaintext always comes
  from an authenticated decryption, never from raw transport bytes.
* **AEAD-open failure is fatal and emits no plaintext** (RFC 004 §5.7, §12).
-/

namespace Kroopt.Core

open Kroopt (TlsError AlertDescription)
open Kroopt.Parse (ParseError parseInnerPlaintext classifyCcs CcsClassification)

/-- The record-path step result type (same as `Step.StepResult`). -/
abbrev RecordStepResult := Except TlsError (State × List OutputAction)

/-- Fail terminally with an alert (shared shape with `Step.failAlert`): move to
`failed`, drop any buffered plaintext, emit the alert and a typed error. No
plaintext is emitted on this path (RFC 004 §12, RFC 013 §7). -/
def recordFailAlert (s : State) (a : AlertDescription) (e : TlsError) : RecordStepResult :=
  .ok ({ s with handshake := .failed a
                closeState := .fatalSent a
                pendingPlainOut := none },
       [ OutputAction.failWithAlert s.connId a,
         OutputAction.reportError s.connId e ])

/-- AEAD metadata for a read-direction protected record. -/
def readMeta (s : State) : RecordCryptoMeta :=
  { conn := s.connId, direction := .read, epoch := .application
    seq := s.readEpoch.seq
    suite := s.negotiated.selectedSuite.getD .aes128GcmSha256
    contentRole := .applicationData }

/-- AEAD metadata for a write-direction protected record. -/
def writeMeta (s : State) : RecordCryptoMeta :=
  { conn := s.connId, direction := .write, epoch := .application
    seq := s.writeEpoch.seq
    suite := s.negotiated.selectedSuite.getD .aes128GcmSha256
    contentRole := .applicationData }

/-- Route a plaintext handshake record to the handshake model by phase
(RFC 006 §5, §10): in `start` it is the ClientHello (parsed and validated, else a
clean decode failure); in `sentServerFinished` it is the client Finished; other
phases ignore it. Uses decidable phase tests so it case-splits cleanly. Emits no
application plaintext (`Kroopt.Proofs.RecordPath`). -/
def handshakeOnPlaintextRecord (s : State) (body : ByteArray) : RecordStepResult :=
  if s.handshake = .start then
    match Kroopt.Parse.parseClientHello body with
    | .error e => recordFailAlert s (alertForParseError e.toPublic) (.parse e.toPublic)
    | .ok wb => handshakeOnClientHello s wb.value body
  else if s.handshake = .sentServerFinished then
    onClientFinishedBytes s body
  else
    .ok (s, [])

/-- Handle inbound transport bytes: reassemble and frame one record, then route
by outer content type (RFC 004 §5). -/
def handleTransportBytes (s0 : State) (b : ByteArray) : RecordStepResult :=
  let s := { s0 with inboundCiphertext := s0.inboundCiphertext ++ b }
  match (Kroopt.Parse.Reader.ofBytes s.inboundCiphertext).tryTakeRecord with
  | .error e => recordFailAlert s (alertForParseError e.toPublic) (.parse e.toPublic)
  | .ok (none, _) =>
      -- Not a full record yet: ask the interpreter to read more.
      .ok (s, [OutputAction.readTransport s.connId])
  | .ok (some (hdr, body), r') =>
      -- Consume the framed record; keep any trailing bytes for the next record.
      let rest := r'.input.extract r'.offset r'.input.size
      let s := { s with inboundCiphertext := rest }
      match hdr.outerType with
      | .applicationData =>
          if s.handshake.isConnected then
            let (oid, s) := s.allocOp .aeadOpen .application (some .read)
            .ok (s, [OutputAction.callCrypto s.connId oid
                      (CryptoOp.aeadOpen (readMeta s) (ByteArray.mk #[]) body)])
          else
            -- Protected record before `connected`: handshake record path is M4.
            .ok (s, [])
      | .changeCipherSpec =>
          match classifyCcs body with
          | .allowedCompat => .ok (s, [])                      -- accept and ignore
          | .rejected =>
              recordFailAlert s .unexpectedMessage (.protocol .illegalMessageForState)
      | .handshake =>
          -- Drive the handshake from a plaintext handshake record (RFC 006 §5, §10).
          handshakeOnPlaintextRecord s body
      | .alert =>
          -- Minimal inbound-alert handling: begin close (full policy at M9).
          .ok ({ s with handshake := .closing, closeState := .receivedCloseNotify },
               [OutputAction.closeTransport s.connId .graceful])
      | .invalid =>
          recordFailAlert s (alertForParseError .invalidContentType) (.parse .invalidContentType)

/-- Handle a *correlated* crypto result for the record layer (RFC 004 §5.6, §6.6):
the operation id has already been checked outstanding by `handleCryptoResult`.

The single safety-critical branch is `aeadOpened` in `connected` state with an
inner content type of `applicationData`: it validates the inner plaintext,
advances the read sequence (overflow fatal), and buffers the content for later
delivery. AEAD-open failure (`verifyFailed`/`failed`) is fatal with no plaintext.
No branch emits `emitPlaintext`. -/
def handleCryptoResultCorrelated (s : State) (op : OperationId) (r : CryptoResult) :
    RecordStepResult :=
  match r with
  | .aeadOpened pt =>
      if s.handshake.isConnected then
        match parseInnerPlaintext pt with
        | .error e => recordFailAlert s (alertForParseError e.toPublic) (.parse e.toPublic)
        | .ok inner =>
            match inner.ctype with
            | .applicationData =>
                match s.readEpoch.seq.next with
                | none => recordFailAlert s .internalError (.protocol .sequenceOverflow)
                | some sq =>
                    .ok ((s.clearOp op |> fun s =>
                          { s with pendingPlainOut := some inner.content
                                   readEpoch := { s.readEpoch with seq := sq } }), [])
            | .alert =>
                .ok ((s.clearOp op |> fun s =>
                      { s with handshake := .closing
                               closeState := .receivedCloseNotify }),
                     [OutputAction.closeTransport s.connId .graceful])
            | .handshake => .ok (s.clearOp op, [])
            | .changeCipherSpec => .ok (s.clearOp op, [])
            | .invalid => .ok (s.clearOp op, [])
      else
        -- Open result while not connected: ignore (no plaintext).
        .ok (s.clearOp op, [])
  | .aeadSealed ct =>
      .ok ((s.clearOp op |> fun s =>
            { s with outboundCiphertext := s.outboundCiphertext ++ ct }),
           [OutputAction.writeTransport s.connId ct])
  | .verifyFailed =>
      -- AEAD / Finished verification failure ⇒ fatal, never plaintext (RFC 004 §12).
      recordFailAlert s .badRecordMac (.crypto .authFailed)
  | .failed e =>
      recordFailAlert s .internalError (.crypto e)
  | .randomBytes _ => .ok (s.clearOp op, [])
  | .ecdheComplete srv h => handshakeOnGatingResult s op (.ecdheComplete srv h)
  | .hkdfSecret d => handshakeOnGatingResult s op (.hkdfSecret d)
  | .keysInstalled => handshakeOnGatingResult s op .keysInstalled
  | .signature sig => handshakeOnGatingResult s op (.signature sig)
  | .verified => handshakeOnGatingResult s op .verified

/-- Handle a returning crypto result (RFC 008 §5 — **operation-id correlation**).
A result is processed only if its operation id is currently outstanding. A
result whose id is **not** outstanding — stale (the connection advanced or
failed since the request), already-consumed (duplicate), or unknown (forged) —
is dropped with no effect: no plaintext, no state change, no protocol progress
(RFC 015 §9.13). This is the gate that keeps a late or replayed provider answer
from perturbing the protocol. -/
def handleCryptoResult (s : State) (op : OperationId) (r : CryptoResult) :
    RecordStepResult :=
  if s.pendingOps.contains op then
    handleCryptoResultCorrelated s op r
  else
    .ok (s, [])

/-- Handle an application send in `connected` state (RFC 004 §6). Accept a bounded
prefix (one fragment ≤ 2¹⁴), build the inner plaintext, advance the write
sequence (overflow fatal), and request an AEAD seal. Emits `acceptPlaintextBytes`
(ownership of the accepted prefix) and `callCrypto` — never `emitPlaintext`. -/
def handleAppSend (s : State) (b : ByteArray) : RecordStepResult :=
  match s.writeEpoch.seq.next with
  | none => recordFailAlert s .internalError (.protocol .sequenceOverflow)
  | some sq =>
      let n := min b.size maxPlaintextFragment
      let frag := b.extract 0 n
      let inner := frag ++ ByteArray.mk #[ContentType.applicationData.toByte]
      let (oid, s) := s.allocOp .aeadSeal .application (some .write)
      let s := { s with writeEpoch := { s.writeEpoch with seq := sq } }
      .ok (s, [ OutputAction.callCrypto s.connId oid
                  (CryptoOp.aeadSeal (writeMeta s) (ByteArray.mk #[]) inner),
                OutputAction.acceptPlaintextBytes s.connId n ])

end Kroopt.Core
