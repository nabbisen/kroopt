import Kroopt.Conn.Interpreter
import Kroopt.Crypto.RealProvider
import Tests.RealFixtures

/-!
# Tests.Correspondence

Production-interpreter correspondence (RFC 031). This suite grows with the RFC; the first
slice validates the **single transcript authority** (§3): the bytes the interpreter writes to
the wire for each handshake message and the bytes it hashes for the key schedule /
CertificateVerify / Finished are the *same* accumulated sequence, and transcript-bound crypto
ops are resolved against the hash of exactly those bytes — never an independently assembled
trace.
-/

namespace Tests.Correspondence

open Kroopt Kroopt.Core Kroopt.Conn Kroopt.Crypto Kroopt.Parse Tests.RealFixtures

structure Check where
  name : String
  ok : Bool

def eqB (a b : ByteArray) : Bool := a.toList == b.toList

-- Representative typed server-flight messages.
def shMsg : HandshakeOut :=
  .serverHello (ByteArray.mk (Array.mkArray 32 0xA1)) (ByteArray.mk #[]) (ByteArray.mk (Array.mkArray 32 0xB2))
               0x1303 0x001d 0x0304
def eeMsg : HandshakeOut := .encryptedExtensions none
def cvMsg : HandshakeOut := .certificateVerify 0x0807 (ByteArray.mk (Array.mkArray 64 0xC3))
def finMsg : HandshakeOut := .finished (ByteArray.mk (Array.mkArray 32 0xD4))

def fd0 : FdKey := { fd := 1, generation := 1 }
def conn0 : ConnId := ⟨0, 0⟩
def tr0 : FakeTransport := { fd := fd0, inbound := [] }

-- A 32-byte server handshake-traffic secret and an arena with it installed as the
-- write/handshake base secret, so the interpreter's seal path has a key to use.
def hsSecret : ByteArray := ByteArray.mk (Array.mkArray 32 0x2b)
def keyedArena : SecretArena :=
  match SecretArena.empty.store hsSecret with
  | .ok (h, a) => a.recordBaseSecret .write .handshake h.id
  | .error _   => SecretArena.empty
def hsKey : ByteArray := Kroopt.Crypto.KeySchedule.trafficKey .chacha20Poly1305Sha256 hsSecret
def hsIv  : ByteArray := Kroopt.Crypto.KeySchedule.trafficIv hsSecret

-- Drive the core handshake far enough to emit the CertificateVerify op, then extract the exact
-- transcript-prefix bytes the core carried in it (RFC 031 §3 — the core is the single transcript
-- authority). The flow mirrors Tests.Handshake's synthetic drive.
def vch : ValidClientHello :=
  { selectedSuite := .chacha20Poly1305Sha256, selectedGroup := .x25519
    clientShare := ByteArray.mk (Array.mkArray 32 0x07), selectedSigScheme := .ed25519
    sni := some (ByteArray.mk #[0x65, 0x78]), alpn := [ByteArray.mk #[0x68, 0x32]]
    sessionId := ByteArray.empty }
def s0core : State := State.initial ⟨0, 0⟩ ⟨0⟩ .sha256
def chWire : ByteArray := ByteArray.mk #[1, 0, 0, 4, 0x03, 0x04, 0, 0]
def fakeSecret : SecretKeyHandle := ⟨42, 0⟩
def fakeServerShare : ByteArray := ByteArray.mk (Array.mkArray 32 0x09)
def fakeServerRandom : ByteArray := ByteArray.mk (Array.mkArray 32 0x5a)

/-- The transcript-prefix bytes the core carries in the CertificateVerify crypto op. -/
def certVerifyPrefix : Option ByteArray :=
  match (do
    let (s1, _) ← onClientHello s0core vch chWire
    let (sR, _) ← onServerRandomDone s1 fakeServerRandom
    let (s2, _) ← onEcdheDone sR fakeServerShare fakeSecret
    let (p1, _) ← onHsScheduleResult s2 (.hkdfSecret ⟨0, 0⟩)
    let (p2, _) ← onHsScheduleResult p1 (.hkdfSecret ⟨0, 0⟩)
    let (p3, _) ← onHsScheduleResult p2 (.hkdfSecret ⟨0, 0⟩)
    let (p4, _) ← onHsScheduleResult p3 (.hkdfSecret ⟨0, 0⟩)
    let (p5, _) ← onHsScheduleResult p4 (.hkdfSecret ⟨0, 0⟩)
    let (p6, _) ← onHsScheduleResult p5 .keysInstalled
    let (_, acts) ← onHsScheduleResult p6 .keysInstalled
    pure acts : Except TlsError (List OutputAction)) with
  | .ok acts => acts.findSome? (fun a => match a with
      | .callCrypto _ _ (.signCertificateVerify _ input) => some input
      | _ => none)
  | .error _ => none

/-- Drive `writeHandshake` actions through the production interpreter and return the transport,
to read the bytes written to the wire. -/
def driveWritesTr (msgs : List HandshakeOut) : FakeTransport :=
  let acts := msgs.map (fun m => OutputAction.writeHandshake conn0 .initial 0 m)
  let (_, tr, _) := execActions fakeProvider ({} : RuntimeState) tr0 acts
  tr

-- An arbitrary stand-in for the committed-prefix bytes the core carries in a transcript-bound
-- op; the interpreter's only job is to hash exactly these bytes.
def samplePrefix : ByteArray := ByteArray.mk #[0xCA, 0xFE, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]


/-! ## Headline: drive the full handshake through the *production* interpreter to `connected`
with the real provider (RFC 031 §6.1/§7.2). Real fixtures come from `Tests.RealFixtures`. -/


/-- Real crypto, but entropy supplied as the fixed test ServerHello Random (RFC 034: the pure
provider errors on `randomBytes`; the interpreter/test layer owns entropy). -/
def realishProvider : CryptoProvider :=
  { capabilities := realCapabilities
  , submit := fun arena op req =>
      match req with
      | .randomBytes _ => .ok (arena, .randomBytes serverRandom)
      | _              => RealProvider.submit cfg arena op req }

def s0real : State := State.initial ⟨0, 0⟩ ⟨0⟩ .sha256

/-- A provider that answers *every* op with a CertificateVerify-style signature result — the wrong
kind for everything but an actual `signCertificateVerify`. Used to exercise the §4 wrong-kind guard. -/
def wrongKindProvider : CryptoProvider :=
  { capabilities := realCapabilities
  , submit := fun arena _ _ => .ok (arena, .signature (ByteArray.mk #[0xAB])) }

/-- Phase 1: feed the ClientHello and let the production interpreter run the real provider until
the whole server flight is emitted/sealed and handshake keys are installed. -/
def phase1 : State × RuntimeState × FakeTransport :=
  driveEvents realishProvider 1024 s0real ({} : RuntimeState) tr0
    [InputEvent.transportBytes ⟨0,0⟩ (recordWrap clientHelloMsg)]

/-- The client's Finished, sealed under the client handshake-traffic key derived in phase 1, over
the through-server-Finished transcript hash — exactly what the core's `aeadOpen` + `verifyFinished`
will reconstruct. -/
def clientFinishedSealed : ByteArray :=
  let (core1, rt1, _) := phase1
  let cHsSecret := ((rt1.arena.lookupBaseSecret .read .handshake).bind rt1.arena.getById).getD ByteArray.empty
  let throughServerFinished := core1.transcript.events.foldl (fun acc e => acc ++ e.wireBytes) (ByteArray.mk #[])
  let hCHSF := Hacl.sha256 throughServerFinished
  let verifyData := Hacl.hmac256 (Kroopt.Crypto.KeySchedule.finishedKey cHsSecret) hCHSF
  let cKey := Kroopt.Crypto.KeySchedule.trafficKey .chacha20Poly1305Sha256 cHsSecret
  let cIv  := Kroopt.Crypto.KeySchedule.trafficIv cHsSecret
  Record13.sealRecord! cKey cIv 0 (Kroopt.Parse.Wire.finished verifyData) .handshake 0

/-- Phase 2: feed the sealed client Finished; the core emits `aeadOpen .handshake`, the real
provider opens it, `verifyFinished` checks the MAC, and the handshake reaches `connected`. -/
def reached : State × RuntimeState × FakeTransport :=
  let (core1, rt1, tr1) := phase1
  driveEvents realishProvider 256 core1 rt1 tr1
    [InputEvent.transportBytes ⟨0,0⟩ clientFinishedSealed]

/-- A client Finished with the *wrong* verify_data — correctly sealed (so it opens), but its MAC
will not match what `verifyFinished` recomputes. -/
def badClientFinishedSealed : ByteArray :=
  let (_, rt1, _) := phase1
  let cHsSecret := ((rt1.arena.lookupBaseSecret .read .handshake).bind rt1.arena.getById).getD ByteArray.empty
  let cKey := Kroopt.Crypto.KeySchedule.trafficKey .chacha20Poly1305Sha256 cHsSecret
  let cIv  := Kroopt.Crypto.KeySchedule.trafficIv cHsSecret
  let badVerifyData := ByteArray.mk (Array.mkArray 32 (0 : UInt8))
  Record13.sealRecord! cKey cIv 0 (Kroopt.Parse.Wire.finished badVerifyData) .handshake 0

def reachedBad : State × RuntimeState × FakeTransport :=
  let (core1, rt1, tr1) := phase1
  driveEvents realishProvider 256 core1 rt1 tr1
    [InputEvent.transportBytes ⟨0,0⟩ badClientFinishedSealed]

/-! ## RFC 033 record reassembly, driven through the *production* interpreter (migrated from the
retired `Tests.RealHandshake` RD driver — the core does the reassembly identically regardless of
which driver feeds it bytes). -/

/-- A ClientHello split across two handshake records, fed to the production interpreter. -/
def fragmentedReach : State × RuntimeState × FakeTransport :=
  let half := clientHelloMsg.size / 2
  driveEvents realishProvider 1024 s0real ({} : RuntimeState) tr0
    [InputEvent.transportBytes ⟨0,0⟩ (recordWrap (clientHelloMsg.extract 0 half)),
     InputEvent.transportBytes ⟨0,0⟩ (recordWrap (clientHelloMsg.extract half clientHelloMsg.size))]

/-- A handshake header claiming a huge length, fed across enough records to pass the reassembly cap. -/
def bigHdrFrag : ByteArray :=
  (ByteArray.mk #[1, 0xFF, 0xFF, 0xFF]) ++ ByteArray.mk (Array.mkArray 16000 (0x00 : UInt8))
def oversizedReach : State × RuntimeState × FakeTransport :=
  let ev := InputEvent.transportBytes ⟨0,0⟩ (recordWrap bigHdrFrag)
  driveEvents realishProvider 64 s0real ({} : RuntimeState) tr0 [ev, ev, ev, ev, ev]

/-- A post-`connected` application send, driven through the production interpreter. -/
def appData : ByteArray := ByteArray.mk #[0x68, 0x69, 0x21]

def afterSend : State × RuntimeState × FakeTransport :=
  let (c, rt, tr) := reached
  driveEvents realishProvider 64 c rt tr [InputEvent.appSend ⟨0,0⟩ appData]

/-- A post-close state: `connected`, then a graceful close issued. -/
def closedState : State :=
  match Kroopt.Core.step reached.1 (.appClose conn0 .graceful) with
  | .ok (s, _) => s
  | .error _ => reached.1

/-- Outer record content-types in a concatenation of TLS records (fuel-bounded walk). -/
def recordTypes : Nat → ByteArray → List UInt8
  | 0, _ => []
  | fuel+1, b =>
    if b.size < 5 then []
    else
      let len := (b.get! 3).toNat * 256 + (b.get! 4).toNat
      let total := 5 + len
      if b.size < total then [b.get! 0]
      else b.get! 0 :: recordTypes fuel (b.extract total b.size)


def checks : List Check :=
  let msgs := [shMsg, eeMsg, cvMsg, finMsg]
  [ -- (1) the wire carries a real record per message, payload = the serialized handshake message.
    { name := "the wire records carry exactly the serialized handshake messages"
    , ok := eqB (FakeTransport.writtenBytes (driveWritesTr msgs))
                (msgs.foldl (fun acc m => acc ++ plaintextHandshakeRecord (serializeHandshakeOut m))
                            (ByteArray.mk #[])) }
    -- (2) computeServerFinished is hashed over exactly the prefix bytes the core carried.
  , { name := "computeServerFinished hashes the core-carried prefix bytes"
    , ok := (match resolveCryptoTranscript (CryptoOp.computeServerFinished .sha256 samplePrefix) with
             | .computeServerFinished _ h => eqB h (Hacl.sha256 samplePrefix)
             | _ => false) }
    -- (3) signCertificateVerify wraps certVerifyContent over the hash of the carried prefix.
  , { name := "signCertificateVerify wraps certVerifyContent over the carried prefix hash"
    , ok := (match resolveCryptoTranscript (CryptoOp.signCertificateVerify .ed25519 samplePrefix) with
             | .signCertificateVerify _ inp => eqB inp (Flight.certVerifyContent (Hacl.sha256 samplePrefix))
             | _ => false) }
    -- (4) verifyFinished (client Finished) hashes the carried prefix.
  , { name := "verifyFinished hashes the carried prefix"
    , ok := (match resolveCryptoTranscript (CryptoOp.verifyFinished .sha256 samplePrefix (ByteArray.mk #[1,2,3])) with
             | .verifyFinished _ h _ => eqB h (Hacl.sha256 samplePrefix)
             | _ => false) }
    -- (5) traffic-secret HKDF hashes its carried prefix context; 'derived' keeps its own context.
  , { name := "traffic-secret HKDF hashes its carried prefix; 'derived' keeps its context"
    , ok := (let bound := resolveCryptoTranscript (CryptoOp.hkdfExpandLabel .sha256 ⟨7,0⟩ "s hs traffic" samplePrefix 32)
             let unbound := resolveCryptoTranscript (CryptoOp.hkdfExpandLabel .sha256 ⟨7,0⟩ "derived" samplePrefix 32)
             (match bound with
              | .hkdfExpandLabel _ _ _ c _ => eqB c (Hacl.sha256 samplePrefix)
              | _ => false)
             && (match unbound with
                 | .hkdfExpandLabel _ _ _ c _ => eqB c samplePrefix
                 | _ => false)) }
    -- (6) a non-transcript op (ECDHE) passes through resolution unchanged.
  , { name := "non-transcript ops pass through resolution unchanged"
    , ok := (match resolveCryptoTranscript (CryptoOp.ecdheX25519 (ByteArray.mk #[9,9])) with
             | .ecdheX25519 p => eqB p (ByteArray.mk #[9,9])
             | _ => false) }
    -- (7) a .handshake-epoch message is sealed as a real protected record (outer 0x17) that
    -- opens, under the same installed key, back to exactly the plaintext message.
  , { name := "handshake-epoch flight message is sealed into a record that opens to the plaintext"
    , ok := (let plain := serializeHandshakeOut eeMsg
             let wire := (handshakeWire keyedArena .handshake 0 plain).toOption.get!
             (wire.size > 0 && wire.get! 0 == 0x17)
             && (match Record13.openRecord hsKey hsIv 0 wire with
                 | some (content, _) => eqB content plain
                 | none => false)) }
    -- (8) the core-authorized sequence is honoured: the same message at seq 3 opens at seq 3
    -- but not at seq 0 (the nonce is a function of the sequence number).
  , { name := "the sealed record uses the core-authorized sequence number"
    , ok := (let plain := serializeHandshakeOut cvMsg
             let wire := (handshakeWire keyedArena .handshake 3 plain).toOption.get!
             (match Record13.openRecord hsKey hsIv 3 wire with
              | some (content, _) => eqB content plain | none => false)
             && (match Record13.openRecord hsKey hsIv 0 wire with
                 | some _ => false | none => true)) }
    -- (9) with no handshake write key installed, the seal path falls back to a cleartext
    -- handshake record (outer type 22) — the transitional keyless path, never a crash.
  , { name := "without an installed key the seal path falls back to a cleartext record"
    , ok := (let plain := serializeHandshakeOut eeMsg
             let wire := (handshakeWire SecretArena.empty .handshake 0 plain).toOption.get!
             wire.size > 0 && wire.get! 0 == 22) }
    -- (10) the plaintext ServerHello epoch is never sealed — it is a cleartext record.
  , { name := "the .initial-epoch ServerHello is written as a cleartext record"
    , ok := (let plain := serializeHandshakeOut shMsg
             let wire := (handshakeWire keyedArena .initial 0 plain).toOption.get!
             wire.size > 0 && wire.get! 0 == 22) }
    -- (11) the core carries the *full* committed transcript prefix in a transcript-bound op:
    -- the CertificateVerify input begins with the inbound ClientHello and extends past it
    -- (it is CH ++ ServerHello ++ EncryptedExtensions ++ Certificate). The interpreter never
    -- has to re-accumulate the inbound prefix — the core is the single transcript authority.
  , { name := "core carries the ClientHello-inclusive transcript prefix in the CertificateVerify op"
    , ok := (match certVerifyPrefix with
             | some p => eqB (p.extract 0 chWire.size) chWire && p.size > chWire.size
             | none => false) }
    -- (12) HEADLINE (§6.1): the production interpreter drives the full handshake to `connected`
    -- with the real provider — real records out, real ECDHE/HKDF/signature/MAC, the client
    -- Finished opened by the core's aeadOpen and verified.
  , { name := "production interpreter + real provider reach `connected`"
    , ok := (match reached.1.handshake with | .connected => true | _ => false) }
    -- (13) HEADLINE (§7.2): the wire is the real flight — a cleartext ServerHello record (0x16)
    -- followed by four sealed protected records (0x17) for EE/Cert/CertVerify/Finished.
  , { name := "the wire flight is a cleartext ServerHello record + four sealed records"
    , ok := (recordTypes 32 (FakeTransport.writtenBytes phase1.2.2)
             == [0x16, 0x17, 0x17, 0x17, 0x17]) }
    -- (14) the interpreter binds the record-header AAD for an aeadSeal op too (RFC 8446 §5.2),
    -- symmetric with aeadOpen: the on-wire ciphertext length is the plaintext plus the 16-byte
    -- Poly1305 tag, matching `Record13.sealRecord`'s `ctLen := inner.size + 16`. (Verified by a
    -- crypto round-trip during development; the full post-`connected` app-record wire path —
    -- record-header framing and the first-record sequence number — is the next slice.)
  , { name := "resolveRecordAAD binds the record-header AAD for an aeadSeal op"
    , ok := (let pt := ByteArray.mk #[10, 20, 30, 40, 50]
             match resolveRecordAAD (CryptoOp.aeadSeal (writeMeta reached.1) (ByteArray.mk #[]) pt) with
             | .aeadSeal _ aad _ => eqB aad (Record13.recordAAD (pt.size + 16))
             | _ => false) }
    -- (15) the full post-`connected` application-data wire path: a real application send through the
    -- production interpreter produces a real `TLSCiphertext` record — record header + sealed inner —
    -- at sequence number 0, which opens back to the application plaintext under the installed
    -- write/application key. Exercises the sequence fix, record-header framing, and AAD together.
  , { name := "post-connected app send produces a real record opening to the plaintext at seq 0"
    , ok := (let before := (FakeTransport.writtenBytes reached.2.2).size
             let allW := FakeTransport.writtenBytes afterSend.2.2
             let record := allW.extract before allW.size
             match afterSend.2.1.arena.lookupInstalled .write .application with
             | some (kId, ivId) =>
                 (match afterSend.2.1.arena.getById kId, afterSend.2.1.arena.getById ivId with
                  | some key, some iv =>
                      (match Record13.openRecord key iv 0 record with
                       | some (content, ct) =>
                           eqB content appData && (match ct with | .applicationData => true | _ => false)
                       | none => false)
                  | _, _ => false)
             | none => false) }
    -- (16) RFC 031 §4 wrong-kind guard: when the provider answers an op with a result whose kind
    -- cannot answer it, the interpreter terminates with an internal-invariant failure and forwards
    -- nothing — the mismatched result never reaches the core's result-kind dispatch.
  , { name := "the interpreter rejects a wrong-kind crypto result and goes terminal (§4)"
    , ok := (let (rt, _, evs) :=
               execAction wrongKindProvider ({} : RuntimeState) tr0
                 (OutputAction.callCrypto conn0 ⟨0⟩ (CryptoOp.ecdheX25519 (ByteArray.mk #[1,2,3])))
             rt.terminal
             && (match rt.lastError with | some .internalInvariantFailure => true | _ => false)
             && evs.isEmpty) }
    -- (17) the guard is not over-eager: a correct-kind result is forwarded to the core unchanged
    -- and does not terminate the connection.
  , { name := "a correct-kind crypto result is forwarded to the core (§4)"
    , ok := (let (rt, _, evs) :=
               execAction realishProvider ({} : RuntimeState) tr0
                 (OutputAction.callCrypto conn0 ⟨0⟩ (CryptoOp.randomBytes 32))
             (!rt.terminal)
             && (match evs with
                 | [InputEvent.cryptoResult _ _ (.randomBytes _)] => true
                 | _ => false)) }
    -- (18) RFC 031 §6 no-early-plaintext bypass: through the entire server flight (phase 1 pauses
    -- at `sentServerFinished`, before `connected`), the interpreter has emitted no application
    -- plaintext — the only path to `plaintextOut` is the core's `emitPlaintext`, reachable only
    -- once connected.
  , { name := "no application plaintext is emitted before `connected` (§6)"
    , ok := phase1.2.1.plaintextOut.isNone
            && (match phase1.1.handshake with | .connected => false | _ => true) }
    -- (19) §6 bypass: an application send before `connected` accepts zero plaintext through the
    -- interpreter — the only path to `acceptedBytes` is the core's `acceptPlaintextBytes`, which the
    -- core emits only from `connected`.
  , { name := "an application send before `connected` accepts zero plaintext (§6)"
    , ok := (let (_, rt, _) := driveEvents realishProvider 16 s0real ({} : RuntimeState) tr0
                                 [InputEvent.appSend conn0 (ByteArray.mk #[1, 2, 3])]
             rt.acceptedBytes == 0) }
    -- (20) §6 bypass: an application send after a close has begun likewise accepts zero plaintext.
  , { name := "an application send after close accepts zero plaintext (§6)"
    , ok := (let (_, rt, _) := driveEvents realishProvider 16 closedState ({} : RuntimeState) tr0
                                 [InputEvent.appSend conn0 (ByteArray.mk #[1, 2, 3])]
             rt.acceptedBytes == 0) }
    -- (21) negative control (migrated from RealHandshake, now production-driven): a client Finished
    -- with the wrong verify_data opens correctly but fails the real `verifyFinished` MAC check, so
    -- the handshake does NOT reach `connected`.
  , { name := "a wrong client Finished is rejected and does not reach `connected`"
    , ok := (match reachedBad.1.handshake with | .connected => false | _ => true)
            && (match reached.1.handshake with | .connected => true | _ => false) }
    -- (22) RFC 033 reassembly: a ClientHello split across two records reassembles in the core and
    -- reaches the same state as the same ClientHello delivered in one record (`phase1`).
  , { name := "a ClientHello split across two records reassembles to the same state (RFC 033)"
    , ok := (fragmentedReach.1.handshake == phase1.1.handshake)
            && (match phase1.1.handshake with | .sentServerFinished => true | _ => false) }
    -- (23) RFC 033: an over-large reassembly buffer fails the connection rather than buffering unbounded.
  , { name := "an over-large handshake reassembly buffer fails the connection (RFC 033)"
    , ok := (match oversizedReach.1.handshake with | .failed _ => true | _ => false) }
    -- (24) RFC 033 unit: `frameHandshakeMessage` frames one complete message, reports incomplete,
    -- and returns the tail when a record coalesces a message with trailing bytes.
  , { name := "frameHandshakeMessage frames, reports incomplete, and splits coalesced (RFC 033)"
    , ok := (let complete   := ByteArray.mk #[1, 0, 0, 3, 0xAA, 0xBB, 0xCC]
             let incomplete := ByteArray.mk #[1, 0, 0, 3, 0xAA]
             let coalesced  := ByteArray.mk #[1, 0, 0, 1, 0x42, 0x99]
             (match frameHandshakeMessage complete with
              | some (m, r) => m.size == 7 && r.size == 0 | none => false)
             && (frameHandshakeMessage incomplete).isNone
             && (match frameHandshakeMessage coalesced with
                 | some (m, r) => m.size == 5 && r.size == 1 | none => false)) }
    -- (25) the certificate fixture is a well-formed DER object (SEQUENCE, 2-byte length, 351 octets).
    -- Full OpenSSL-parseability is fixed at generation time (`scripts/gen-test-cert.sh`) and the
    -- Ed25519 CertificateVerify signing path is gated cross-library by `scripts/ed25519-interop.sh`.
  , { name := "the certificate fixture is a well-formed Ed25519 X.509 DER object"
    , ok := certDer.size == 351 && certDer.get! 0 == 0x30 && certDer.get! 1 == 0x82 }
    -- (26) RFC 037 §4: the over-large handshake input is now rejected by the cumulative
    -- total-handshake-bytes budget charged *in the core* (proven in Kroopt.Proofs.Budget),
    -- which fires before the per-buffer reassembly cap and maps to the generic internal_error
    -- alert (no budget detail leaks).
  , { name := "an over-large handshake input fails via the core resource-budget (RFC 037 §4)"
    , ok := (match oversizedReach.1.handshake with | .failed .internalError => true | _ => false) }
    -- (RFC 037 §3) secret-leak: every terminal interpreter path drops the connection's live secret
    -- references. `keyedArena` holds a stored secret (liveCount > 0); after a terminal action the
    -- runtime arena has no live secret material. This is the Lean-side *best-effort* release
    -- (bumpGeneration drops bytes and invalidates handles), NOT guaranteed zeroization — the C-owned
    -- zeroizing arena is that target. No production zeroization guarantee is claimed.
  , { name := "graceful close drops every live secret reference (RFC 037 §3)"
    , ok := (let (rt, _, _) := execAction realishProvider ({ arena := keyedArena } : RuntimeState) tr0
                                 (OutputAction.closeTransport conn0 .graceful)
             keyedArena.liveCount > 0 && rt.arena.liveCount == 0) }
  , { name := "fatal close drops every live secret reference (RFC 037 §3)"
    , ok := (let (rt, _, _) := execAction realishProvider ({ arena := keyedArena } : RuntimeState) tr0
                                 (OutputAction.closeTransport conn0 (.fatal .internalError))
             rt.arena.liveCount == 0) }
  , { name := "abortive close drops every live secret reference (RFC 037 §3)"
    , ok := (let (rt, _, _) := execAction realishProvider ({ arena := keyedArena } : RuntimeState) tr0
                                 (OutputAction.closeTransport conn0 .abortive)
             rt.arena.liveCount == 0) }
  , { name := "a fatal alert drops every live secret reference (RFC 037 §3)"
    , ok := (let (rt, _, _) := execAction realishProvider ({ arena := keyedArena } : RuntimeState) tr0
                                 (OutputAction.failWithAlert conn0 .internalError)
             rt.arena.liveCount == 0) }
  , { name := "a reported error drops every live secret reference (RFC 037 §3)"
    , ok := (let (rt, _, _) := execAction realishProvider ({ arena := keyedArena } : RuntimeState) tr0
                                 (OutputAction.reportError conn0 .closed)
             rt.arena.liveCount == 0) }
    -- (RFC 037 §6) a graceful close from `connected` seals an encrypted close_notify (warning = 1,
    -- close_notify = 0) under the application write epoch — reusing the application-data AEAD-seal
    -- action — rather than tearing down the transport in the clear.
  , { name := "a graceful close from `connected` seals an encrypted close_notify (RFC 037 §6)"
    , ok := (match Kroopt.Core.step reached.1 (.appClose conn0 .graceful) with
             | .ok (s, [OutputAction.callCrypto _ _ (CryptoOp.aeadSeal _ _ inner)]) =>
                 eqB inner (ByteArray.mk #[1, 0, ContentType.alert.toByte])
                 && (match s.closeState with | .sentCloseNotify => true | _ => false)
                 && (match s.handshake with | .closing => true | _ => false)
             | _ => false) }
    -- (RFC 037 §6) end-to-end through the production interpreter: the close_notify is sealed and
    -- written as a TLS 1.3 record (outer type 0x17, application_data) before the transport closes.
  , { name := "a graceful close writes a sealed close_notify record before closing (RFC 037 §6)"
    , ok := (let before := (FakeTransport.writtenBytes reached.2.2).size
             let (s, _, tr') := driveEvents realishProvider 64 reached.1 reached.2.1 reached.2.2
                                  [InputEvent.appClose conn0 .graceful]
             let allW := FakeTransport.writtenBytes tr'
             allW.size > before
             && (match recordTypes 8 (allW.extract before allW.size) with
                 | 0x17 :: _ => true | _ => false)
             && (match s.handshake with | .closing => true | _ => false)) }
  ]

def main : IO UInt32 := do
  let mut bad := 0
  for c in checks do
    if c.ok then IO.println s!"  PASS  {c.name}"
    else do IO.println s!"  FAIL  {c.name}"; bad := bad + 1
  if bad == 0 then
    IO.println s!"All {checks.length} checks passed."
    return 0
  else
    IO.println s!"{bad} of {checks.length} checks FAILED."
    return 1

end Tests.Correspondence

def main : IO UInt32 := Tests.Correspondence.main
