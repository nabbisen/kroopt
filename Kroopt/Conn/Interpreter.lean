import Kroopt.Core.Step
import Kroopt.Crypto.Provider
import Kroopt.Crypto.Hacl
import Kroopt.Crypto.KeySchedule
import Kroopt.Conn.Transport
import Kroopt.Conn.Flight
import Kroopt.Conn.Record13
import Kroopt.Parse.Wire

/-!
# Kroopt.Conn.Interpreter

The thin imperative interpreter (RFC 002 §5, RFC 010 §6). It executes the core's
`OutputAction` list over the transport and the crypto provider, and feeds results
back as `InputEvent`s — and it makes **no protocol decisions**. Every function
here dispatches on the `OutputAction` *variant* alone; none branches on the
handshake phase, chooses a cipher suite, derives a sequence number, or decides
whether plaintext is legal. That is the proof/runtime correspondence contract
made into a runtime artifact (RFC 010 §12): all protocol truth stays in
`Kroopt.Core.step`, which the proofs in `Kroopt.Proofs` constrain.

The driver is a fuel-bounded loop, so it can never spin on repeated `wouldBlock`
(RFC 010 §10).
-/

namespace Kroopt.Conn

open Kroopt (TlsError TransportError CryptoError)
open Kroopt.Core (State InputEvent OutputAction HandshakeInfo CryptoOp)
open Kroopt.Crypto (CryptoProvider SecretArena)

/-- How many bytes a single `readTransport` requests. -/
def maxReadChunk : Nat := 16384

/-- The interpreter's bookkeeping — pending ciphertext, the one buffered
plaintext record for `recv`, accepted-plaintext accounting for `send`, and the
public metadata view. Protocol truth lives in the core `State`, never here
(RFC 010 §9). -/
structure RuntimeState where
  outbound       : ByteArray := ByteArray.mk #[]
  plaintextOut   : Option ByteArray := none
  acceptedBytes  : Nat := 0
  writeInterest  : Bool := false
  metadata       : Option HandshakeInfo := none
  lastError      : Option TlsError := none
  terminal       : Bool := false
  arena          : SecretArena := SecretArena.empty
  deriving Inhabited

/-- Try to push the pending ciphertext queue toward the transport, honouring
partial writes and `wouldBlock` (RFC 010 §4). Bytes already sent are removed from
the head of the queue, preserving order. -/
partial def drainOutbound {τ : Type} [Transport τ] (rt : RuntimeState) (tr : τ) : RuntimeState × τ :=
  if rt.outbound.isEmpty then (rt, tr)
  else
    match Transport.send tr (Transport.fd tr) rt.outbound with
    | (.sent n, tr') =>
        if n = 0 ∨ n ≥ rt.outbound.size then
          ({ rt with outbound := rt.outbound.extract n rt.outbound.size }, tr')
        else
          drainOutbound { rt with outbound := rt.outbound.extract n rt.outbound.size } tr'
    | (.wouldBlock, tr') => (rt, tr')
    | (.error e, tr') => ({ rt with lastError := some (.transport e), terminal := true }, tr')

/-- Resolve a transcript-bound crypto op by hashing the **prefix bytes the core carried in it**
(RFC 031 §3). The verified core is the single transcript authority: it commits the inbound
ClientHello and every server message to its transcript and passes the exact committed-prefix
bytes (`TranscriptState.prefixBytes`) in the op. The interpreter only computes the hash the
provider expects — it never reconstructs or re-accumulates the transcript. For HKDF, only the
traffic-secret derivations carry a transcript prefix; other steps (e.g. the `derived` step) carry
their own context and pass through. Non-transcript ops (ECDHE, AEAD) pass through unchanged. -/
def resolveCryptoTranscript : CryptoOp → CryptoOp
  | .signCertificateVerify scheme pfx =>
      .signCertificateVerify scheme (Flight.certVerifyContent (Kroopt.Crypto.Hacl.sha256 pfx))
  | .computeServerFinished alg pfx =>
      .computeServerFinished alg (Kroopt.Crypto.Hacl.sha256 pfx)
  | .verifyFinished alg pfx received =>
      .verifyFinished alg (Kroopt.Crypto.Hacl.sha256 pfx) received
  | .hkdfExpandLabel alg secret label ctx len =>
      if label == "s hs traffic" || label == "c hs traffic"
         || label == "s ap traffic" || label == "c ap traffic" || label == "exp master" then
        .hkdfExpandLabel alg secret label (Kroopt.Crypto.Hacl.sha256 ctx) len
      else
        .hkdfExpandLabel alg secret label ctx len
  | op => op

/-- Fill in the record-header AAD (RFC 8446 §5.2) for an AEAD record op. The core routes the
record and hands the provider the plaintext/ciphertext, but the record header — which is the AEAD's
additional data — is a wire-framing detail the interpreter owns: it is exactly the header
`Record13.sealRecord` binds on the seal side. We reconstruct it from the on-wire ciphertext length
so that the provider's seal and open agree with the framing; without it, a real AEAD provider
produces records a peer rejects and rejects every inbound protected record.

  * `aeadOpen`: the ciphertext is already the on-wire payload, so its length is the header length.
  * `aeadSeal`: the on-wire ciphertext is the plaintext plus the 16-byte Poly1305 tag, matching
    `Record13.sealRecord`'s `ctLen := inner.size + 16`. -/
def resolveRecordAAD : CryptoOp → CryptoOp
  | .aeadOpen meta _ ct => .aeadOpen meta (Record13.recordAAD ct.size) ct
  | .aeadSeal meta _ pt => .aeadSeal meta (Record13.recordAAD (pt.size + 16)) pt
  | op => op

/-- Whether a provider result is a well-formed answer to a crypto op of the given kind (RFC 031
§4 — the operation-id lifecycle's *same operation kind* requirement, enforced at the interpreter
layer). A typed `failed` error answers any op; `verifyFailed` answers an open or a Finished verify
(an adversarial outcome, not a malformed result). Anything else is a provider misbehaving: the
interpreter must not feed a mismatched result into the verified core as if it answered the op. -/
def resultMatchesKind : Kroopt.Core.CryptoOpKind → Kroopt.Core.CryptoResult → Bool
  | _,                        .failed _        => true
  | .randomBytes,             .randomBytes _   => true
  | .ecdhe,                   .ecdheComplete _ _ => true
  | .hkdfExtract,             .hkdfSecret _    => true
  | .hkdfExpand,              .hkdfSecret _    => true
  | .installTrafficKeys,      .keysInstalled   => true
  | .aeadSeal,                .aeadSealed _    => true
  | .aeadOpen,                .aeadOpened _    => true
  | .aeadOpen,                .verifyFailed    => true
  | .verifyFinished,          .verified        => true
  | .verifyFinished,          .verifyFailed    => true
  | .signCertificateVerify,   .signature _     => true
  | .computeServerFinished,   .finishedMac _   => true
  | _, _ => false

/-- Frame a cleartext TLS 1.3 handshake record (`content_type = handshake`, legacy record
version `0x0303`). The ServerHello travels in such a record — it precedes the encrypted flight. -/
def plaintextHandshakeRecord (plain : ByteArray) : ByteArray :=
  ByteArray.mk #[(22 : UInt8), 0x03, 0x03] ++ Kroopt.Parse.Wire.be16 plain.size.toUInt16 ++ plain

/-- Seal one handshake-flight message as a real TLS 1.3 protected record under the server
handshake-traffic key installed in the arena, at the core-authorized sequence number `seq`
(RFC 031 §3 — the interpreter MAY seal but the epoch/seq come from the core). Returns `none`
when no handshake write key is installed; that is the transitional fake-provider path, whose
bytes never reach a real wire. -/
def sealHandshakeRecord (arena : SecretArena) (seq : UInt64) (plain : ByteArray) :
    Except Kroopt.ResourceLimitError (Option ByteArray) :=
  match arena.lookupBaseSecret .write .handshake with
  | none => .ok none
  | some sid =>
    match arena.getById sid with
    | none => .ok none
    | some secret =>
        let key := Kroopt.Crypto.KeySchedule.trafficKey .chacha20Poly1305Sha256 secret
        let iv  := Kroopt.Crypto.KeySchedule.trafficIv secret
        (Record13.sealRecord key iv seq plain .handshake 0).map some

/-- Realize a flight message as the wire bytes its core-authorized epoch demands: a
`.handshake`-epoch message becomes a sealed protected record (or, transitionally, a cleartext
record if no key is installed); the `.initial`-epoch ServerHello becomes a cleartext handshake
record. The transcript itself lives in the core (RFC 031 §3) — over plaintext messages — so
the interpreter only frames/seals the wire; it does not maintain a transcript. -/
def handshakeWire (arena : SecretArena) (epoch : Kroopt.Core.Epoch) (seq : UInt64) (plain : ByteArray) :
    Except Kroopt.ResourceLimitError ByteArray :=
  match epoch with
  | .handshake =>
      match sealHandshakeRecord arena seq plain with
      | .ok (some r) => .ok r
      | .ok none     => .ok (plaintextHandshakeRecord plain)  -- transitional no-key cleartext path
      | .error e     => .error e                              -- oversize record → fail the connection
  | _ => .ok (plaintextHandshakeRecord plain)

/-- Mark the runtime terminal and drop every live secret reference (RFC 037 §3). On the Lean
side this is a *best-effort* release: `bumpGeneration` drops the stored secret bytes and invalidates
every outstanding handle (a stale handle then resolves to `none`, never the wrong secret). It is
**not** guaranteed memory zeroization — the C-owned zeroizing arena (RFC 013 §13.4) is the fixed
target for that, and no production zeroization guarantee is claimed until it lands. -/
def terminate (rt : RuntimeState) (err : Option TlsError := none) : RuntimeState :=
  { rt with terminal := true
            arena := rt.arena.bumpGeneration
            lastError := match err with | some e => some e | none => rt.lastError }

/-- Execute one action (RFC 010 §6). Dispatches on the action **variant only** —
no protocol-state branching. Returns the updated runtime/transport and any
follow-up `InputEvent`s to feed back to the core. -/
def execAction {τ : Type} [Transport τ] (prov : CryptoProvider) (rt : RuntimeState) (tr : τ) :
    OutputAction → RuntimeState × τ × List InputEvent
  | .readTransport conn =>
      match Transport.recv tr (Transport.fd tr) maxReadChunk with
      | (.bytes b, tr')   => (rt, tr', [InputEvent.transportBytes conn b])
      | (.wouldBlock, tr') => (rt, tr', [])
      | (.eof, tr')        => (rt, tr', [InputEvent.transportEof conn])
      | (.error e, tr')    => ({ rt with lastError := some (.transport e) }, tr',
                               [InputEvent.transportEof conn])
  | .writeTransport _ b =>
      -- The core emits `writeTransport` only for application-data ciphertext the provider has
      -- sealed (RFC 004 §6) — the bare AEAD output, with no record header. Frame it as a
      -- `TLSCiphertext` record here, where the interpreter owns wire framing (the handshake flight
      -- is framed the same way via `Record13`). The 5-byte header is exactly the AEAD AAD the seal
      -- bound (`Record13.recordAAD` over the on-wire ciphertext length), so open and wire agree.
      let record := Record13.recordAAD b.size ++ b
      let (rt', tr') := drainOutbound { rt with outbound := rt.outbound ++ record } tr
      (rt', tr', [])
  | .writeHandshake _ epoch seq msg =>
      -- Realize the typed handshake message via the shared serializer (RFC 032); no
      -- first-byte dispatch. The wire carries the real record for the core-authorized epoch/seq
      -- (plaintext ServerHello, sealed encrypted flight). The transcript is the core's, not the
      -- interpreter's.
      let plain := Kroopt.Core.serializeHandshakeOut msg
      match handshakeWire rt.arena epoch seq plain with
      | .ok wire =>
          let (rt', tr') := drainOutbound { rt with outbound := rt.outbound ++ wire } tr
          (rt', tr', [])
      | .error e => (terminate rt (some (.resourceLimit e)), tr, [])
  | .writeCertificate _ epoch seq der =>
      -- The interpreter owns Certificate framing but uses the *core's* single serializer over the
      -- DER the core resolved (RFC 032 §4): identical bytes to the core's transcript contribution.
      let plain := Kroopt.Core.serializeServerCertificate der
      match handshakeWire rt.arena epoch seq plain with
      | .ok wire =>
          let (rt', tr') := drainOutbound { rt with outbound := rt.outbound ++ wire } tr
          (rt', tr', [])
      | .error e => (terminate rt (some (.resourceLimit e)), tr, [])
  | .enableWriteInterest _  => ({ rt with writeInterest := true }, Transport.enableWrite tr (Transport.fd tr), [])
  | .disableWriteInterest _ => ({ rt with writeInterest := false }, Transport.disableWrite tr (Transport.fd tr), [])
  | .callCrypto conn op req =>
      match prov.submit rt.arena op (resolveRecordAAD (resolveCryptoTranscript req)) with
      | .ok (arena', r) =>
          if resultMatchesKind req.kind r then
            ({ rt with arena := arena' }, tr, [InputEvent.cryptoResult conn op r])
          else
            -- The provider answered with a result whose kind cannot answer this op (RFC 031 §4):
            -- an internal-invariant violation. Terminate; never feed the mismatched result into
            -- the verified core, where it would be dispatched on the result kind alone.
            (terminate { rt with arena := arena' } (some .internalInvariantFailure), tr, [])
      | .error e        => (rt, tr, [InputEvent.cryptoResult conn op (.failed e)])
  | .emitPlaintext _ b        => ({ rt with plaintextOut := some b }, tr, [])
  | .acceptPlaintextBytes _ n => ({ rt with acceptedBytes := rt.acceptedBytes + n }, tr, [])
  | .reportHandshakeComplete _ info => ({ rt with metadata := some info }, tr, [])
  | .reportError _ e          => (terminate rt (some e), tr, [])
  | .failWithAlert _ _        => (terminate rt, tr, [])
  | .closeTransport _ _       => (terminate rt, Transport.closeConnection tr (Transport.fd tr), [])
  | .releaseSecret h          => ({ rt with arena := rt.arena.release h }, tr, [])

/-- Execute a list of actions in order, accumulating follow-up events. -/
def execActions {τ : Type} [Transport τ] (prov : CryptoProvider) (rt : RuntimeState) (tr : τ)
    (acts : List OutputAction) : RuntimeState × τ × List InputEvent :=
  acts.foldl
    (fun (acc : RuntimeState × τ × List InputEvent) a =>
      let (rt', tr', evs) := execAction prov acc.1 acc.2.1 a
      (rt', tr', acc.2.2 ++ evs))
    (rt, tr, [])

/-- The fuel-bounded drive loop (RFC 010 §6, §10 — *never spin on wouldBlock*).
Process events FIFO, but feed each step's follow-up events **before** the
remaining external events, so a crypto/transport cascade completes in phase. -/
def driveEvents {τ : Type} [Transport τ] (prov : CryptoProvider) :
    Nat → State → RuntimeState → τ → List InputEvent →
    State × RuntimeState × τ
  | 0, core, rt, tr, _ => (core, rt, tr)
  | _, core, rt, tr, [] => (core, rt, tr)
  | fuel + 1, core, rt, tr, ev :: rest =>
      match Kroopt.Core.step core ev with
      | .error e => (core, { rt with lastError := some e, terminal := true }, tr)
      | .ok (core', acts) =>
          let (rt', tr', newEvs) := execActions prov rt tr acts
          driveEvents prov fuel core' rt' tr' (newEvs ++ rest)

/-- Default progress budget per external event (RFC 010 §7). -/
def progressBudget : Nat := 256

end Kroopt.Conn
