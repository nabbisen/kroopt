import Kroopt.Core.Crypto
import Kroopt.Core.CipherSuite
import Kroopt.Core.Record
import Kroopt.Error

/-!
# Kroopt.Core.KeyScheduleDriver

The verified, **pure** orchestrator for the TLS 1.3 key schedule (RFC 8446 §7.1).
It produces the sequence of `CryptoOp`s the schedule requires and threads the
`SecretKeyHandle`s each step yields into the inputs of the next — exactly the
sequence the M14 test scripted by hand and the real provider answers, now moved
into the verified core where it belongs.

It lives in the pure core zone: it constructs `CryptoOp` *values* (data) and never
performs cryptography, IO, or FFI. The interpreter executes the ops against a real
provider; this module only decides *which op comes next* and *with which handles*.
It is not yet invoked by `Kroopt.Core.step` — wiring it into the live handshake
(which touches the handshake's emission/legality proofs) is the next milestone.
This module is proven in isolation first.

Properties proved (`Kroopt.Proofs.KeyScheduleDriver`):

* **schedule-ops only** — every op emitted is an ECDHE/HKDF/install op, never an
  AEAD, signature, or any non-schedule op. This is the discipline the eventual
  `step` integration relies on to preserve "no plaintext before connected".
* **monotone progress** — each accepted result advances the phase by exactly one
  rank, so the schedule is finite and terminates.
* **`complete` is absorbing** — once finished, further results emit nothing.
-/

namespace Kroopt.Core.KeyScheduleDriver

open Kroopt (TlsError)
open Kroopt.Core (CryptoOp CryptoResult SecretKeyHandle HashAlgorithm CipherSuite
  Direction Epoch)

/-- Which derivation result the driver is currently awaiting. The phases form a
single linear chain from the ECDHE share through to the installed application
keys (RFC 8446 §7.1). -/
inductive Phase where
  | awaitShared
  | awaitEarly
  | awaitDerivedHs
  | awaitHandshake
  | awaitServerHs
  | awaitClientHs
  | awaitInstallWriteHs
  | awaitInstallReadHs
  | handshakeKeysInstalled
  | awaitDerivedMs
  | awaitMaster
  | awaitServerAp
  | awaitClientAp
  | awaitInstallWriteAp
  | awaitInstallReadAp
  | complete
  deriving DecidableEq, Repr, Inhabited

/-- Position of a phase in the chain (0 = first await, 15 = complete). Strictly
increasing along the schedule. `handshakeKeysInstalled` (rank 8) is the pause
between the handshake-key stage and the application-key stage. -/
def Phase.rank : Phase → Nat
  | awaitShared => 0
  | awaitEarly => 1
  | awaitDerivedHs => 2
  | awaitHandshake => 3
  | awaitServerHs => 4
  | awaitClientHs => 5
  | awaitInstallWriteHs => 6
  | awaitInstallReadHs => 7
  | handshakeKeysInstalled => 8
  | awaitDerivedMs => 9
  | awaitMaster => 10
  | awaitServerAp => 11
  | awaitClientAp => 12
  | awaitInstallWriteAp => 13
  | awaitInstallReadAp => 14
  | complete => 15

/-- Secret handles collected as the schedule runs. Each is filled when its
producing operation's result is accepted. -/
structure Handles where
  shared    : Option SecretKeyHandle := none
  early     : Option SecretKeyHandle := none
  derivedHs : Option SecretKeyHandle := none
  handshake : Option SecretKeyHandle := none
  sHs       : Option SecretKeyHandle := none
  cHs       : Option SecretKeyHandle := none
  derivedMs : Option SecretKeyHandle := none
  master    : Option SecretKeyHandle := none
  sAp       : Option SecretKeyHandle := none
  cAp       : Option SecretKeyHandle := none
  deriving Inhabited

/-- The orchestrator state: the current phase, the handles collected so far, and
the fixed protocol parameters the schedule expands over (the negotiated suite, the
empty-transcript hash for the two `"derived"` steps, and the CH..SH / CH..SF
transcript hashes for the traffic-secret derivations). -/
structure State where
  phase     : Phase
  handles   : Handles
  suite     : CipherSuite
  emptyHash : ByteArray
  hsTranscript : ByteArray
  /-- The CH..server-Finished transcript hash, not known when the handshake-key
  stage starts; supplied later by `resumeApplication`. -/
  apTranscript : ByteArray := ByteArray.empty
  deriving Inhabited

/-- Whether an op is a legitimate key-schedule op (the only kinds the driver ever
emits): ECDHE, HKDF-Extract, HKDF-Expand-Label, or traffic-key install. Notably
excludes AEAD, signatures, and randomness. -/
def isScheduleOp : CryptoOp → Bool
  | .ecdheX25519 _ => true
  | .hkdfExtract _ _ _ => true
  | .hkdfExpandLabel _ _ _ _ _ => true
  | .installTrafficKeys _ _ _ _ => true
  | _ => false

/-- Begin the handshake-key stage: emit the ECDHE operation and await its result.
The application transcript is not yet known and is supplied later by
`resumeApplication`. -/
def start (suite : CipherSuite) (peerShare emptyHash hsTranscript : ByteArray) :
    State × CryptoOp :=
  ({ phase := .awaitShared, handles := {}, suite := suite, emptyHash := emptyHash,
     hsTranscript := hsTranscript },
   CryptoOp.ecdheX25519 peerShare)

/-- Helper: an HKDF-Expand-Label op for a 32-byte secret derivation. -/
def expand (secret : SecretKeyHandle) (label : String) (ctx : ByteArray) :
    CryptoOp :=
  CryptoOp.hkdfExpandLabel .sha256 secret label ctx 32

/-- Consume the awaited crypto result, store the handle it yields, and emit the
next operation in the schedule. An unexpected result for the current phase is a
typed invariant failure (mirrors operation-id correlation discipline). -/
def advance (s : State) (r : CryptoResult) : Except TlsError (State × List CryptoOp) :=
  let h := s.handles
  match s.phase, r with
  | .awaitShared, .ecdheComplete _ sh =>
      let h := { h with shared := some sh }
      .ok ({ s with phase := .awaitEarly, handles := h },
           [CryptoOp.hkdfExtract .sha256 none none])
  | .awaitEarly, .hkdfSecret e =>
      let h := { h with early := some e }
      .ok ({ s with phase := .awaitDerivedHs, handles := h }, [expand e "derived" s.emptyHash])
  | .awaitDerivedHs, .hkdfSecret d =>
      let h := { h with derivedHs := some d }
      .ok ({ s with phase := .awaitHandshake, handles := h },
           [CryptoOp.hkdfExtract .sha256 (some d) h.shared])
  | .awaitHandshake, .hkdfSecret hs =>
      let h := { h with handshake := some hs }
      .ok ({ s with phase := .awaitServerHs, handles := h },
           [expand hs "s hs traffic" s.hsTranscript])
  | .awaitServerHs, .hkdfSecret shs =>
      let h := { h with sHs := some shs }
      .ok ({ s with phase := .awaitClientHs, handles := h },
           [expand (h.handshake.getD shs) "c hs traffic" s.hsTranscript])
  | .awaitClientHs, .hkdfSecret chs =>
      let h := { h with cHs := some chs }
      .ok ({ s with phase := .awaitInstallWriteHs, handles := h },
           [CryptoOp.installTrafficKeys s.suite .write .handshake (h.sHs.getD chs)])
  | .awaitInstallWriteHs, .keysInstalled =>
      .ok ({ s with phase := .awaitInstallReadHs },
           [CryptoOp.installTrafficKeys s.suite .read .handshake (h.cHs.getD ⟨0, 0⟩)])
  | .awaitInstallReadHs, .keysInstalled =>
      -- handshake-key stage complete; pause until the application transcript is
      -- known (the server flight must be committed first). `resumeApplication`
      -- drives the rest.
      .ok ({ s with phase := .handshakeKeysInstalled }, [])
  | .handshakeKeysInstalled, _ => .ok (s, [])
  | .awaitDerivedMs, .hkdfSecret d =>
      let h := { h with derivedMs := some d }
      .ok ({ s with phase := .awaitMaster, handles := h },
           [CryptoOp.hkdfExtract .sha256 (some d) none])
  | .awaitMaster, .hkdfSecret m =>
      let h := { h with master := some m }
      .ok ({ s with phase := .awaitServerAp, handles := h },
           [expand m "s ap traffic" s.apTranscript])
  | .awaitServerAp, .hkdfSecret sap =>
      let h := { h with sAp := some sap }
      .ok ({ s with phase := .awaitClientAp, handles := h },
           [expand (h.master.getD sap) "c ap traffic" s.apTranscript])
  | .awaitClientAp, .hkdfSecret cap =>
      let h := { h with cAp := some cap }
      .ok ({ s with phase := .awaitInstallWriteAp, handles := h },
           [CryptoOp.installTrafficKeys s.suite .write .application (h.sAp.getD cap)])
  | .awaitInstallWriteAp, .keysInstalled =>
      .ok ({ s with phase := .awaitInstallReadAp },
           [CryptoOp.installTrafficKeys s.suite .read .application (h.cAp.getD ⟨0, 0⟩)])
  | .awaitInstallReadAp, .keysInstalled =>
      .ok ({ s with phase := .complete }, [])
  | .complete, _ => .ok (s, [])
  | _, _ => .error .internalInvariantFailure

/-- Begin the application-key stage. Called once the server flight is committed
and the CH..server-Finished transcript hash is known. Requires the handshake-key
stage to have finished (`handshakeKeysInstalled`); records the application
transcript and emits the Derive-Secret(handshake, "derived") op that opens the
master-secret chain. -/
def resumeApplication (s : State) (apTranscript : ByteArray) :
    Except TlsError (State × List CryptoOp) :=
  if s.phase = .handshakeKeysInstalled then
    .ok ({ s with phase := .awaitDerivedMs, apTranscript := apTranscript },
         [expand (s.handles.handshake.getD ⟨0, 0⟩) "derived" s.emptyHash])
  else
    .error .internalInvariantFailure

end Kroopt.Core.KeyScheduleDriver
