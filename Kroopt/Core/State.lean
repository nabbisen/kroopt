import Kroopt.Error
import Kroopt.Core.Id
import Kroopt.Core.CipherSuite
import Kroopt.Core.Record
import Kroopt.Core.Crypto
import Kroopt.Core.Transcript

/-!
# Kroopt.Core.State

The single authoritative connection state (RFC 002 §4) and its component types:
the handshake phase (RFC 006 §4), close state (RFC 013 §3), negotiation result,
and resource budgets (RFC 019 §7).

`State` is the only source of protocol truth. It stores handles and abstract
identifiers, never raw long-lived secrets (RFC 002 §4). It intentionally does
**not** derive `Repr`: it transiently holds `pendingPlainOut` (authenticated
plaintext, never logged by kroopt — RFC 018 §2). A redacted summary is provided
instead for diagnostics (RFC 020 §3).
-/

namespace Kroopt.Core

open Kroopt (AlertDescription)

/-- The TLS 1.3 server handshake phases (RFC 006 §4). Phase names reflect what
has been installed/proven, not merely what was sent. `connected` is the only
phase in which application data may cross the boundary. -/
inductive HandshakeState where
  | start
  | recvdClientHello
  | requestedEcdhe
  | derivedHandshakeSecrets
  | sentServerHello
  | sentEncryptedExtensions
  | sentCertificate
  | requestedCertificateVerifySignature
  | sentCertificateVerify
  | sentServerFinished
  | requestedClientFinishedVerify
  | recvdClientFinished
  | connected
  | closing
  | closed
  | failed (alert : AlertDescription)
  deriving DecidableEq, BEq, Repr, Inhabited

namespace HandshakeState

/-- Terminal phases are absorbing: `closed` and any `failed` alert (RFC 013 §7). -/
def isTerminal : HandshakeState → Bool
  | closed   => true
  | failed _ => true
  | _        => false

/-- The single phase in which application plaintext may be emitted or accepted
(RFC 002 §7, RFC 006 §9). -/
def isConnected : HandshakeState → Bool
  | connected => true
  | _         => false

@[simp] theorem isConnected_connected : isConnected connected = true := rfl
@[simp] theorem isTerminal_closed : isTerminal closed = true := rfl
@[simp] theorem isTerminal_failed (a : AlertDescription) :
    isTerminal (failed a) = true := rfl
@[simp] theorem isConnected_start : isConnected start = false := rfl

/-- `connected` is not a terminal phase. -/
@[simp] theorem isTerminal_connected : isTerminal connected = false := rfl

end HandshakeState

/-- Close-handshake state, distinguishing graceful close, inbound close_notify,
fatal termination, and transport truncation (RFC 013 §3). -/
inductive CloseState where
  | open
  | sentCloseNotify
  | receivedCloseNotify
  | bidirectionalClose
  | transportEofBeforeCloseNotify
  | fatalSent (alert : AlertDescription)
  | fatalReceived (alert : AlertDescription)
  | transportClosed
  deriving DecidableEq, Repr, Inhabited

/-- Negotiation result so far. SNI/ALPN byte values are added at M8 (RFC 011);
M0 keeps the cryptographic selections. -/
structure NegotiationState where
  selectedSuite : Option CipherSuite
  selectedGroup : Option NamedGroup
  selectedSigScheme : Option SignatureScheme
  deriving Repr, Inhabited

namespace NegotiationState

def empty : NegotiationState :=
  { selectedSuite := none, selectedGroup := none, selectedSigScheme := none }

end NegotiationState

/-- Per-connection resource counters (RFC 019 §7). Updated before allocation
where possible; exceeding a configured limit is a terminal security failure. -/
structure BudgetState where
  handshakeBytesSeen : Nat
  clientHelloBytesSeen : Nat
  extensionsSeen : Nat
  pendingCiphertextBytes : Nat
  pendingPlaintextRecords : Nat
  pendingCryptoOps : Nat
  progressStepsThisCall : Nat
  deriving Repr, Inhabited

namespace BudgetState

def empty : BudgetState :=
  { handshakeBytesSeen := 0, clientHelloBytesSeen := 0, extensionsSeen := 0,
    pendingCiphertextBytes := 0, pendingPlaintextRecords := 0,
    pendingCryptoOps := 0, progressStepsThisCall := 0 }

end BudgetState

/-- The single authoritative connection state (RFC 002 §4).

`pendingPlainOut` holds at most one record of authenticated application
plaintext waiting for the caller's `recv` (RFC 004 §9). It is the only
caller-visible plaintext kroopt retains, and is the field whose emission is
gated to `connected` by the core (proved in `Kroopt.Proofs`). -/
structure State where
  connId : ConnId
  configGen : ConfigGeneration
  handshake : HandshakeState
  readEpoch : EpochState
  writeEpoch : EpochState
  pendingOps : PendingCryptoOps
  pendingPlainOut : Option ByteArray
  transcript : TranscriptState
  negotiated : NegotiationState
  closeState : CloseState
  budgets : BudgetState

namespace State

/-- The initial handshaking state for a freshly accepted connection (RFC 010 §4.2):
phase `start`, both directions in the plaintext initial epoch, no buffered
plaintext, no pending crypto, default budgets. -/
def initial (conn : ConnId) (cfg : ConfigGeneration) (alg : HashAlgorithm) : State :=
  { connId := conn
    configGen := cfg
    handshake := .start
    readEpoch := EpochState.fresh
    writeEpoch := EpochState.fresh
    pendingOps := PendingCryptoOps.empty
    pendingPlainOut := none
    transcript := TranscriptState.fresh alg
    negotiated := NegotiationState.empty
    closeState := .open
    budgets := BudgetState.empty }

/-- A redacted, non-secret diagnostic summary (RFC 020 §3). Never includes
`pendingPlainOut` bytes, secret handles, or transcript digests. -/
def redactedSummary (s : State) : String :=
  let plain := if s.pendingPlainOut.isSome then "buffered" else "none"
  s!"conn={s.connId.value}/{s.connId.generation} \
     phase={repr s.handshake} \
     close={repr s.closeState} \
     readEpoch={repr s.readEpoch.epoch} writeEpoch={repr s.writeEpoch.epoch} \
     pendingPlaintext={plain} \
     pendingCryptoOps={s.pendingOps.ops.length}"

end State

end Kroopt.Core
