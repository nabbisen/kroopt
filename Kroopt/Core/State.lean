import Kroopt.Error
import Kroopt.Core.Id
import Kroopt.Core.CipherSuite
import Kroopt.Core.Record
import Kroopt.Core.Crypto
import Kroopt.Core.Transcript
import Kroopt.Core.Config
import Kroopt.Core.KeyScheduleDriver

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
  | requestedServerRandom
  | requestedEcdhe
  | derivedHandshakeSecrets
  | sentServerHello
  | sentEncryptedExtensions
  | sentCertificate
  | requestedCertificateVerifySignature
  | requestedServerFinishedMac
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
  selectedSni : Option ByteArray
  selectedAlpn : Option AlpnProtocol
  selectedCert : Option CertificateChainHandle
  /-- The server's ephemeral x25519 public share, captured from the ECDHE crypto result
  (RFC 8446 §4.2.8). Held here so the ServerHello it goes into can become a typed
  core-authorized action (RFC 032) rather than a placeholder. -/
  serverShare : Option ByteArray
  /-- The client's x25519 key_share, carried from the ClientHello so the ECDHE op can be
  requested after the server random is drawn (RFC 032). -/
  clientShare : Option ByteArray
  /-- The server's 32-byte Random, drawn from the CSPRNG via a core `randomBytes` op so it
  is a core value the typed ServerHello can carry (RFC 032), not interpreter-supplied. -/
  serverRandom : Option ByteArray
  /-- The public certificate-chain DER resolved for the selected endpoint (RFC 012). The core
  commits this exact byte string to its transcript and emits it in `writeCertificate`, so the
  transcript and the wire agree by construction. Empty when no chain is configured. -/
  selectedCertDer : ByteArray := ByteArray.empty
  /-- The client's `legacy_session_id`, echoed verbatim in the ServerHello's
  `legacy_session_id_echo` (RFC 8446 §4.1.3). Empty for a minimal client. -/
  clientSessionId : ByteArray := ByteArray.empty
  deriving Inhabited

namespace NegotiationState

def empty : NegotiationState :=
  { selectedSuite := none, selectedGroup := none, selectedSigScheme := none
    selectedSni := none, selectedAlpn := none, selectedCert := none
    serverShare := none, clientShare := none, serverRandom := none
    selectedCertDer := ByteArray.mk #[], clientSessionId := ByteArray.mk #[] }

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
  nextOpId : UInt64
  inboundCiphertext : ByteArray
  outboundCiphertext : ByteArray
  /-- Handshake-message reassembly buffer (RFC 033): handshake records carry an opaque
  byte stream that may split a message across records or coalesce several; this holds
  the unframed remainder between records. Bounded at runtime. -/
  handshakeReasm : ByteArray
  pendingPlainOut : Option ByteArray
  pendingClientFinished : Option ByteArray
  transcript : TranscriptState
  /-- The active key-schedule orchestrator, present while the handshake is driving
  the schedule (RFC 8446 §7.1) through `Kroopt.Core.KeyScheduleDriver`. -/
  keySched : Option KeyScheduleDriver.State := none
  negotiated : NegotiationState
  serverConfig : ValidatedServerConfig
  closeState : CloseState
  budgets : BudgetState

namespace State

/-- The initial handshaking state for a freshly accepted connection (RFC 010 §4.2):
phase `start`, both directions in the plaintext initial epoch, empty buffers, no
buffered plaintext, no pending crypto, default budgets. -/
def initial (conn : ConnId) (cfg : ConfigGeneration) (alg : HashAlgorithm) : State :=
  { connId := conn
    configGen := cfg
    handshake := .start
    readEpoch := EpochState.fresh
    writeEpoch := EpochState.fresh
    pendingOps := PendingCryptoOps.empty
    nextOpId := 0
    inboundCiphertext := ByteArray.mk #[]
    outboundCiphertext := ByteArray.mk #[]
    handshakeReasm := ByteArray.mk #[]
    pendingPlainOut := none
    pendingClientFinished := none
    transcript := TranscriptState.fresh alg
    negotiated := NegotiationState.empty
    -- A placeholder config advertising the baseline server-auth schemes. `TlsConn.server` overrides
    -- `serverConfig` with the caller's validated config before any ClientHello is processed
    -- (RFC 011 §6), so this default is only ever observed by core-level tests driving `step`.
    serverConfig := ValidatedServerConfig.baseline
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

/-- Allocate a fresh operation id and register a pending crypto operation with
its expected metadata, so the returning result can be correlated and stale or
wrong-kind results rejected (RFC 008 §5). Returns the id and the updated state. -/
def allocOp (s : State) (kind : CryptoOpKind) (epoch : Epoch)
    (dir : Option Direction) : OperationId × State :=
  let oid : OperationId := ⟨s.nextOpId⟩
  let pend : PendingCryptoOp :=
    { id := oid, expectedKind := kind, expectedEpoch := epoch, expectedDirection := dir }
  (oid, { s with nextOpId := s.nextOpId + 1
                 pendingOps := ⟨pend :: s.pendingOps.ops⟩ })

/-- Remove a pending crypto operation by id once its result has been handled. -/
def clearOp (s : State) (op : OperationId) : State :=
  { s with pendingOps := ⟨s.pendingOps.ops.filter (fun o => o.id != op)⟩ }

end State

end Kroopt.Core
