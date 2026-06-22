import Kroopt.Core.CipherSuite
import Kroopt.Core.Record

/-!
# Kroopt.Core.Transcript

Transcript state over **exact wire bytes** (RFC 007). TLS 1.3 security depends on
hashing the exact ordered handshake bytes: kroopt must never parse a message,
reconstruct it later, and assume the reconstruction is transcript-equivalent.
Parser normalization, extension reordering, padding, or DER differences would
make the verification transcript diverge from the peer's.

This module follows RFC 007 §9.1's proof-friendly approach: the proof model is an
abstract ordered sequence of the *exact* bytes committed, with non-secret event
metadata. (The runtime keeps a provider-backed digest handle in parallel; the
append calls are the correspondence point, checked by tests.) The binding
discipline is enforced by construction — append functions take only a
`ByteArray`, and parser output is carried in a `WireBound` whose `wireBytes` are
the exact consumed slice.
-/

namespace Kroopt.Core

/-- A value paired with the exact wire bytes it was parsed from or framed to.
The *only* bytes that may enter the transcript are these — a structured value
alone is never sufficient (RFC 007 §6). -/
structure WireBound (α : Type) where
  value : α
  wireBytes : ByteArray

/-- The TLS 1.3 handshake message kinds that enter the server-path transcript
(RFC 007 §3). -/
inductive HandshakeMessageType where
  | clientHello
  | serverHello
  | encryptedExtensions
  | certificate
  | certificateVerify
  | finished
  deriving DecidableEq, Repr, Inhabited

/-- Reference to a provider-backed running transcript digest. Non-secret id. -/
structure TranscriptDigestHandle where
  id : UInt64
  deriving DecidableEq, Repr, Inhabited

/-- Non-secret per-event metadata (RFC 007 §3, §9.2): message kind, direction,
and byte length. Never carries raw attacker bytes or secret-derived values. -/
structure TranscriptEventMeta where
  kind : HandshakeMessageType
  direction : Direction
  length : Nat
  deriving DecidableEq, Repr, Inhabited

/-- One committed transcript event: its non-secret metadata together with the
exact wire bytes (the proof model stores them to make exact-byte binding a
provable structural fact). -/
structure TranscriptEvent where
  meta : TranscriptEventMeta
  wireBytes : ByteArray

/-- Transcript state. `events` is the ordered sequence of committed messages with
their exact bytes; `snapshotCounter` issues monotone snapshot ids that pin a
transcript-bound crypto operation to the exact prefix it was computed over
(RFC 007 §7). -/
structure TranscriptState where
  hashAlg : HashAlgorithm
  events : List TranscriptEvent
  snapshotCounter : UInt64

namespace TranscriptState

/-- A fresh transcript for a selected hash algorithm. -/
def fresh (alg : HashAlgorithm) : TranscriptState :=
  { hashAlg := alg, events := [], snapshotCounter := 0 }

/-- The number of committed messages so far. -/
def eventCount (ts : TranscriptState) : Nat := ts.events.length

/-- The total committed length (sum of exact event byte lengths). -/
def committedLength (ts : TranscriptState) : Nat :=
  (ts.events.map (fun e => e.wireBytes.size)).foldl (· + ·) 0

/-- Append a framed (kerver-generated) handshake message from its exact emitted
bytes (RFC 007 §4). The bytes are stored verbatim — the binding is structural. -/
def appendFramed (ts : TranscriptState) (kind : HandshakeMessageType)
    (dir : Direction) (wire : ByteArray) : TranscriptState :=
  { ts with events := ts.events ++ [⟨⟨kind, dir, wire.size⟩, wire⟩] }

/-- Append a parsed (peer) handshake message using the **exact consumed slice**
carried by its `WireBound`, never a reconstruction (RFC 007 §6). -/
def appendParsed {α : Type} (ts : TranscriptState) (kind : HandshakeMessageType)
    (dir : Direction) (parsed : WireBound α) : TranscriptState :=
  appendFramed ts kind dir parsed.wireBytes

end TranscriptState

/-- A transcript snapshot pins a crypto operation to the exact committed prefix
(RFC 007 §7). `eventCount` is the number of messages committed at snapshot time. -/
structure TranscriptSnapshot where
  id : UInt64
  hashAlg : HashAlgorithm
  eventCount : Nat
  deriving DecidableEq, Repr, Inhabited

namespace TranscriptState

/-- Take a snapshot of the current transcript and advance the snapshot counter.
The snapshot's `eventCount` is the count *before* any subsequent append, so a
Finished/CertificateVerify input built from it covers exactly the prefix up to
(not including) the message being produced (RFC 007 §4, §8). -/
def snapshot (ts : TranscriptState) : TranscriptSnapshot × TranscriptState :=
  (⟨ts.snapshotCounter, ts.hashAlg, ts.events.length⟩,
   { ts with snapshotCounter := ts.snapshotCounter + 1 })

/-- The exact committed bytes of the prefix a snapshot pins: the concatenation, in order, of
the wire bytes of the first `snap.eventCount` events (RFC 007 §7–§8). This is the single
transcript authority a transcript-bound crypto op is hashed over — it includes the inbound
ClientHello and every server-flight message committed before the snapshot, so the interpreter
never reconstructs or re-accumulates the transcript itself (RFC 031 §3). -/
def prefixBytes (ts : TranscriptState) (snap : TranscriptSnapshot) : ByteArray :=
  (ts.events.take snap.eventCount).foldl (fun acc e => acc ++ e.wireBytes) (ByteArray.mk #[])

end TranscriptState

/-- The purpose a transcript-bound input serves. -/
inductive TranscriptPurpose where
  | certificateVerify
  | serverFinished
  | clientFinished
  deriving DecidableEq, Repr, Inhabited

/-- An input to a transcript-bound crypto operation: which snapshot prefix it
covers and what it is for. The provider computes the actual hash; the core only
pins the snapshot so a stale result (older snapshot) is rejected (RFC 007 §7). -/
structure TranscriptBoundInput where
  snapshot : TranscriptSnapshot
  purpose : TranscriptPurpose
  deriving DecidableEq, Repr, Inhabited

/-- Build the CertificateVerify input descriptor over a snapshot (RFC 007 §5). -/
def makeCertificateVerifyInput (snap : TranscriptSnapshot) : TranscriptBoundInput :=
  { snapshot := snap, purpose := .certificateVerify }

/-- Build a Finished input descriptor over a snapshot (RFC 007 §5). -/
def makeFinishedInput (snap : TranscriptSnapshot) (p : TranscriptPurpose) :
    TranscriptBoundInput :=
  { snapshot := snap, purpose := p }

end Kroopt.Core
