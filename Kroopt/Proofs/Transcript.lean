import Kroopt.Core.Transcript

/-!
# Kroopt.Proofs.Transcript

Transcript binding and ordering (RFC 007 §8). TLS 1.3 verification hashes the
exact ordered handshake bytes, so kroopt must (a) commit messages in order,
(b) commit the *exact* wire bytes — never a reconstruction — and (c) take the
Finished/CertificateVerify snapshot over the prefix *before* the message being
produced is appended.

These are structural facts about the append/snapshot functions, proved here so
the handshake driver cannot silently violate them.

All proofs are `sorry`/`axiom`/`unsafe`-free.
-/

namespace Kroopt.Core
namespace Proofs

open Kroopt

/-- **Exact-byte binding (RFC 007 §6).** A framed append stores the given wire
bytes verbatim as the last event — no reconstruction. -/
theorem appendFramed_binds_exact_bytes
    (ts : TranscriptState) (kind : HandshakeMessageType) (dir : Direction)
    (wire : ByteArray) :
    (ts.appendFramed kind dir wire).events.getLast?
      = some ⟨⟨kind, dir, wire.size⟩, wire⟩ := by
  unfold TranscriptState.appendFramed
  simp [List.getLast?_concat]

/-- **Parsed messages enter by their exact consumed slice (RFC 007 §6).**
`appendParsed` commits the `WireBound`'s `wireBytes`, never the structured value
re-serialized. -/
theorem appendParsed_uses_wire_bytes
    {α : Type} (ts : TranscriptState) (kind : HandshakeMessageType)
    (dir : Direction) (parsed : WireBound α) :
    (ts.appendParsed kind dir parsed).events.getLast?
      = some ⟨⟨kind, dir, parsed.wireBytes.size⟩, parsed.wireBytes⟩ := by
  unfold TranscriptState.appendParsed
  exact appendFramed_binds_exact_bytes ts kind dir parsed.wireBytes

/-- **Order preservation (RFC 007 §8).** Append extends the event sequence at the
end, preserving every earlier event in place. -/
theorem appendFramed_preserves_order
    (ts : TranscriptState) (kind : HandshakeMessageType) (dir : Direction)
    (wire : ByteArray) :
    (ts.appendFramed kind dir wire).events
      = ts.events ++ [⟨⟨kind, dir, wire.size⟩, wire⟩] := by
  unfold TranscriptState.appendFramed; rfl

/-- Append increases the committed-message count by exactly one. -/
theorem appendFramed_increments_count
    (ts : TranscriptState) (kind : HandshakeMessageType) (dir : Direction)
    (wire : ByteArray) :
    (ts.appendFramed kind dir wire).eventCount = ts.eventCount + 1 := by
  unfold TranscriptState.appendFramed TranscriptState.eventCount
  simp

/-- **Snapshot covers the current prefix (RFC 007 §8).** A snapshot's
`eventCount` is exactly the number of messages committed so far — so a Finished
or CertificateVerify input built from a snapshot taken *before* appending message
M covers the prefix up to but not including M. -/
theorem snapshot_eventCount
    (ts : TranscriptState) :
    (ts.snapshot.1).eventCount = ts.eventCount := by
  unfold TranscriptState.snapshot TranscriptState.eventCount; rfl

/-- **Snapshot does not commit anything (RFC 007 §7).** Taking a snapshot leaves
the committed event sequence unchanged; only the snapshot counter advances. So a
snapshot taken before an append, followed by the append, yields a snapshot whose
`eventCount` is one less than the post-append count — the "before this message"
discipline. -/
theorem snapshot_then_append_is_before
    (ts : TranscriptState) (kind : HandshakeMessageType) (dir : Direction)
    (wire : ByteArray) :
    let snap := ts.snapshot.1
    let ts' := (ts.snapshot.2).appendFramed kind dir wire
    snap.eventCount + 1 = ts'.eventCount := by
  simp only [TranscriptState.snapshot, TranscriptState.appendFramed,
    TranscriptState.eventCount]
  simp

end Proofs
end Kroopt.Core
