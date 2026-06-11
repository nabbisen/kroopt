/-!
# Kroopt.Core.Record

Record-layer identity types: directions, epochs, and sequence numbers
(RFC 004 §4, RFC 005). M0 defines the types and the overflow-checked sequence
successor; the full record parse/seal/open orchestration arrives at M2 (RFC 004).

The key safety property seeded here is **no silent sequence wrap**: `SeqNo.next`
returns `none` at the maximum value so the core can fail fatally before deriving
a nonce from a wrapped sequence (RFC 005 §7.2).
-/

namespace Kroopt.Core

/-- Record direction. Read and write never share a sequence counter (RFC 005). -/
inductive Direction where
  | read
  | write
  deriving DecidableEq, Repr, Inhabited

/-- Key epoch. `initial` carries no AEAD keys (plaintext handshake records);
`handshake` and `application` each have their own keys and sequence space
(RFC 004 §4, RFC 005 §4). -/
inductive Epoch where
  | initial
  | handshake
  | application
  deriving DecidableEq, Repr, Inhabited

/-- Per-direction, per-epoch record sequence number. -/
structure SeqNo where
  value : UInt64
  deriving DecidableEq, Repr, Inhabited

namespace SeqNo

/-- The zero sequence number installed on every epoch change (RFC 005 §4). -/
def zero : SeqNo := ⟨0⟩

/-- Overflow-checked successor. Returns `none` exactly when the value is at the
`UInt64` maximum (where `value + 1` wraps to `0`), so the core can treat
overflow as fatal **before** any nonce is derived from a reused position
(RFC 005 §7.2). Never silently wraps. -/
def next (s : SeqNo) : Option SeqNo :=
  let v := s.value + 1
  if v = 0 then none else some ⟨v⟩

/-- Sanity: succeeding `zero` yields sequence `1`, never `none`. -/
theorem next_zero : next zero = some ⟨1⟩ := by
  simp [next, zero]

end SeqNo

/-- Per-direction record state: which epoch is installed, the current sequence
number, and whether AEAD keys exist for it yet. -/
structure EpochState where
  epoch : Epoch
  seq : SeqNo
  keysInstalled : Bool
  deriving Repr, Inhabited

namespace EpochState

/-- Initial state for a fresh direction: plaintext epoch, sequence zero, no keys. -/
def fresh : EpochState :=
  { epoch := .initial, seq := SeqNo.zero, keysInstalled := false }

end EpochState

end Kroopt.Core
