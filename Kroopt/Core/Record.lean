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

/-! ## TLS 1.3 record model (RFC 004 §3)

TLS 1.3 records are subtle: a protected record has an **outer** content type of
`application_data`, while the **true inner** content type lives inside the
authenticated plaintext. The three record types below keep that distinction
explicit so the parser cannot confuse a protected record with a real
application-data record (RFC 004 §3). -/

/-- TLS record content type (the wire byte). `invalid` is kept as an explicit
rejected value so an unknown byte never silently aliases a real type. -/
inductive ContentType where
  | changeCipherSpec
  | alert
  | handshake
  | applicationData
  | invalid
  deriving DecidableEq, Repr, Inhabited

namespace ContentType

/-- Wire byte for a content type (RFC 8446 §5.1). -/
def toByte : ContentType → UInt8
  | changeCipherSpec => 20
  | alert            => 21
  | handshake        => 22
  | applicationData  => 23
  | invalid          => 255

/-- Decode a content-type byte; unknown values become `invalid` (rejected later,
never treated as a valid type). -/
def ofByte (b : UInt8) : ContentType :=
  if b == 20 then changeCipherSpec
  else if b == 21 then alert
  else if b == 22 then handshake
  else if b == 23 then applicationData
  else invalid

end ContentType

/-- Maximum `TLSPlaintext.fragment` length: 2¹⁴ (RFC 8446 §5.1). -/
def maxPlaintextFragment : Nat := 16384

/-- Maximum `TLSCiphertext` protected-record length: 2¹⁴ + 256, accounting for
the inner content-type byte, padding, and AEAD expansion (RFC 8446 §5.2). -/
def maxCiphertextFragment : Nat := 16384 + 256

/-- A byte string with a compile-time-tracked maximum length. The bound is a
field, so an over-length record body is unconstructable — the record size limit
is enforced *by construction* (RFC 004 §14, mirroring the parser's `Reader`). -/
structure BoundedBytes (maxLen : Nat) where
  bytes : ByteArray
  bound : bytes.size ≤ maxLen

namespace BoundedBytes

/-- Validate a byte string against the bound, or reject it. -/
def ofBytes? (maxLen : Nat) (b : ByteArray) : Option (BoundedBytes maxLen) :=
  if h : b.size ≤ maxLen then some ⟨b, h⟩ else none

/-- The empty bounded string (always valid). -/
def empty (maxLen : Nat) : BoundedBytes maxLen :=
  ⟨ByteArray.mk #[], Nat.zero_le _⟩

/-- The size of a bounded string never exceeds its bound — by construction. -/
theorem size_le (maxLen : Nat) (bb : BoundedBytes maxLen) : bb.bytes.size ≤ maxLen :=
  bb.bound

end BoundedBytes

/-- An unprotected record: a real content type with a size-bounded fragment.
Used for plaintext handshake records before keys are installed (RFC 004 §3). -/
structure TLSPlaintext where
  ctype : ContentType
  legacyRecordVersion : UInt16
  fragment : BoundedBytes maxPlaintextFragment

/-- The decrypted contents of a protected record: the real `content`, the real
inner `ctype`, and the zero-padding length (RFC 004 §3). The inner content type
is what gates application-plaintext emission. -/
structure TLSInnerPlaintext where
  content : ByteArray
  ctype : ContentType
  paddingZeros : Nat

/-- A protected record on the wire. `opaqueType` is always `applicationData` for
TLS 1.3 protected records; the real type is inside `encryptedRecord` after AEAD
open (RFC 004 §3). -/
structure TLSCiphertext where
  opaqueType : ContentType
  legacyRecordVersion : UInt16
  encryptedRecord : BoundedBytes maxCiphertextFragment

end Kroopt.Core
