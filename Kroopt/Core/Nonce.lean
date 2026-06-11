import Kroopt.Core.Id
import Kroopt.Core.Record

/-!
# Kroopt.Core.Nonce

The nonce / key-epoch model (RFC 005 §3, §5). AEAD nonce reuse is catastrophic,
so the per-record nonce and the key-epoch identity are first-class, and the
uniqueness property is a proof target (`Kroopt.Proofs.Nonces`), not a convention.

The concrete TLS 1.3 derivation is `nonce = iv_base XOR left_pad(seq)`. For a
*fixed* IV base this map is a bijection in the sequence number, so for the
uniqueness argument the nonce is modeled as the (public) IV-base identity
together with the sequence value it is derived from (`RecordNonce`). The concrete
byte realization (`nonceBytes`) is provided for the interpreter and known-answer
tests; the security-relevant fact — distinct sequence numbers within one epoch
give distinct nonces — is proved over the model.
-/

namespace Kroopt.Core

/-- A non-secret identifier for a key epoch: which connection, direction, epoch,
and generation a traffic key belongs to (RFC 005 §3). Used to correlate nonces,
proofs, logs, and crypto-operation metadata without exposing secret bytes. -/
structure KeyEpochId where
  conn : ConnId
  direction : Direction
  epoch : Epoch
  generation : UInt64
  deriving DecidableEq, Repr, Inhabited

/-- The per-record nonce, modeled by the public IV-base identity and the sequence
value it derives from (RFC 005 §5). Two records under one fixed IV base collide
only if their sequence values collide — which the uniqueness theorem rules out. -/
structure RecordNonce where
  ivBaseId : Nat
  seqValue : UInt64
  deriving DecidableEq, Repr

/-- Derive the (modeled) nonce for a record from a fixed IV-base identity and a
sequence number. Injective in the sequence for a fixed IV base — see
`Kroopt.Proofs.Nonces.nonce_unique_within_epoch`. -/
def deriveNonce (ivBaseId : Nat) (seq : SeqNo) : RecordNonce :=
  { ivBaseId := ivBaseId, seqValue := seq.value }

/-! ## Concrete byte realization (for the interpreter and KATs)

These are the bytes the real AEAD call uses. They are not the basis of the
uniqueness proof (that is `deriveNonce`); they are the realization the FFI and
known-answer tests exercise at M6. -/

/-- The eight-byte big-endian encoding of the sequence value. -/
def seqBytesBE (seq : SeqNo) : ByteArray :=
  let v := seq.value
  ByteArray.mk #[
    (v >>> 56).toUInt8, (v >>> 48).toUInt8, (v >>> 40).toUInt8, (v >>> 32).toUInt8,
    (v >>> 24).toUInt8, (v >>> 16).toUInt8, (v >>> 8).toUInt8, v.toUInt8 ]

/-- The left-padded per-record sequence block: zero bytes then the eight-byte
big-endian sequence, to the AEAD IV length (12 for the TLS 1.3 AEADs). -/
def paddedSeqBytes (ivLen : Nat) (seq : SeqNo) : ByteArray :=
  let seqB := seqBytesBE seq
  let pad := ivLen - seqB.size
  ByteArray.mk (Array.mkArray pad 0) ++ seqB

/-- The concrete TLS 1.3 per-record nonce: `iv_base XOR left_pad(seq)`
(RFC 8446 §5.3). Computed byte-wise over the IV-length block. -/
def nonceBytes (ivBase : ByteArray) (ivLen : Nat) (seq : SeqNo) : ByteArray :=
  let padded := paddedSeqBytes ivLen seq
  ByteArray.mk (ivBase.data.zipWith padded.data (· ^^^ ·))

end Kroopt.Core
