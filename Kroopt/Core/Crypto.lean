import Kroopt.Error
import Kroopt.Core.Id
import Kroopt.Core.CipherSuite
import Kroopt.Core.Record

/-!
# Kroopt.Core.Crypto

Crypto operation shapes (RFC 002 §3.1 crypto-as-action, RFC 005 §3/§6, RFC 008).

The verified core never calls crypto. It emits `CryptoOp` (inside a `callCrypto`
action) and consumes `CryptoResult` (inside a `cryptoResult` event), correlated
by `OperationId`. This module defines those shapes plus the non-printable
`SecretKeyHandle`.

**Secret discipline (RFC 018 §3.5).** `SecretKeyHandle`, `CryptoOp`, and
`CryptoResult` deliberately do **not** derive `Repr`, `ToString`, `BEq`, or
`Hashable`: they reference secret bytes or plaintext and must never be printable
or serializable. Only `Inhabited` (a non-leaking default) is provided where a
default value is structurally required.
-/

namespace Kroopt.Core

/-- Opaque reference to secret bytes owned by the crypto provider / secret arena
(RFC 008 §6, RFC 013 §13). Carries only a non-secret id and generation. No
printable/serializable instances by construction (RFC 018 §3.5). -/
structure SecretKeyHandle where
  id : UInt64
  generation : UInt64
  deriving Inhabited

/-- What a record's plaintext is (used as AEAD inner content type and to gate
inner-content-type validation). -/
inductive RecordContentRole where
  | handshake
  | applicationData
  | alert
  deriving DecidableEq, Repr, Inhabited

/-- Non-secret metadata attached to every record seal/open so the interpreter
and provider can reject misuse, and so proofs can reason about direction/epoch
without touching key bytes (RFC 005 §6). -/
structure RecordCryptoMeta where
  conn : ConnId
  direction : Direction
  epoch : Epoch
  seq : SeqNo
  suite : CipherSuite
  contentRole : RecordContentRole
  deriving Repr, Inhabited

/-- A purpose tag for a crypto operation, stored in the pending-op table without
the operation's secret-bearing payload (RFC 008 §6). -/
inductive CryptoOpKind where
  | randomBytes
  | ecdhe
  | hkdfExtract
  | hkdfExpand
  | aeadSeal
  | aeadOpen
  | signCertificateVerify
  | verifyFinished
  deriving DecidableEq, Repr, Inhabited

/-- A crypto operation the core asks the interpreter to perform. Typed by
purpose — no generic `call(name, bytes)` (RFC 008 §4). Carries plaintext /
ciphertext / public shares; not printable (RFC 018). -/
inductive CryptoOp where
  | randomBytes (len : Nat)
  | ecdheX25519 (peerShare : ByteArray)
  | hkdfExtract (alg : HashAlgorithm)
  | hkdfExpandLabel (alg : HashAlgorithm) (len : Nat)
  | aeadSeal (meta : RecordCryptoMeta) (aad : ByteArray) (plaintext : ByteArray)
  | aeadOpen (meta : RecordCryptoMeta) (aad : ByteArray) (ciphertext : ByteArray)
  | signCertificateVerify (scheme : SignatureScheme) (input : ByteArray)
  | verifyFinished (alg : HashAlgorithm) (transcriptHash : ByteArray) (received : ByteArray)

namespace CryptoOp

/-- The purpose tag of an operation, for pending-op correlation. -/
def kind : CryptoOp → CryptoOpKind
  | randomBytes _              => .randomBytes
  | ecdheX25519 _              => .ecdhe
  | hkdfExtract _              => .hkdfExtract
  | hkdfExpandLabel _ _        => .hkdfExpand
  | aeadSeal _ _ _             => .aeadSeal
  | aeadOpen _ _ _             => .aeadOpen
  | signCertificateVerify _ _  => .signCertificateVerify
  | verifyFinished _ _ _       => .verifyFinished

end CryptoOp

/-- A correlated crypto result re-entering the core. Accepted only if it matches
the pending op's id, kind, epoch, and direction (RFC 008 §5). Not printable. -/
inductive CryptoResult where
  | randomBytes (b : ByteArray)
  | sharedSecret (h : SecretKeyHandle)
  | hkdfSecret (h : SecretKeyHandle)
  | aeadSealed (ciphertext : ByteArray)
  | aeadOpened (plaintext : ByteArray)
  | signature (bytes : ByteArray)
  | verified
  | verifyFailed
  | failed (e : CryptoError)

/-- A pending crypto operation awaiting its result. Stores only the expected
non-secret metadata so a returning result can be matched and stale/wrong-kind
results rejected (RFC 005 §3, RFC 008 §6). -/
structure PendingCryptoOp where
  id : OperationId
  expectedKind : CryptoOpKind
  expectedEpoch : Epoch
  expectedDirection : Option Direction
  deriving Repr, Inhabited

/-- The set of outstanding crypto operations for a connection. Bounded by
`ResourceLimits.maxPendingCryptoOps` (RFC 019). -/
structure PendingCryptoOps where
  ops : List PendingCryptoOp
  deriving Repr, Inhabited

namespace PendingCryptoOps

def empty : PendingCryptoOps := ⟨[]⟩

/-- Whether an operation id is outstanding. A `cryptoResult` whose id is not
outstanding is stale and must be rejected (RFC 002 §5). -/
def contains (p : PendingCryptoOps) (id : OperationId) : Bool :=
  p.ops.any (fun o => o.id == id)

end PendingCryptoOps

end Kroopt.Core
