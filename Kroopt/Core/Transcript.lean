import Kroopt.Core.CipherSuite

/-!
# Kroopt.Core.Transcript

Transcript state over exact wire bytes (RFC 007). M0 defines the minimal shape:
the bound hash algorithm, a committed-byte length, and a snapshot counter for
crypto-operation correlation. The exact-byte binding discipline, append
functions, and Finished/CertificateVerify input construction arrive at M4
(RFC 007 §5).

`TranscriptDigestHandle` is a non-secret reference to a provider-backed running
digest; it is safe to hold and compare by id, but the digest *value* is never
exposed (RFC 007 §3, RFC 020 forbidden trace payloads).
-/

namespace Kroopt.Core

/-- Reference to a provider-backed running transcript digest. Non-secret id. -/
structure TranscriptDigestHandle where
  id : UInt64
  deriving DecidableEq, Repr, Inhabited

/-- Transcript state. `committedLength` counts exact wire bytes committed so
far; `snapshotCounter` issues monotone snapshot ids that pin a transcript-bound
crypto operation to the exact bytes it was computed over (RFC 007 §7). -/
structure TranscriptState where
  hashAlg : HashAlgorithm
  committedLength : Nat
  snapshotCounter : UInt64
  deriving Repr, Inhabited

namespace TranscriptState

/-- A fresh transcript for a selected hash algorithm. -/
def fresh (alg : HashAlgorithm) : TranscriptState :=
  { hashAlg := alg, committedLength := 0, snapshotCounter := 0 }

end TranscriptState

end Kroopt.Core
