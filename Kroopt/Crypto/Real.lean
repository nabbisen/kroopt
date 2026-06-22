import Kroopt.Crypto.Arena
import Kroopt.Crypto.KeySchedule
import Kroopt.Crypto.Hacl
import Kroopt.Core.Record
import Kroopt.Core.Crypto

/-!
# Kroopt.Crypto.Real

The real-crypto layer that closes the loop the fake never could: traffic keys
derived by the key schedule are *installed into the secret arena* under opaque
handles, then read back by handle to seal/open records with the native HACL
ChaCha20-Poly1305 AEAD. This demonstrates real key material flowing through the
arena from derivation to use — the point of making the crypto seam stateful.

Record nonce per RFC 8446 §5.3: the per-record sequence number, encoded big-
endian and left-padded to the IV length, XORed with the static write IV.

What this is *not* yet: driven by the verified core. The core's current
`CryptoOp`s carry no key handles or labels, so it cannot yet emit the
install/seal/open calls below. Wiring that (enriching the ops and re-proving
operation-id correlation over the richer shapes) is the next milestone; this
module proves the crypto engine and arena are ready for it.
-/

namespace Kroopt.Crypto.Real

open Kroopt (CryptoError)
open Kroopt.Core (Direction Epoch SeqNo SecretKeyHandle RecordCryptoMeta CipherSuite)
open Kroopt.Crypto (SecretArena)

/-- A per-(direction, epoch) installed AEAD key and IV, referenced by handle so
the key bytes live only in the arena. -/
structure TrafficKeyEntry where
  dir       : Direction
  epoch     : Epoch
  suite     : CipherSuite
  keyHandle : SecretKeyHandle
  ivHandle  : SecretKeyHandle

/-- The installed traffic keys for a connection. -/
structure KeyStore where
  entries : List TrafficKeyEntry := []
  deriving Inhabited

/-- Per-record nonce (RFC 8446 §5.3): IV XOR big-endian(seq), seq in the low 8
bytes of the 12-byte IV. -/
def nonce (iv : ByteArray) (seq : UInt64) : ByteArray := Id.run do
  let mut out := iv
  let n := iv.size
  let mut s := seq
  let mut i := 0
  while i < 8 do
    if n ≥ 1 + i then
      let idx := n - 1 - i
      out := out.set! idx ((out.get! idx) ^^^ (s % 256).toUInt8)
    s := s / 256
    i := i + 1
  return out

/-- Install a derived traffic key and IV for a (direction, epoch) into the arena,
returning the updated arena and key store. The key bytes never leave the arena. -/
def install (a : SecretArena) (ks : KeyStore) (dir : Direction) (epoch : Epoch)
    (suite : CipherSuite) (key iv : ByteArray) :
    Except CryptoError (SecretArena × KeyStore) := do
  let (kh, a1) ← a.store key
  let (ih, a2) ← a1.store iv
  .ok (a2, { entries := ⟨dir, epoch, suite, kh, ih⟩ :: ks.entries })

/-- Find the installed key for a (direction, epoch). -/
def find? (ks : KeyStore) (dir : Direction) (epoch : Epoch) : Option TrafficKeyEntry :=
  ks.entries.find? (fun e => decide (e.dir = dir) && decide (e.epoch = epoch))

/-- AEAD seal dispatched by cipher suite: AES-128/256-GCM via the HACL*/EverCrypt Vale path,
ChaCha20-Poly1305 directly. The FFI wrappers fail closed on a wrong-size key, so a suite/key
mismatch can never emit ciphertext under the wrong primitive. -/
def aeadSealBySuite (suite : CipherSuite) (key nonce aad pt : ByteArray) : ByteArray :=
  match suite with
  | .aes128GcmSha256        => Hacl.aes128GcmSeal key nonce aad pt
  | .aes256GcmSha384        => Hacl.aes256GcmSeal key nonce aad pt
  | .chacha20Poly1305Sha256 => Hacl.chachaPolySeal key nonce aad pt

/-- AEAD open dispatched by cipher suite. `none` on authentication failure — no plaintext escapes. -/
def aeadOpenBySuite (suite : CipherSuite) (key nonce aad ctTag : ByteArray) : Option ByteArray :=
  match suite with
  | .aes128GcmSha256        => Hacl.aes128GcmOpen key nonce aad ctTag
  | .aes256GcmSha384        => Hacl.aes256GcmOpen key nonce aad ctTag
  | .chacha20Poly1305Sha256 => Hacl.chachaPolyOpen key nonce aad ctTag

/-- Seal a record: look up the key/IV for the record's direction and epoch in the
arena, derive the nonce from the sequence number, and AEAD-encrypt. Returns
ciphertext++tag. -/
def sealRecord (a : SecretArena) (ks : KeyStore) (meta : RecordCryptoMeta)
    (aad plaintext : ByteArray) : Except CryptoError ByteArray :=
  match find? ks meta.direction meta.epoch with
  | none => .error .invalidHandle
  | some e =>
    match a.get e.keyHandle, a.get e.ivHandle with
    | some key, some iv => .ok (aeadSealBySuite meta.suite key (nonce iv meta.seq.value) aad plaintext)
    | _, _ => .error .invalidHandle

/-- Open a record: look up the key/IV, derive the nonce, AEAD-decrypt. Returns
authenticated plaintext, or `authFailed` (no plaintext escapes on failure). -/
def openRecord (a : SecretArena) (ks : KeyStore) (meta : RecordCryptoMeta)
    (aad ciphertextAndTag : ByteArray) : Except CryptoError ByteArray :=
  match find? ks meta.direction meta.epoch with
  | none => .error .invalidHandle
  | some e =>
    match a.get e.keyHandle, a.get e.ivHandle with
    | some key, some iv =>
      match aeadOpenBySuite meta.suite key (nonce iv meta.seq.value) aad ciphertextAndTag with
      | some pt => .ok pt
      | none => .error .authFailed
    | _, _ => .error .invalidHandle

end Kroopt.Crypto.Real
