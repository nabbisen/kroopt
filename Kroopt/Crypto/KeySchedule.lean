import Kroopt.Crypto.Hacl
import Kroopt.Core.CipherSuite

/-!
# Kroopt.Crypto.KeySchedule

The real TLS 1.3 key schedule (RFC 8446 §7.1), computed on the native HACL*
primitives (`Kroopt.Crypto.Hacl`). RFC 8446 §7.1 is hash-agnostic; this module is
parameterized by the negotiated suite's `HashAlgorithm` (SHA-256 or SHA-384), so the
SHA-384 suites (`TLS_AES_256_GCM_SHA384`) share one schedule with the SHA-256 ones.
Every entry point defaults to SHA-256, preserving the established SHA-256 callers
verbatim. Validated end-to-end against the RFC 8448 §3 trace in `Tests.KeySchedule`.
-/

namespace Kroopt.Crypto.KeySchedule

open Kroopt.Crypto.Hacl
open Kroopt.Core (CipherSuite HashAlgorithm)

/-- `n` zero bytes. -/
def zeros (n : Nat) : ByteArray := ByteArray.mk (Array.mkArray n 0)

/-! ## Hash-algorithm dispatch -/

/-- Output length of the transcript/HKDF hash: 32 for SHA-256, 48 for SHA-384. -/
def hashLen : HashAlgorithm → Nat
  | .sha256 => 32
  | .sha384 => 48

/-- The hash function itself. -/
def hashOf : HashAlgorithm → ByteArray → ByteArray
  | .sha256 => sha256
  | .sha384 => sha384

/-- HKDF-Extract for the schedule's hash. -/
def hkdfExtractH : HashAlgorithm → ByteArray → ByteArray → ByteArray
  | .sha256 => hkdfExtract256
  | .sha384 => hkdfExtract384

/-- HKDF-Expand for the schedule's hash. -/
def hkdfExpandH : HashAlgorithm → ByteArray → ByteArray → Nat → ByteArray
  | .sha256, prk, info, len => hkdfExpand256 prk info len.toUInt32
  | .sha384, prk, info, len => hkdfExpand384 prk info len.toUInt32

/-- HMAC for the schedule's hash (the Finished MAC, RFC 8446 §4.4.4). -/
def hmacH : HashAlgorithm → ByteArray → ByteArray → ByteArray
  | .sha256 => hmac256
  | .sha384 => hmac384

/-- HkdfLabel (RFC 8446 §7.1):
```
struct {
  uint16 length;
  opaque label<7..255> = "tls13 " + Label;
  opaque context<0..255> = Context;
} HkdfLabel;
```
-/
def hkdfLabel (length : Nat) (label : String) (context : ByteArray) : ByteArray :=
  let full := ("tls13 " ++ label).toUTF8
  let hdr := ByteArray.mk #[(length / 256 % 256).toUInt8, (length % 256).toUInt8, full.size.toUInt8]
  ((hdr ++ full).push context.size.toUInt8) ++ context

/-- HKDF-Expand-Label (RFC 8446 §7.1), under the schedule hash `h`. -/
def expandLabel (secret : ByteArray) (label : String) (context : ByteArray) (length : Nat)
    (h : HashAlgorithm := .sha256) : ByteArray :=
  hkdfExpandH h secret (hkdfLabel length label context) length

/-- Derive-Secret(Secret, Label, Messages) = HKDF-Expand-Label(Secret, Label,
Transcript-Hash(Messages), Hash.length). Here `transcriptHash` is already the
hash of the messages (computed under the same `h`). -/
def deriveSecret (secret : ByteArray) (label : String) (transcriptHash : ByteArray)
    (h : HashAlgorithm := .sha256) : ByteArray :=
  expandLabel secret label transcriptHash (hashLen h) h

/-- Transcript-Hash of the empty message sequence: Hash(""). -/
def emptyHash (h : HashAlgorithm := .sha256) : ByteArray := hashOf h ByteArray.empty

/-! ## The secret chain -/

/-- Early Secret = HKDF-Extract(0, 0) with no PSK. -/
def earlySecret (h : HashAlgorithm := .sha256) : ByteArray :=
  hkdfExtractH h (zeros (hashLen h)) (zeros (hashLen h))

/-- Derive-Secret(Early, "derived", "") — the salt for the Handshake extract. -/
def derivedForHandshake (early : ByteArray) (h : HashAlgorithm := .sha256) : ByteArray :=
  deriveSecret early "derived" (emptyHash h) h

/-- Handshake Secret = HKDF-Extract(Derive-Secret(Early,"derived",""), ECDHE). -/
def handshakeSecret (early ecdhe : ByteArray) (h : HashAlgorithm := .sha256) : ByteArray :=
  hkdfExtractH h (derivedForHandshake early h) ecdhe

/-- client_handshake_traffic_secret = Derive-Secret(HS, "c hs traffic", CH..SH). -/
def clientHandshakeTrafficSecret (hs transcriptHash : ByteArray) (h : HashAlgorithm := .sha256) : ByteArray :=
  deriveSecret hs "c hs traffic" transcriptHash h

/-- server_handshake_traffic_secret = Derive-Secret(HS, "s hs traffic", CH..SH). -/
def serverHandshakeTrafficSecret (hs transcriptHash : ByteArray) (h : HashAlgorithm := .sha256) : ByteArray :=
  deriveSecret hs "s hs traffic" transcriptHash h

/-- Derive-Secret(HS, "derived", "") — the salt for the Master extract. -/
def derivedForMaster (hs : ByteArray) (h : HashAlgorithm := .sha256) : ByteArray :=
  deriveSecret hs "derived" (emptyHash h) h

/-- Master Secret = HKDF-Extract(Derive-Secret(HS,"derived",""), 0). -/
def masterSecret (hs : ByteArray) (h : HashAlgorithm := .sha256) : ByteArray :=
  hkdfExtractH h (derivedForMaster hs h) (zeros (hashLen h))

/-- client_application_traffic_secret_0 = Derive-Secret(MS, "c ap traffic", CH..SF). -/
def clientAppTrafficSecret (ms transcriptHash : ByteArray) (h : HashAlgorithm := .sha256) : ByteArray :=
  deriveSecret ms "c ap traffic" transcriptHash h

/-- server_application_traffic_secret_0 = Derive-Secret(MS, "s ap traffic", CH..SF). -/
def serverAppTrafficSecret (ms transcriptHash : ByteArray) (h : HashAlgorithm := .sha256) : ByteArray :=
  deriveSecret ms "s ap traffic" transcriptHash h

/-! ## Traffic keys, IVs, and Finished keys (RFC 8446 §7.3, §4.4.4) -/

/-- AEAD key length for a suite. -/
def aeadKeyLen : CipherSuite → Nat
  | .aes128GcmSha256 => 16
  | .aes256GcmSha384 => 32
  | .chacha20Poly1305Sha256 => 32

/-- AEAD IV length (12 for all TLS 1.3 suites). -/
def aeadIvLen : Nat := 12

/-- [sender]_write_key = HKDF-Expand-Label(Secret, "key", "", key_length), expanded under the
suite's hash to the suite's AEAD key length. -/
def trafficKey (suite : CipherSuite) (secret : ByteArray) : ByteArray :=
  expandLabel secret "key" ByteArray.empty (aeadKeyLen suite) suite.hashAlg

/-- [sender]_write_iv = HKDF-Expand-Label(Secret, "iv", "", 12), under the schedule hash `h`. -/
def trafficIv (secret : ByteArray) (h : HashAlgorithm := .sha256) : ByteArray :=
  expandLabel secret "iv" ByteArray.empty aeadIvLen h

/-- finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length), under `h`. -/
def finishedKey (secret : ByteArray) (h : HashAlgorithm := .sha256) : ByteArray :=
  expandLabel secret "finished" ByteArray.empty (hashLen h) h

end Kroopt.Crypto.KeySchedule
