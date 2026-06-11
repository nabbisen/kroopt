import Kroopt.Crypto.Hacl
import Kroopt.Core.CipherSuite

/-!
# Kroopt.Crypto.KeySchedule

The real TLS 1.3 key schedule (RFC 8446 §7.1), computed on the native HACL*
primitives (`Kroopt.Crypto.Hacl`). This produces the genuine traffic secrets,
keys, and IVs from a real ECDHE shared secret — the thing the fake provider only
ever stubbed.

Only the SHA-256 schedule is built here (the `TLS_CHACHA20_POLY1305_SHA256` suite
with X25519); SHA-384 suites would add a parallel set once HACL HKDF-384 is
vendored. Validated end-to-end against the RFC 8448 §3 trace in
`Tests.KeySchedule`.
-/

namespace Kroopt.Crypto.KeySchedule

open Kroopt.Crypto.Hacl
open Kroopt.Core (CipherSuite)

/-- `n` zero bytes. -/
def zeros (n : Nat) : ByteArray := ByteArray.mk (Array.mkArray n 0)

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

/-- HKDF-Expand-Label (RFC 8446 §7.1). -/
def expandLabel (secret : ByteArray) (label : String) (context : ByteArray) (length : Nat) : ByteArray :=
  hkdfExpand256 secret (hkdfLabel length label context) length.toUInt32

/-- Derive-Secret(Secret, Label, Messages) = HKDF-Expand-Label(Secret, Label,
Transcript-Hash(Messages), Hash.length). Here `transcriptHash` is already the
hash of the messages. -/
def deriveSecret (secret : ByteArray) (label : String) (transcriptHash : ByteArray) : ByteArray :=
  expandLabel secret label transcriptHash 32

/-- Transcript-Hash of the empty message sequence: SHA-256(""). -/
def emptyHash : ByteArray := sha256 ByteArray.empty

/-! ## The secret chain (SHA-256) -/

/-- Early Secret = HKDF-Extract(0, 0) with no PSK. -/
def earlySecret : ByteArray := hkdfExtract256 (zeros 32) (zeros 32)

/-- Derive-Secret(Early, "derived", "") — the salt for the Handshake extract. -/
def derivedForHandshake (early : ByteArray) : ByteArray := deriveSecret early "derived" emptyHash

/-- Handshake Secret = HKDF-Extract(Derive-Secret(Early,"derived",""), ECDHE). -/
def handshakeSecret (early ecdhe : ByteArray) : ByteArray :=
  hkdfExtract256 (derivedForHandshake early) ecdhe

/-- client_handshake_traffic_secret = Derive-Secret(HS, "c hs traffic", CH..SH). -/
def clientHandshakeTrafficSecret (hs transcriptHash : ByteArray) : ByteArray :=
  deriveSecret hs "c hs traffic" transcriptHash

/-- server_handshake_traffic_secret = Derive-Secret(HS, "s hs traffic", CH..SH). -/
def serverHandshakeTrafficSecret (hs transcriptHash : ByteArray) : ByteArray :=
  deriveSecret hs "s hs traffic" transcriptHash

/-- Derive-Secret(HS, "derived", "") — the salt for the Master extract. -/
def derivedForMaster (hs : ByteArray) : ByteArray := deriveSecret hs "derived" emptyHash

/-- Master Secret = HKDF-Extract(Derive-Secret(HS,"derived",""), 0). -/
def masterSecret (hs : ByteArray) : ByteArray := hkdfExtract256 (derivedForMaster hs) (zeros 32)

/-- client_application_traffic_secret_0 = Derive-Secret(MS, "c ap traffic", CH..SF). -/
def clientAppTrafficSecret (ms transcriptHash : ByteArray) : ByteArray :=
  deriveSecret ms "c ap traffic" transcriptHash

/-- server_application_traffic_secret_0 = Derive-Secret(MS, "s ap traffic", CH..SF). -/
def serverAppTrafficSecret (ms transcriptHash : ByteArray) : ByteArray :=
  deriveSecret ms "s ap traffic" transcriptHash

/-! ## Traffic keys, IVs, and Finished keys (RFC 8446 §7.3, §4.4.4) -/

/-- AEAD key length for a suite. -/
def aeadKeyLen : CipherSuite → Nat
  | .aes128GcmSha256 => 16
  | .aes256GcmSha384 => 32
  | .chacha20Poly1305Sha256 => 32

/-- AEAD IV length (12 for all TLS 1.3 suites). -/
def aeadIvLen : Nat := 12

/-- [sender]_write_key = HKDF-Expand-Label(Secret, "key", "", key_length). -/
def trafficKey (suite : CipherSuite) (secret : ByteArray) : ByteArray :=
  expandLabel secret "key" ByteArray.empty (aeadKeyLen suite)

/-- [sender]_write_iv = HKDF-Expand-Label(Secret, "iv", "", iv_length). -/
def trafficIv (secret : ByteArray) : ByteArray :=
  expandLabel secret "iv" ByteArray.empty aeadIvLen

/-- finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length). -/
def finishedKey (secret : ByteArray) : ByteArray :=
  expandLabel secret "finished" ByteArray.empty 32

end Kroopt.Crypto.KeySchedule
