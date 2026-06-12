import Kroopt.Crypto.Hacl
import Kroopt.Crypto.KeySchedule
import Kroopt.Parse.Wire

/-!
# Kroopt.Conn.Flight — real TLS 1.3 server-flight assembly (interpreter zone)

The pure verified core models the server flight with abstract handles: it does not
hold the certificate DER, the server random, the CertificateVerify signature, or
the Finished MAC. Those are real bytes the **interpreter** supplies from the crypto
provider and the configuration. This module is that supplier: it turns negotiated
parameters and real HACL crypto outputs into the exact wire bytes of the server
flight (via `Kroopt.Parse.Wire`) and the transcript hashes that bind them
(RFC 8446 §4.4).

It lives in the impure `Conn` zone (it calls FFI crypto), keeping the verified core
free of any of this. The live handshake will call these to fill in the real bytes
where the core currently commits structural placeholders; this is the component
that bridges the M26/M27 serializers to a real handshake.

The CertificateVerify content construction here is the one cross-validated against
OpenSSL in `scripts/ed25519-interop.sh` (HACL signs / OpenSSL verifies and vice
versa), so a kroopt-produced Ed25519 CertificateVerify is wire-interoperable.
-/


namespace Kroopt.Conn.Flight

open Kroopt.Crypto
open Kroopt.Parse

/-- Transcript-Hash of an ordered handshake-message list: SHA-256 of the verbatim
concatenation of the messages (RFC 8446 §4.4.1). -/
def transcriptHash (messages : List ByteArray) : ByteArray :=
  Hacl.sha256 (messages.foldl (fun (acc m : ByteArray) => acc ++ m) ByteArray.empty)

/-- The RFC 8446 §4.4.3 server CertificateVerify signed content: 64 spaces, the
context string `"TLS 1.3, server CertificateVerify"`, a `0x00` separator, then the
handshake transcript hash. (130 octets for a SHA-256 transcript.) -/
def certVerifyContent (transcriptHash : ByteArray) : ByteArray :=
  let spaces : ByteArray := ByteArray.mk (Array.mkArray 64 (0x20 : UInt8))
  let label  : ByteArray := String.toUTF8 "TLS 1.3, server CertificateVerify"
  spaces ++ label ++ ByteArray.mk #[(0x00 : UInt8)] ++ transcriptHash

/-- Sign the server CertificateVerify content with an Ed25519 certificate key
(the 32-byte seed). -/
def signCertVerify (certPriv transcriptHash : ByteArray) : ByteArray :=
  Hacl.ed25519Sign certPriv (certVerifyContent transcriptHash)

/-- Verify a server CertificateVerify signature against the leaf public key. -/
def verifyCertVerify (certPub transcriptHash sig : ByteArray) : Bool :=
  Hacl.ed25519Verify certPub (certVerifyContent transcriptHash) sig

/-- Ed25519 SignatureScheme code (RFC 8446 §4.2.3, `ed25519`). -/
def ed25519Scheme : UInt16 := 0x0807

/-- A real Ed25519 CertificateVerify handshake message over the transcript hash. -/
def certificateVerifyMessage (certPriv transcriptHash : ByteArray) : ByteArray :=
  Wire.certificateVerify ed25519Scheme (signCertVerify certPriv transcriptHash)

/-- Server Finished `verify_data` = `HMAC(finished_key, transcript_hash)`, with
`finished_key = HKDF-Expand-Label(server_hs_traffic, "finished", "", 32)`
(RFC 8446 §4.4.4). -/
def serverFinishedVerifyData (hsTrafficSecret transcriptHash : ByteArray) : ByteArray :=
  Hacl.hmac256 (KeySchedule.finishedKey hsTrafficSecret) transcriptHash

/-- A real server Finished handshake message. -/
def serverFinishedMessage (hsTrafficSecret transcriptHash : ByteArray) : ByteArray :=
  Wire.finished (serverFinishedVerifyData hsTrafficSecret transcriptHash)

/-- A real ServerHello handshake message from negotiated parameters and the
server's ephemeral x25519 share. -/
def serverHelloMessage (random share : ByteArray) (suite group version : UInt16) : ByteArray :=
  Wire.serverHello random ByteArray.empty suite group share version

end Kroopt.Conn.Flight
