/-!
# Kroopt.Parse.Wire — TLS 1.3 handshake wire serialization (RFC 8446 §4)

Pure byte builders: the serialization counterpart to the bounds-safe `Reader`
parser. The verified core decides *what* to send; this module turns those
decisions into exact TLS 1.3 wire bytes. Serialization has no over-read risk, so
these are total `ByteArray` functions with no proof obligations.

Validated byte-for-byte against the RFC 8448 §3 "Simple 1-RTT Handshake" trace in
`Tests.Wire` — including that `SHA-256(ClientHello ‖ ServerHello)` equals the
RFC 8448 CH‥ServerHello transcript hash the key schedule already derives over.

This replaces the structural placeholder frames (e.g. `frameServerHello`) used by
the synthetic handshake; wiring it into the live handshake transcript is a
follow-up so the real handshake produces real wire bytes a TLS peer accepts.
-/

namespace Kroopt.Parse.Wire

/-- Big-endian 2-byte encoding of a `UInt16`. -/
def be16 (n : UInt16) : ByteArray :=
  ByteArray.mk #[(n >>> 8).toUInt8, n.toUInt8]

/-- Big-endian 3-byte encoding of a length (caller ensures `n < 2^24`). -/
def be24 (n : Nat) : ByteArray :=
  ByteArray.mk #[(n >>> 16).toUInt8, (n >>> 8).toUInt8, n.toUInt8]

/-- A TLS vector: `body` prefixed with its byte length as one big-endian byte. -/
def u8Len (body : ByteArray) : ByteArray :=
  ByteArray.mk #[body.size.toUInt8] ++ body

/-- A TLS vector: `body` prefixed with its byte length as two big-endian bytes. -/
def u16Len (body : ByteArray) : ByteArray :=
  be16 body.size.toUInt16 ++ body

/-- A TLS vector: `body` prefixed with its byte length as three big-endian bytes. -/
def u24Len (body : ByteArray) : ByteArray :=
  be24 body.size ++ body

/-- A handshake message: 1-byte `msgType`, 3-byte length, body (RFC 8446 §4). -/
def handshake (msgType : UInt8) (body : ByteArray) : ByteArray :=
  ByteArray.mk #[msgType] ++ u24Len body

/-- A TLS extension: 2-byte type, 2-byte length, `data` (RFC 8446 §4.2). -/
def extension (extType : UInt16) (data : ByteArray) : ByteArray :=
  be16 extType ++ u16Len data

/-- A `key_share` KeyShareEntry: named group then a 2-byte-vector key_exchange
(RFC 8446 §4.2.8). -/
def keyShareEntry (group : UInt16) (keyExchange : ByteArray) : ByteArray :=
  be16 group ++ u16Len keyExchange

/-- Serialize a TLS 1.3 ServerHello (RFC 8446 §4.1.3) to exact wire bytes.
`legacy_version` is fixed `0x0303` and `legacy_compression_method` is `0`; the
extensions are `key_share` then `supported_versions`, matching RFC 8448 §3. -/
def serverHello (random : ByteArray) (sessionIdEcho : ByteArray)
    (cipherSuite : UInt16) (group : UInt16) (keyShare : ByteArray)
    (selectedVersion : UInt16) : ByteArray :=
  let exts : ByteArray :=
    extension 0x0033 (keyShareEntry group keyShare)
      ++ extension 0x002b (be16 selectedVersion)
  let body : ByteArray :=
    be16 0x0303
      ++ random
      ++ u8Len sessionIdEcho
      ++ be16 cipherSuite
      ++ ByteArray.mk #[(0x00 : UInt8)]   -- legacy_compression_method
      ++ u16Len exts
  handshake 0x02 body

/-- EncryptedExtensions (RFC 8446 §4.3.1): type 8, body is a 2-byte-vector of
extension bytes (empty in the simple handshake → `08 00 00 02 00 00`). -/
def encryptedExtensions (exts : ByteArray) : ByteArray :=
  handshake 0x08 (u16Len exts)

/-- A Finished message (RFC 8446 §4.4.4): type 20, body = `verify_data`. -/
def finished (verifyData : ByteArray) : ByteArray :=
  handshake 0x14 verifyData

end Kroopt.Parse.Wire
