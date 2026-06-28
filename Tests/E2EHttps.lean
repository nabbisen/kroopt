import Kroopt.Conn.Uniform
import Kroopt.Parse.Handshake

/-!
# Tests.E2EHttps

End-to-end acceptance for jemmet integration (RFC 015 §7, §10), modeled against
the fake transport and fake crypto provider (real iotakt / curl / OpenSSL interop
is the deferred v0.3 binding). A minimal "jemmet" HTTP/1.1 handler consumes the
uniform `PlainConn` abstraction; the *same* handler serves a TLS `TlsConn` and a
plaintext connection. Negative cases confirm malformed or plaintext input to the
TLS listener never reaches the handler as application bytes.
-/

namespace Tests.E2EHttps

open Kroopt Kroopt.Core Kroopt.Conn Kroopt.Crypto

structure Check where
  name : String
  ok : Bool

def bytesOf (l : List UInt8) : ByteArray := ByteArray.mk l.toArray
def u16be (n : Nat) : List UInt8 := [(n / 256).toUInt8, (n % 256).toUInt8]

-- ClientHello / client Finished records (same shape as the conn/e2e harness).
def keyShareEntry : List UInt8 := [0x00, 0x1d, 0, 32] ++ List.replicate 32 0x07  -- 32-byte x25519 share (RFC 8446 §4.2.8.2)
def extKeyShare : List UInt8 := [0, 51, 0, 38, 0, 36] ++ keyShareEntry
def extSigAlgs : List UInt8 := [0, 0x0d, 0, 4, 0, 2, 0x08, 0x07]  -- signature_algorithms: ed25519
def extSupVer : List UInt8 := [0, 43, 0, 3, 2, 0x03, 0x04]
def extGroups : List UInt8 := [0, 10, 0, 4, 0, 2, 0x00, 0x1d]  -- supported_groups: x25519 (RFC 8446 §4.2.7)
def extsBody : List UInt8 := extSupVer ++ extGroups ++ extKeyShare ++ extSigAlgs
def chBody : List UInt8 :=
  [0x03, 0x03] ++ (List.replicate 32 0xAA) ++ [0] ++
  [0, 2, 0x13, 0x03] ++ [1, 0] ++ (u16be extsBody.length ++ extsBody)
def chMsg : List UInt8 :=
  [1] ++ [0, (chBody.length / 256).toUInt8, (chBody.length % 256).toUInt8] ++ chBody
def record (ty : UInt8) (body : List UInt8) : ByteArray :=
  bytesOf ([ty, 0x03, 0x03] ++ u16be body.length ++ body)
def chRecord : ByteArray := record 22 chMsg
def clientFinishedRecord : ByteArray := record 22 ([20] ++ [0, 0, 32] ++ List.replicate 32 0x55)

-- An HTTP request, wrapped as a TLS application-data inner record (content + the
-- inner content-type byte 23), then record-framed. The fake AEAD is identity, so
-- this round-trips to the plaintext request on recv.
def httpRequest : ByteArray := "GET / HTTP/1.1\r\nHost: edge\r\n\r\n".toUTF8
def appDataRecord : ByteArray := record 23 (httpRequest.toList ++ [23])
def httpResponse : ByteArray := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi".toUTF8

def isGetRequest (b : ByteArray) : Bool := b.toList.take 4 == "GET ".toUTF8.toList

/-- The minimal jemmet handler: one `recv`; if it looks like an HTTP GET, send a
response and flush. Generic over **any** `PlainConn` — TLS or plaintext. -/
def jemmetServeOnce {σ : Type} [PlainConn σ] (s : σ) : σ × Bool :=
  let (s, r) := PlainConn.recv s
  match r with
  | .bytes req =>
      if isGetRequest req then
        let (s, _) := PlainConn.send s httpResponse
        let (s, _) := PlainConn.flush s
        (s, true)
      else (s, false)
  | _ => (s, false)

-- TLS config with a default endpoint and http/1.1 allowed.
def fd0 : FdKey := { fd := 1, generation := 1 }
def http11 : AlpnProtocol := ⟨"http/1.1".toUTF8⟩
def leaf : LeafCertificateMeta :=
  { publicKeyKind := .ed25519, subjectNameCount := 1, notBeforeUnix := none, notAfterUnix := none }
def chain : CertificateChainHandle :=
  { id := 1, generation := ⟨1⟩, chainLen := 1, derSize := 500, leafMeta := leaf }
def key : PrivateKeyHandle := { secret := ⟨1, 0⟩, keyKind := .ed25519, generation := ⟨1⟩ }
def epDefault : EndpointConfig :=
  { chain := chain, key := key, allowedAlpn := [http11]
    signatureSchemes := [.ed25519], cipherSuites := [.aes128GcmSha256] }
def vcfg : ValidatedServerConfig :=
  match validateServerConfig
          { defaultEndpoint := some epDefault, sniRoutes := [], alpnMode := .serverPreference } ⟨1⟩ with
  | .ok v => v | .error _ => default

def tlsServer (inbound : List ByteArray) : TlsConn FakeTransport :=
  (TlsConn.server fd0 ⟨0, 0⟩ ⟨1⟩ .sha256 fakeProvider vcfg).feedInbound inbound

/-- A connected TLS connection with the HTTP request queued as an app-data record. -/
def connectedWithRequest : TlsConn FakeTransport :=
  let c := tlsServer [chRecord, clientFinishedRecord, appDataRecord]
  let c := c.progress (.transportReadable ⟨0, 0⟩)
  c.progress (.transportReadable ⟨0, 0⟩)

-- A connected TLS conn whose ALPN was negotiated, for the handoff check.
def connectedWithAlpn : TlsConn FakeTransport :=
  let s := State.initial ⟨0, 0⟩ ⟨1⟩ .sha256
  let neg := { s.negotiated with selectedAlpn := some http11 }
  { core := { s with handshake := .connected, negotiated := neg }
    rt := {}, tr := { fd := fd0, inbound := [] }, prov := fakeProvider }

def checks : List Check :=
  [ -- the acceptance headline: an HTTPS request served E2E through kroopt
    { name := "handshake completes through TlsConn over the fakes"
    , ok := connectedWithRequest.isConnected }
  , { name := "jemmet serves the HTTPS request through TlsConn (one handler path)"
    , ok := (jemmetServeOnce connectedWithRequest).2 }
  , { name := "the HTTP response ciphertext reached the transport"
    , ok := (let (c, _) := jemmetServeOnce connectedWithRequest
             c.tr.writtenBytes.size > connectedWithRequest.tr.writtenBytes.size) }
    -- the SAME handler serves a plaintext connection (RFC 015 §3, §4)
  , { name := "the same jemmet handler serves a plaintext connection"
    , ok := (let plain : PlaintextConn := { inbound := [httpRequest] }
             (jemmetServeOnce plain).2) }
  , { name := "plaintext connection reports no ALPN"
    , ok := (PlainConn.negotiatedProtocol ({ inbound := [] } : PlaintextConn)).isNone }
    -- ALPN handoff (RFC 015 §5)
  , { name := "negotiated ALPN (http/1.1) is reported to jemmet after connected"
    , ok := (match PlainConn.negotiatedProtocol connectedWithAlpn with
             | some a => a.eq http11 | none => false) }
    -- negative: malformed / plaintext input never reaches jemmet as plaintext
  , { name := "plaintext HTTP sent to the TLS listener never becomes app data"
    , ok := (let c := tlsServer [record 23 httpRequest.toList]  -- not a ClientHello
             let c := c.progress (.transportReadable ⟨0, 0⟩)
             match (jemmetServeOnce c).2 with
             | true => false   -- must NOT have served HTTP
             | false => true) }
  , { name := "garbage on the TLS listener fails the handshake, yields no plaintext"
    , ok := (let c := tlsServer [record 22 (List.replicate 20 0xFF)]  -- junk handshake
             let c := c.progress (.transportReadable ⟨0, 0⟩)
             match (c.recv).2 with
             | .bytes _ => false   -- never deliver unauthenticated bytes
             | _ => true) }
  , { name := "TLS connection never delivers bytes before connected"
    , ok := (let c := tlsServer [appDataRecord]   -- app data while still handshaking
             match (c.recv).2 with
             | .bytes _ => false | _ => true) }
    -- redacted error view (RFC 015 §6)
  , { name := "redacted error view carries a category, not raw bytes"
    , ok := (let v := redactError connectedWithRequest (.parse .oversizedRecord)
             v.category == .parse) }
  , { name := "redacted view reduces any SNI to a length, never the raw value"
    , ok := (let s := { connectedWithRequest.core with
                        negotiated := { connectedWithRequest.core.negotiated with
                                        selectedSni := some (bytesOf [1,2,3,4,5]) } }
             let v := redactError { connectedWithRequest with core := s } .closed
             v.sniPreviewLen == some 5) }
    -- diagnostics (RFC 015 §8)
  , { name := "the live driver counts a completed handshake (internal Metrics wired into driveEvents, RFC 015 §8)"
    , ok := connectedWithRequest.rt.metrics.handshakesCompleted == 1
              && connectedWithRequest.rt.metrics.handshakesFailed == 0 }
  ]

def main : IO UInt32 := do
  let mut failures := 0
  IO.println "kroopt M10 jemmet integration + E2E HTTPS acceptance:"
  for c in checks do
    if c.ok then IO.println s!"  PASS  {c.name}"
    else IO.println s!"  FAIL  {c.name}"; failures := failures + 1
  if failures == 0 then
    IO.println s!"\nAll {checks.length} checks passed."
    return 0
  else
    IO.println s!"\n{failures} of {checks.length} checks FAILED."
    return 1

end Tests.E2EHttps

def main : IO UInt32 := Tests.E2EHttps.main
