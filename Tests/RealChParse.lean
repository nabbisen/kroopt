import Kroopt.Conn.Interpreter
import Kroopt.Conn.Record13
import Kroopt.Crypto.RealProvider
import Tests.RealFixtures

/-! # Real-ClientHello parse/negotiate check (RFC 026 de-risk)

Feed a ClientHello produced by a real TLS 1.3 client (OpenSSL / Python `ssl`) into the verified core
with the real HACL* provider and confirm the core parses it, negotiates kroopt's required parameters,
does the ECDHE against the client's real key_share, and produces a server flight — i.e. the parser and
policy handle a real, non-fixture ClientHello. Isolates the "does a real ClientHello parse?" risk from
the socket/orchestration work that follows. -/

namespace Tests.RealChParse

open Kroopt Kroopt.Core Kroopt.Conn Kroopt.Crypto Tests.RealFixtures

def conn0 : ConnId := ⟨0, 0⟩

/-- Pinned ServerHello random (RFC 8448) but real ECDHE against whatever key_share the real client
sent. The fixed server ephemeral is a test-only simplification; the ECDHE math is real. -/
def realishProvider : CryptoProvider :=
  { capabilities := realCapabilities
    submit := fun arena op req =>
      match req with
      | .randomBytes _ => .ok (arena, .randomBytes serverRandom)
      | _              => RealProvider.submit cfg arena op req }

def s0 : State :=
  { State.initial conn0 ⟨0⟩ .sha256 with serverConfig := realServerConfig }

def tr0 : FakeTransport := { fd := ⟨1, 1⟩, inbound := [] }

def main : IO Unit := do
  let path := "/tmp/real_ch.bin"
  unless (← System.FilePath.pathExists path) do
    IO.println s!"no ClientHello at {path}; run scripts/real-ch-interop.sh (it generates one via python ssl)."
    return
  let ch ← IO.FS.readBinFile path
  IO.println s!"read real ClientHello record: {ch.size} bytes"
  let (core, _rt, tr) :=
    driveEvents realishProvider 2048 s0 ({} : RuntimeState) tr0
      [InputEvent.transportBytes conn0 ch]
  let flight := FakeTransport.writtenBytes tr
  IO.println s!"core reached: {repr core.handshake}"
  IO.println s!"negotiated suite: {repr core.negotiated.selectedSuite}"
  IO.println s!"negotiated group: {repr core.negotiated.selectedGroup}"
  IO.println s!"server flight bytes written: {flight.size}"
  match core.handshake with
  | .sentServerFinished =>
      if flight.size > 0 then
        IO.println "PASS: real ClientHello parsed, negotiated, and produced a server flight."
      else
        IO.println "PARTIAL: reached sentServerFinished but no flight bytes."
  | _ => IO.println "RESULT: did not reach a flight — see phase above."

end Tests.RealChParse

def main : IO Unit := Tests.RealChParse.main
