import Tests.RealFixtures
import Kroopt.Conn.Interpreter
import Kroopt.Conn.Record13
import Kroopt.Crypto.RealProvider
import Kroopt.Parse.Wire

/-!
# Tests.Replay — captured-client replay bridge (RFC 036 §2)

Replays real-shaped ClientHello captures through the **pure parser + production interpreter over
the fake transport** — the same path live sockets use, minus the syscalls — and asserts
deterministic negotiation and rejection. This exercises real client-byte diversity (multiple
offered suites/groups, fragmentation/coalescing, version rejection) on the verified path *before*
the socket, isolating "does a real ClientHello negotiate deterministically?" from socket
orchestration.

Captures here are sanitized and committed: a ClientHello's random and key_share are public
handshake values, and nothing secret is stored. The server ephemeral is pinned (RFC 8448 random)
so the negotiated *result* is deterministic; the ECDHE math is real.
-/

namespace Tests.Replay

open Kroopt Kroopt.Core Kroopt.Conn Kroopt.Crypto Kroopt.Parse Tests.RealFixtures

structure Check where
  name : String
  ok : Bool

def conn0 : ConnId := ⟨0, 0⟩

/-- Real provider with a pinned server random (so the negotiated result is reproducible); the
ECDHE/HKDF/signature math is the real HACL\* path against the client's real key_share. -/
def prov : CryptoProvider :=
  { capabilities := realCapabilities
    submit := fun arena op req =>
      match req with
      | .randomBytes _ => .ok (arena, .randomBytes serverRandom)
      | _              => RealProvider.submit cfg arena op req }

def s0 : State := { State.initial conn0 ⟨0⟩ .sha256 with serverConfig := realServerConfig }
def tr0 : FakeTransport := { fd := ⟨1, 1⟩, inbound := [] }

/-- Drive the interpreter over a list of inbound chunks; return the final core state and the
number of server-flight bytes written. -/
def replay (chunks : List ByteArray) : State × Nat :=
  let evs := chunks.map (InputEvent.transportBytes conn0 ·)
  let (core, _, tr) := driveEvents prov 4096 s0 ({} : RuntimeState) tr0 evs
  (core, (FakeTransport.writtenBytes tr).size)

/-- Build a ClientHello message (x25519 key_share fixed) from the offered suites and the
supported_versions / supported_groups / signature_algorithms extensions. Mirrors the real wire
layout (`RealFixtures.clientHelloMsg`). -/
def buildCH (suites supVer supGrp sigAlg : ByteArray) : ByteArray :=
  let random : ByteArray := ByteArray.mk (Array.mkArray 32 (0xAB : UInt8))
  let ks   : ByteArray := Wire.extension 0x0033 (Wire.u16Len (Wire.keyShareEntry 0x001d clientShare))
  let exts : ByteArray := supVer ++ supGrp ++ sigAlg ++ ks
  let body : ByteArray :=
    Wire.be16 0x0303 ++ random ++ Wire.u8Len ByteArray.empty
      ++ Wire.u16Len suites ++ Wire.u8Len (ByteArray.mk #[(0x00 : UInt8)])
      ++ Wire.u16Len exts
  Wire.handshake 0x01 body

-- extension fixtures
def extTls13   : ByteArray := hx "00 2b 00 03 02 03 04"           -- supported_versions: TLS 1.3
def extTls12   : ByteArray := hx "00 2b 00 03 02 03 03"           -- supported_versions: TLS 1.2 only
def grpX25519  : ByteArray := hx "00 0a 00 04 00 02 00 1d"        -- groups: x25519
def grpBroad   : ByteArray := hx "00 0a 00 06 00 04 00 17 00 1d"  -- groups: secp256r1, x25519
def sigEd25519 : ByteArray := hx "00 0d 00 04 00 02 08 07"        -- sig_algs: ed25519

-- captures (record-wrapped, ready for the wire)
def constrainedCH : ByteArray := recordWrap clientHelloMsg                                  -- 1301,1303 / x25519
def broadCH       : ByteArray := recordWrap (buildCH (hx "13 02 13 01 13 03") extTls13 grpX25519 sigEd25519)
def noTls13CH     : ByteArray := recordWrap (buildCH (hx "13 01 13 03") extTls12 grpX25519 sigEd25519)

def suiteIs (s : State) (c : CipherSuite) : Bool :=
  match s.negotiated.selectedSuite with | some c' => c' == c | none => false
def groupIsX25519 (s : State) : Bool :=
  match s.negotiated.selectedGroup with | some .x25519 => true | _ => false
def reachedFlight (s : State) : Bool :=
  match s.handshake with | .sentServerFinished => true | _ => false

-- reference result from the whole constrained capture
def whole : State × Nat := replay [constrainedCH]
def frag3 : State × Nat :=
  let ch := constrainedCH; let n := ch.size
  replay [ch.extract 0 (n/3), ch.extract (n/3) (2*n/3), ch.extract (2*n/3) n]
def frag2 : State × Nat :=
  let ch := constrainedCH; let n := ch.size
  replay [ch.extract 0 (n/2), ch.extract (n/2) n]
def broad : State × Nat := replay [broadCH]
def rejected : State × Nat := replay [noTls13CH]

def checks : List Check :=
  [ -- constrained capture negotiates deterministically and produces a flight
    { name := "constrained CH → aes128GcmSha256 / x25519, server flight produced"
    , ok := suiteIs whole.1 .aes128GcmSha256 && groupIsX25519 whole.1
              && reachedFlight whole.1 && whole.2 > 0 }

    -- fragmentation / coalescing: same bytes split across chunks → identical result
  , { name := "same capture in 3 fragments → identical negotiation + flight (reassembly)"
    , ok := suiteIs frag3.1 .aes128GcmSha256 && groupIsX25519 frag3.1
              && reachedFlight frag3.1 && frag3.2 == whole.2 }
  , { name := "same capture in 2 fragments → identical negotiation + flight (coalescing)"
    , ok := suiteIs frag2.1 .aes128GcmSha256 && groupIsX25519 frag2.1
              && reachedFlight frag2.1 && frag2.2 == whole.2 }

    -- a broad ClientHello negotiates a different supported suite than the constrained one
  , { name := "broad CH (adds aes256GcmSha384 first) negotiates that supported suite / x25519"
    , ok := suiteIs broad.1 .aes256GcmSha384 && groupIsX25519 broad.1
              && reachedFlight broad.1 && broad.2 > 0 }
  , { name := "broad vs constrained: same client, different offer → different deterministic suite"
    , ok := suiteIs whole.1 .aes128GcmSha256 && suiteIs broad.1 .aes256GcmSha384 }

    -- a TLS-1.2-only ClientHello is rejected cleanly (no downgrade, no flight)
  , { name := "TLS-1.2-only CH is rejected: no negotiation, no server flight"
    , ok := !reachedFlight rejected.1
              && (match rejected.1.negotiated.selectedSuite with | none => true | _ => false) }
  , { name := "rejected capture leaves a terminal/failed state, never connected"
    , ok := (match rejected.1.handshake with
             | .connected => false
             | .sentServerFinished => false
             | _ => true) }
  ]

def main : IO Unit := do
  let mut failed := 0
  for c in checks do
    if c.ok then IO.println s!"  ok   {c.name}"
    else
      failed := failed + 1
      IO.println s!"  FAIL {c.name}"
  if failed == 0 then
    IO.println s!"All {checks.length} passed."
  else
    IO.eprintln s!"{failed} of {checks.length} FAILED."
    IO.Process.exit 1

end Tests.Replay

def main : IO Unit := Tests.Replay.main
