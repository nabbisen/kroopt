import Tests.RealFixtures
import Kroopt.Conn.Interpreter
import Kroopt.Conn.Record13
import Kroopt.Crypto.RealProvider
import Kroopt.Parse.Wire

/-!
# Tests.Replay — captured-client replay bridge (RFC 036 §2)

Replays ClientHello captures — both synthetic (built from the wire helpers) and **genuine records
captured from `openssl s_client` and Python `ssl`** — through the **pure parser + production
interpreter over the fake transport** — the same path live sockets use, minus the syscalls — and
asserts deterministic negotiation and rejection. This exercises real client-byte diversity (multiple
offered suites/groups, real extension sets incl. SNI, fragmentation/coalescing, version rejection)
on the verified path *before* the socket.

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

/-- Like `replay`, but returns the raw wire bytes (RFC 041): a record-path reject's only output is a
single plaintext fatal alert record — never a handshake flight. -/
def replayWire (chunks : List ByteArray) : State × ByteArray :=
  let evs := chunks.map (InputEvent.transportBytes conn0 ·)
  let (core, _, tr) := driveEvents prov 4096 s0 ({} : RuntimeState) tr0 evs
  (core, FakeTransport.writtenBytes tr)

/-- The wire is exactly one plaintext fatal `Alert` record (content type 21, fatal level) for the
given description, and nothing else — i.e. an alert and no ServerHello/handshake flight. -/
def isPlaintextAlertOf (a : AlertDescription) (w : ByteArray) : Bool :=
  w.size == 7 && w.get! 0 == 21 && w.get! 1 == 0x03 && w.get! 2 == 0x03
    && w.get! 3 == 0x00 && w.get! 4 == 0x02 && w.get! 5 == 2 && w.get! 6 == a.toByte

/-- Drive a capture with the `debug_trace` gate set to `enabled`; return the recorded trace
(RFC 036 §3). With `enabled := false` (the default) the trace must stay empty. -/
def traceOf (enabled : Bool) (ch : ByteArray) : List String :=
  let (_, rt, _) := driveEvents prov 4096 s0 ({ traceEnabled := enabled } : RuntimeState) tr0
                      [InputEvent.transportBytes conn0 ch]
  rt.trace

/-- Internal operational counters after driving a capture (RFC 015 §8 / RFC 020 §10.2). -/
def metricsOf (ch : ByteArray) : Metrics :=
  let (_, rt, _) := driveEvents prov 4096 s0 ({} : RuntimeState) tr0 [InputEvent.transportBytes conn0 ch]
  rt.metrics

def hasSub (s sub : String) : Bool := (s.splitOn sub).length > 1

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

/-- Like `buildCH`, but takes the entire extension blob verbatim — used to commit *malformed/edge*
captures (missing key_share, duplicated extension, only-unsupported group) for the rejection corpus.
Real clients do not emit these, so they are built deterministically rather than packet-captured. -/
def buildExts (suites exts : ByteArray) : ByteArray :=
  let random : ByteArray := ByteArray.mk (Array.mkArray 32 (0xAB : UInt8))
  let body : ByteArray :=
    Wire.be16 0x0303 ++ random ++ Wire.u8Len ByteArray.empty
      ++ Wire.u16Len suites ++ Wire.u8Len (ByteArray.mk #[(0x00 : UInt8)])
      ++ Wire.u16Len exts
  Wire.handshake 0x01 body
def extTls13   : ByteArray := hx "00 2b 00 03 02 03 04"           -- supported_versions: TLS 1.3
def extTls12   : ByteArray := hx "00 2b 00 03 02 03 03"           -- supported_versions: TLS 1.2 only
def grpX25519  : ByteArray := hx "00 0a 00 04 00 02 00 1d"        -- groups: x25519
def grpBroad   : ByteArray := hx "00 0a 00 06 00 04 00 17 00 1d"  -- groups: secp256r1, x25519
def sigEd25519 : ByteArray := hx "00 0d 00 04 00 02 08 07"        -- sig_algs: ed25519
def grpUnknown : ByteArray := hx "00 0a 00 04 00 02 fa fa"        -- groups: only unknown 0xfafa
def ksX25519   : ByteArray := Wire.extension 0x0033 (Wire.u16Len (Wire.keyShareEntry 0x001d clientShare))

-- captures (record-wrapped, ready for the wire)
def constrainedCH : ByteArray := recordWrap clientHelloMsg                                  -- 1301,1303 / x25519
def broadCH       : ByteArray := recordWrap (buildCH (hx "13 02 13 01 13 03") extTls13 grpX25519 sigEd25519)
def noTls13CH     : ByteArray := recordWrap (buildCH (hx "13 01 13 03") extTls12 grpX25519 sigEd25519)

-- ── committed malformed / edge captures (RFC 036 §2) — each must reject deterministically ──
def mfSuites      : ByteArray := hx "13 01 13 03"
def noKeyShareCH  : ByteArray := recordWrap (buildExts mfSuites (extTls13 ++ grpX25519 ++ sigEd25519))
def dupExtCH      : ByteArray := recordWrap (buildExts mfSuites (extTls13 ++ extTls13 ++ grpX25519 ++ sigEd25519 ++ ksX25519))
def unknownGrpCH  : ByteArray := recordWrap (buildExts mfSuites (extTls13 ++ grpUnknown ++ sigEd25519 ++ ksX25519))
-- key_share present but supported_groups absent → strict reject (RFC 8446 §4.2.8; review HIGH-3)
def noSgCH        : ByteArray := recordWrap (buildExts mfSuites (extTls13 ++ sigEd25519 ++ ksX25519))

-- ── committed GREASE-tolerance captures (RFC 036 §4): unknown/reserved values alongside valid ones
-- must be *ignored* (RFC 8701), not fatal — a browser-grade prerequisite, verified here. ──
def grpGreaseX25519 : ByteArray := hx "00 0a 00 06 00 04 0a 0a 00 1d"   -- supported_groups: GREASE 0x0a0a, x25519
def greaseGrpCH     : ByteArray := recordWrap (buildExts (hx "13 01") (extTls13 ++ grpGreaseX25519 ++ sigEd25519 ++ ksX25519))
def greaseSuiteCH   : ByteArray := recordWrap (buildExts (hx "0a 0a 13 01") (extTls13 ++ grpX25519 ++ sigEd25519 ++ ksX25519))

-- ── committed real-client captures (RFC 036 §2) ──
-- Genuine TLS 1.3 ClientHello records captured from `openssl s_client` and Python `ssl` (OpenSSL).
-- Already full records (outer `16 03 01`); sanitized — client random + key_share are public.
-- `osslBroad`/`pyBroad` offer the default suite/group breadth; `osslConstrained` was captured with
-- `-ciphersuites TLS_CHACHA20_POLY1305_SHA256 -groups X25519`; `pyBroad` also carries SNI example.com.
def osslBroadCapture : ByteArray :=
  hx "16 03 01 00 dc 01 00 00 d8 03 03 3a e0 78 2e 10 7c 00 38 ce 2c 2a f0 aa"
  ++ hx "b7 d8 72 a1 61 b6 36 09 40 c9 a1 de 27 cc 70 54 53 0c 8c 20 9c 9b 15 c5"
  ++ hx "9a 62 ee 1b 67 0b 94 46 c6 d1 3a 4d 60 91 57 83 01 4e de dc df e9 2e 28"
  ++ hx "73 0b a0 6f 00 08 13 02 13 03 13 01 00 ff 01 00 00 87 00 0b 00 04 03 00"
  ++ hx "01 02 00 0a 00 16 00 14 00 1d 00 17 00 1e 00 19 00 18 01 00 01 01 01 02"
  ++ hx "01 03 01 04 00 23 00 00 00 16 00 00 00 17 00 00 00 0d 00 1e 00 1c 04 03"
  ++ hx "05 03 06 03 08 07 08 08 08 09 08 0a 08 0b 08 04 08 05 08 06 04 01 05 01"
  ++ hx "06 01 00 2b 00 03 02 03 04 00 2d 00 02 01 01 00 33 00 26 00 24 00 1d 00"
  ++ hx "20 6d 83 81 31 96 de 10 1b c6 3e 7d e2 f7 dd 67 97 6a de 1d 91 de b4 d2"
  ++ hx "43 f1 fd 42 24 36 ba 0e 0a"
def osslConstrainedCapture : ByteArray :=
  hx "16 03 01 00 c6 01 00 00 c2 03 03 91 1d 54 25 83 f5 fc f7 5f 01 9a 5f b2"
  ++ hx "c5 6a 87 5f 3e a4 a0 89 fb a4 be 77 a9 7c 48 2c 3f 11 4c 20 ab 13 4a ba"
  ++ hx "82 e4 48 1a 6b 46 2c e3 8e f7 2c 08 f2 de 6e 29 72 68 43 61 a5 5c e3 6c"
  ++ hx "54 f7 e3 e1 00 04 13 03 00 ff 01 00 00 75 00 0b 00 04 03 00 01 02 00 0a"
  ++ hx "00 04 00 02 00 1d 00 23 00 00 00 16 00 00 00 17 00 00 00 0d 00 1e 00 1c"
  ++ hx "04 03 05 03 06 03 08 07 08 08 08 09 08 0a 08 0b 08 04 08 05 08 06 04 01"
  ++ hx "05 01 06 01 00 2b 00 03 02 03 04 00 2d 00 02 01 01 00 33 00 26 00 24 00"
  ++ hx "1d 00 20 a4 ac 6e 1a cb 4e 92 eb 9a 9e 24 8d 90 64 86 3c 51 a7 68 64 85"
  ++ hx "fe 4c a3 fc ad 27 d9 01 97 99 4e"
def pyBroadCapture : ByteArray :=
  hx "16 03 01 00 f0 01 00 00 ec 03 03 07 7f ad 5a e8 a0 2b 8b ec 11 10 01 9e"
  ++ hx "70 1e d1 17 64 e2 73 af 20 3f 2a 0f 1d ad e5 ea 9e c0 20 20 bf 91 09 0f"
  ++ hx "c2 48 86 0c 75 ca ab e5 4f e3 cc 81 93 f1 63 44 ae df 75 ed 1b f4 df 91"
  ++ hx "ea 66 15 65 00 08 13 02 13 03 13 01 00 ff 01 00 00 9b 00 00 00 10 00 0e"
  ++ hx "00 00 0b 65 78 61 6d 70 6c 65 2e 63 6f 6d 00 0b 00 04 03 00 01 02 00 0a"
  ++ hx "00 16 00 14 00 1d 00 17 00 1e 00 19 00 18 01 00 01 01 01 02 01 03 01 04"
  ++ hx "00 23 00 00 00 16 00 00 00 17 00 00 00 0d 00 1e 00 1c 04 03 05 03 06 03"
  ++ hx "08 07 08 08 08 09 08 0a 08 0b 08 04 08 05 08 06 04 01 05 01 06 01 00 2b"
  ++ hx "00 03 02 03 04 00 2d 00 02 01 01 00 33 00 26 00 24 00 1d 00 20 c2 ac a3"
  ++ hx "8a e8 f7 80 94 a6 b0 6a 9f d7 f4 01 96 c3 37 70 da 58 31 53 1d 69 df fc"
  ++ hx "f3 b7 0d c8 1c"

def suiteIs (s : State) (c : CipherSuite) : Bool :=
  match s.negotiated.selectedSuite with | some c' => c' == c | none => false
def groupIsX25519 (s : State) : Bool :=
  match s.negotiated.selectedGroup with | some .x25519 => true | _ => false
def reachedFlight (s : State) : Bool :=
  match s.handshake with | .sentServerFinished => true | _ => false
def failedIllegal (s : State) : Bool :=
  match s.handshake with | .failed .illegalParameter => true | _ => false

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

def osslBroadR : State × Nat := replay [osslBroadCapture]
def osslConstR : State × Nat := replay [osslConstrainedCapture]
def pyBroadR   : State × Nat := replay [pyBroadCapture]
def osslBroadFrag : State × Nat :=
  let ch := osslBroadCapture; let n := ch.size
  replay [ch.extract 0 (n/3), ch.extract (n/3) (2*n/3), ch.extract (2*n/3) n]

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

    -- ── committed real-client captures (openssl s_client / Python ssl) ──
  , { name := "real openssl broad CH → aes256GcmSha384 / x25519, server flight produced"
    , ok := suiteIs osslBroadR.1 .aes256GcmSha384 && groupIsX25519 osslBroadR.1
              && reachedFlight osslBroadR.1 && osslBroadR.2 > 0 }
  , { name := "real openssl constrained CH (-CHACHA20) → chacha20Poly1305Sha256 / x25519 (client constraint honored)"
    , ok := suiteIs osslConstR.1 .chacha20Poly1305Sha256 && groupIsX25519 osslConstR.1
              && reachedFlight osslConstR.1 && osslConstR.2 > 0 }
  , { name := "real Python ssl broad CH (carries SNI example.com) → aes256GcmSha384 / x25519, flight"
    , ok := suiteIs pyBroadR.1 .aes256GcmSha384 && groupIsX25519 pyBroadR.1
              && reachedFlight pyBroadR.1 && pyBroadR.2 > 0 }
  , { name := "real openssl capture in 3 fragments → identical negotiation + flight (reassembly)"
    , ok := suiteIs osslBroadFrag.1 .aes256GcmSha384 && groupIsX25519 osslBroadFrag.1
              && reachedFlight osslBroadFrag.1 && osslBroadFrag.2 == osslBroadR.2 }

    -- ── malformed / edge captures (RFC 036 §2): deterministic rejection emits a plaintext fatal
    -- alert and no handshake flight (RFC 041 — record-path `recordFailAlert` now transmits) ──
  , { name := "malformed: ClientHello with no key_share → reject emits illegal_parameter alert, no flight"
    , ok := let r := replayWire [noKeyShareCH]; failedIllegal r.1 && isPlaintextAlertOf .illegalParameter r.2 }
  , { name := "malformed: duplicate supported_versions extension → reject emits illegal_parameter alert"
    , ok := let r := replayWire [dupExtCH]; failedIllegal r.1 && isPlaintextAlertOf .illegalParameter r.2 }
  , { name := "edge: ClientHello offering only an unsupported group → reject emits illegal_parameter alert"
    , ok := let r := replayWire [unknownGrpCH]; failedIllegal r.1 && isPlaintextAlertOf .illegalParameter r.2 }
  , { name := "strict (HIGH-3): key_share present, supported_groups absent → reject emits illegal_parameter alert, no flight"
    , ok := let r := replayWire [noSgCH]; failedIllegal r.1 && isPlaintextAlertOf .illegalParameter r.2 }

    -- ── GREASE tolerance (RFC 036 §4 / RFC 8701): unknown values alongside valid ones are ignored ──
  , { name := "GREASE: unknown named group (0x0a0a) alongside x25519 → ignored, x25519 selected, full flight"
    , ok := let r := replay [greaseGrpCH]; groupIsX25519 r.1 && reachedFlight r.1 }
  , { name := "GREASE: unknown cipher (0x0a0a) before TLS_AES_128_GCM_SHA256 → ignored, aes128 selected, full flight"
    , ok := let r := replay [greaseSuiteCH]; suiteIs r.1 .aes128GcmSha256 && reachedFlight r.1 }

    -- ── debug_trace runtime wiring (RFC 036 §3) ──
  , { name := "debug_trace OFF by default → no trace recorded (no production overhead/leak)"
    , ok := (traceOf false osslBroadCapture).isEmpty }
  , { name := "debug_trace ON → a real handshake records a non-empty trace with real action events"
    , ok := let t := traceOf true osslBroadCapture
            !t.isEmpty
              && t.any (fun l => hasSub l "crypto-call")
              && t.any (fun l => hasSub l "handshake-out")
              && t.any (fun l => hasSub l "certificate-out") }

    -- ── internal operational counters wired into the live driver (RFC 015 §8) ──
  , { name := "live driver counts a rejected handshake: handshakesFailed + alertsClassified move, completed stays 0"
    , ok := let m := metricsOf noKeyShareCH
            m.handshakesFailed == 1 && m.alertsClassified == 1 && m.handshakesCompleted == 0 }
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
