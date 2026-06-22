import Kroopt.Conn.Interpreter
import Kroopt.Conn.Record13
import Kroopt.Crypto.RealProvider
import Tests.RealFixtures

/-!
# Tests.SocketDriver

The first real-socket increment of the v0.3 milestone (RFC 010). Where
`Tests.SocketHandshake` confirms the *record layer* survives real kernel I/O,
this drives the **verified core + production interpreter** over a real OS socket:
a ClientHello arrives *from the wire*, the pure `Kroopt.Core.step` machine (with
the real HACL\* provider) processes it, and the sealed server flight it produces
is written *back to the wire*. The peer reads the flight off the socket and
checks its record framing.

The interpreter remains pure and effect-free; the I/O lives entirely in a thin
driver loop (`driveOverSocket`) that does the syscalls — `sockRead` to obtain
wire bytes, `driveEvents` to advance the core, `sockWrite` to flush the bytes the
core authorised. This is the shape RFC 010 §6 specifies: the core decides which
bytes are legal to write; the driver only moves them. The socket helpers
(`Kroopt/Native/kroopt_socket.c`) are test-only transport glue; kroopt's
production path reaches the network only through iotakt.
-/

namespace Tests.SocketDriver

open Kroopt Kroopt.Core Kroopt.Conn Kroopt.Crypto Tests.RealFixtures

@[extern "kroopt_socketpair"] opaque sockpairRaw : IO UInt64
@[extern "kroopt_sock_write"] opaque sockWrite (fd : UInt32) (buf : ByteArray) : IO UInt64
@[extern "kroopt_sock_read"]  opaque sockRead (fd : UInt32) (n : UInt32) : IO ByteArray
@[extern "kroopt_sock_close"] opaque sockClose (fd : UInt32) : IO Unit

def socketpair : IO (UInt32 × UInt32) := do
  let packed ← sockpairRaw
  pure ((packed >>> 32).toUInt32, (packed &&& 0xFFFFFFFF).toUInt32)

/-- Read exactly one TLS record (5-byte header + length-prefixed body) from `fd`.
`kroopt_sock_read` fills exactly its byte count, so reads must be sized to known
record boundaries rather than a speculative large chunk (which would block). -/
def readRecord (fd : UInt32) : IO ByteArray := do
  let hdr ← sockRead fd 5
  if hdr.size < 5 then pure hdr
  else
    let len := (hdr.get! 3).toNat * 256 + (hdr.get! 4).toNat
    let body ← sockRead fd len.toUInt32
    pure (hdr ++ body)

/-- The walk of outer record content-types across a concatenation of TLS records
(fuel-bounded). The first byte of each record is its outer `ContentType`. -/
def recordTypes : Nat → ByteArray → List UInt8
  | 0, _ => []
  | fuel + 1, b =>
    if b.size < 5 then []
    else
      let len := (b.get! 3).toNat * 256 + (b.get! 4).toNat
      let total := 5 + len
      if b.size < total then [b.get! 0]
      else b.get! 0 :: recordTypes fuel (b.extract total b.size)

/-- A no-op staging transport: the I/O driver owns the real socket, so the pure
interpreter neither reads nor drains a transport — `recv`/`send` always report
`wouldBlock`, leaving authorised output in `RuntimeState.outbound` for the driver
to flush, and consuming no input (the driver feeds bytes via `transportBytes`). -/
structure NullT where
  unit : Unit := ()

def nullFd : FdKey := { fd := 0, generation := 0 }

instance : Transport NullT where
  fd _              := nullFd
  recv t _ _        := (.wouldBlock, t)
  send t _ _        := (.wouldBlock, t)
  enableWrite t _   := t
  disableWrite t _  := t
  closeConnection t _ := t

def nullTransport : NullT := {}

def conn0 : ConnId := ⟨0, 0⟩

/-- The deterministic, RFC 8448-backed server: the real HACL\* provider with the
fixed server randomness the fixtures pin (so the handshake is reproducible). -/
def realishProvider : CryptoProvider :=
  { capabilities := realCapabilities
  , submit := fun arena op req =>
      match req with
      | .randomBytes _ => .ok (arena, .randomBytes serverRandom)
      | _              => RealProvider.submit cfg arena op req }

/-- The initial server state, configured to present the fixture Ed25519 leaf certificate (RFC 012).
Existing in-model tests use the empty default config; here we override `serverConfig` so the flight
carries a real (non-empty) Certificate — exactly what a real client requires. -/
def s0 : State := { State.initial conn0 ⟨0⟩ .sha256 with serverConfig := realServerConfig }

/-- One driver turn (RFC 010 §6): read whatever bytes are on the wire, advance the
pure core with them, and flush the ciphertext the core authorised back to the wire.
Returns the advanced core and runtime; the staging transport is discarded. -/
def driveOverSocket (fd : UInt32) (core : State) (rt : RuntimeState) : IO (State × RuntimeState) := do
  let inbound ← readRecord fd
  let (core', rt', _) :=
    driveEvents realishProvider 1024 core rt nullTransport
      [InputEvent.transportBytes conn0 inbound]
  if !rt'.outbound.isEmpty then
    let _ ← sockWrite fd rt'.outbound
  pure (core', { rt' with outbound := ByteArray.empty })

/-- The peer's client Finished, sealed under the client handshake-traffic key the server derived in
phase 1, over the through-server-Finished transcript hash — exactly what the core's `aeadOpen` +
`verifyFinished` reconstruct (mirrors `Tests.Correspondence`). A real client (OpenSSL/curl) computes
this itself; here the deterministic fixtures let us produce it from the server's own derived state. -/
def buildClientFinished (core1 : State) (rt1 : RuntimeState) : ByteArray :=
  let cHsSecret := ((rt1.arena.lookupBaseSecret .read .handshake).bind rt1.arena.getById).getD ByteArray.empty
  let through := core1.transcript.events.foldl (fun acc e => acc ++ e.wireBytes) (ByteArray.mk #[])
  let verifyData := Hacl.hmac256 (KeySchedule.finishedKey cHsSecret) (Hacl.sha256 through)
  let cKey := KeySchedule.trafficKey .chacha20Poly1305Sha256 cHsSecret
  let cIv  := KeySchedule.trafficIv cHsSecret
  Record13.sealRecord! cKey cIv 0 (Kroopt.Parse.Wire.finished verifyData) .handshake 0

def main : IO Unit := do
  IO.println "kroopt verified core driving a TLS 1.3 server handshake over a real OS socket:"
  let (a, b) ← socketpair          -- a = peer, b = kroopt server side
  let mut failures : Nat := 0
  let report (name : String) (ok : Bool) : IO Unit := do
    let mark := if ok then "ok" else "FAIL"
    IO.println s!"  {name}: {mark}"

  -- The peer puts a real ClientHello on the wire.
  let _ ← sockWrite a (recordWrap clientHelloMsg)

  -- The server reads it off the wire, runs the verified core, and writes the flight back.
  let (core1, _rt1) ← driveOverSocket b s0 ({} : RuntimeState)

  -- Close the server side so the peer's read drains the buffered flight and then sees EOF
  -- (the blocking reader returns the bytes it has rather than waiting for a fixed count).
  sockClose b
  let flight ← sockRead a 16384
  sockClose a

  let types := recordTypes 16 flight
  let nonEmpty := flight.size > 0
  if !nonEmpty then failures := failures + 1
  report "the server flight reached the peer over the socket" nonEmpty

  -- First record: a cleartext handshake record carrying ServerHello (outer 22, body 0x02).
  let shCleartext :=
    flight.size ≥ 6 && flight.get! 0 == 22 && flight.get! 5 == 0x02
  if !shCleartext then failures := failures + 1
  report "the flight opens with a cleartext ServerHello record" shCleartext

  -- Every record after the ServerHello is an encrypted record (outer application_data 0x17).
  let restSealed := match types with
    | 22 :: rest => rest.length ≥ 1 && rest.all (· == 0x17)
    | _          => false
  if !restSealed then failures := failures + 1
  report "the encrypted flight records carry outer application_data (0x17)" restSealed

  -- The core advanced to the post-flight state, awaiting the client Finished.
  let reachedFlight := match core1.handshake with | .sentServerFinished => true | _ => false
  if !reachedFlight then failures := failures + 1
  report "the verified core reached sentServerFinished over real I/O" reachedFlight

  -- Second socketpair: the full server handshake to `connected` over the wire. The peer puts a
  -- ClientHello on the wire; the server replies with its flight; the peer puts a valid client
  -- Finished on the wire; the server opens it, verifies the MAC, and reaches `connected`.
  let (c, d) ← socketpair        -- c = peer, d = kroopt server side
  let _ ← sockWrite c (recordWrap clientHelloMsg)
  let (coreA, rtA) ← driveOverSocket d s0 ({} : RuntimeState)
  let _ ← sockWrite c (buildClientFinished coreA rtA)
  let (coreB, _rtB) ← driveOverSocket d coreA rtA
  sockClose c; sockClose d

  -- The core resolved the configured public cert chain and committed it (RFC 012): the flight
  -- carries a real, non-empty Certificate (sealed inside the handshake epoch), and that same DER
  -- is what went into the transcript the CertificateVerify signs and the Finished MACs.
  let certWired := core1.negotiated.selectedCertDer.data == certDer.data && !certDer.isEmpty
  if !certWired then failures := failures + 1
  report "the configured certificate DER flows into the core's committed transcript" certWired

  let connected := match coreB.handshake with | .connected => true | _ => false
  if !connected then failures := failures + 1
  report "the full handshake reaches `connected` over the socket (client Finished verified)" connected

  if failures == 0 then
    IO.println "All 6 checks passed."
  else
    IO.println s!"{failures} check(s) FAILED."
    throw (IO.userError "socket-driver checks failed")

end Tests.SocketDriver

def main : IO Unit := Tests.SocketDriver.main
