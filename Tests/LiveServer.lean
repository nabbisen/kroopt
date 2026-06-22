import Kroopt.Conn.Interpreter
import Kroopt.Conn.Record13
import Kroopt.Crypto.RealProvider
import Kroopt.Crypto.Hacl
import Tests.RealFixtures

/-!
# Tests.LiveServer

A test-only TLS 1.3 server that runs the verified core + production interpreter over a real
AF_UNIX listening socket, against an **independent** client (OpenSSL `s_client`, curl, or Python
`ssl`). This is the v0.3 interop target (RFC 026): where `Tests.SocketDriver` proves the handshake
completes over a socket with the *in-model* client, this proves it against a real implementation.

Real entropy is drawn at the IO layer (RFC 034 §4): the pure provider must never draw entropy, so
the ephemeral X25519 private key and the ServerHello random are drawn here via `Hacl.randomBytes`
and injected — the ephemeral into the provider config, the random as the one `randomBytes` op's
answer. The fixture Ed25519 leaf certificate is presented (its private key is `certSeed`, so the
CertificateVerify a real client checks against the cert's public key verifies).

The socket helpers are test-only glue; kroopt's production path reaches the network only through
iotakt. This driver loop does the syscalls; the interpreter stays pure.
-/

namespace Tests.LiveServer

open Kroopt Kroopt.Core Kroopt.Conn Kroopt.Crypto Tests.RealFixtures

@[extern "kroopt_sock_write"]  opaque sockWrite (fd : UInt32) (buf : ByteArray) : IO UInt64
@[extern "kroopt_sock_read"]   opaque sockRead (fd : UInt32) (n : UInt32) : IO ByteArray
@[extern "kroopt_sock_close"]  opaque sockClose (fd : UInt32) : IO Unit
@[extern "kroopt_sock_listen"] opaque sockListen (path : String) : IO UInt32
@[extern "kroopt_sock_accept"] opaque sockAccept (lfd : UInt32) : IO UInt32

def conn0 : ConnId := ⟨0, 0⟩

/-- Read exactly one TLS record (5-byte header + length-prefixed body) from `fd`. Returns a short
read (< 5 bytes) on EOF. -/
def readRecord (fd : UInt32) : IO ByteArray := do
  let hdr ← sockRead fd 5
  if hdr.size < 5 then pure hdr
  else
    let len := (hdr.get! 3).toNat * 256 + (hdr.get! 4).toNat
    let body ← sockRead fd len.toUInt32
    pure (hdr ++ body)

/-- A no-op staging transport: the driver owns the socket, so the interpreter leaves authorised
output in `RuntimeState.outbound` for the driver to flush. -/
structure NullT where
  unit : Unit := ()

instance : Transport NullT where
  fd _                := { fd := 0, generation := 0 }
  recv t _ _          := (.wouldBlock, t)
  send t _ _          := (.wouldBlock, t)
  enableWrite t _     := t
  disableWrite t _    := t
  closeConnection t _ := t

def nullTransport : NullT := {}

/-- A name for the handshake phase, for diagnostics. -/
def phaseName : HandshakeState → String
  | .start => "start"
  | .recvdClientHello => "recvdClientHello"
  | .requestedServerRandom => "requestedServerRandom"
  | .requestedEcdhe => "requestedEcdhe"
  | .derivedHandshakeSecrets => "derivedHandshakeSecrets"
  | .sentServerHello => "sentServerHello"
  | .sentEncryptedExtensions => "sentEncryptedExtensions"
  | .sentCertificate => "sentCertificate"
  | .requestedCertificateVerifySignature => "requestedCertificateVerifySignature"
  | .requestedServerFinishedMac => "requestedServerFinishedMac"
  | .sentCertificateVerify => "sentCertificateVerify"
  | .sentServerFinished => "sentServerFinished"
  | .requestedClientFinishedVerify => "requestedClientFinishedVerify"
  | .recvdClientFinished => "recvdClientFinished"
  | .connected => "connected"
  | .closing => "closing"
  | .closed => "closed"
  | .failed _ => "failed"

/-- Drive the handshake: read a record, advance the core, flush authorised bytes, repeat until
`connected`, a terminal state, EOF, or the fuel runs out. -/
partial def driveToConnected (fd : UInt32) (prov : CryptoProvider)
    (core : State) (rt : RuntimeState) : IO (State × RuntimeState) := do
  match core.handshake with
  | .connected => pure (core, rt)
  | .failed _  => pure (core, rt)
  | .closed    => pure (core, rt)
  | _ =>
    let rec ← readRecord fd
    if rec.size < 5 then pure (core, rt)
    else
      let (core', rt', _) :=
        driveEvents prov 2048 core rt nullTransport [InputEvent.transportBytes conn0 rec]
      if !rt'.outbound.isEmpty then
        let _ ← sockWrite fd rt'.outbound
      driveToConnected fd prov core' { rt' with outbound := ByteArray.empty }

def serve (args : List String) : IO Unit := do
  let path := args.headD "/tmp/kroopt-tls.sock"
  let ephR ← Hacl.randomBytes 32
  let srR  ← Hacl.randomBytes 32
  match ephR, srR with
  | .bytes eph, .bytes sr =>
    -- Real entropy injected at the IO layer: ephemeral into the provider config, the ServerHello
    -- random as the single `randomBytes` op's answer. The pure provider draws no entropy itself.
    let liveCfg := { cfg with ephemeralPrivate := eph }
    let prov : CryptoProvider :=
      { capabilities := realCapabilities
      , submit := fun a o r =>
          match r with
          | .randomBytes _ => .ok (a, .randomBytes sr)
          | _              => RealProvider.submit liveCfg a o r }
    let s0 : State :=
      { State.initial conn0 ⟨0⟩ .sha256 with serverConfig := realServerConfig }
    let lfd ← sockListen path
    if lfd == 0xFFFFFFFF then
      IO.println "LISTEN FAILED"
      return
    IO.println s!"kroopt TLS server listening on {path}"
    let cfd ← sockAccept lfd
    if cfd == 0xFFFFFFFF then
      IO.println "ACCEPT FAILED"
      sockClose lfd
      return
    let (core, _rt) ← driveToConnected cfd prov s0 {}
    match core.handshake with
    | .connected => IO.println "HANDSHAKE_OK reached connected"
    | h          => IO.println s!"HANDSHAKE_INCOMPLETE final phase {phaseName h}"
    sockClose cfd
    sockClose lfd
  | _, _ => IO.println "ENTROPY DRAW FAILED"

end Tests.LiveServer

def main (args : List String) : IO Unit := Tests.LiveServer.serve args
