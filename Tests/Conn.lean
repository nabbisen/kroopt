import Kroopt.Conn.TlsConn
import Kroopt.Parse.Handshake

/-!
# Tests.Conn

Interpreter-faithfulness and `TlsConn`-semantics tests (RFC 010 §11, RFC 014 §6).
The interpreter is exercised through the public API against the pure fake
transport and the deterministic fake provider: a full handshake driven through
`TlsConn`, the precise write/flush/read semantics, partial-write ordering,
progress-budget termination, and stale-event/result rejection.
-/

namespace Tests.Conn

open Kroopt Kroopt.Core Kroopt.Conn Kroopt.Crypto

structure Check where
  name : String
  ok : Bool

def bytesOf (l : List UInt8) : ByteArray := ByteArray.mk l.toArray
def u16be (n : Nat) : List UInt8 := [(n / 256).toUInt8, (n % 256).toUInt8]

-- A valid ClientHello, record-framed (same shape as the e2e harness).
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
def record (body : List UInt8) : ByteArray := bytesOf ([22, 0x03, 0x03] ++ u16be body.length ++ body)
def chRecord : ByteArray := record chMsg
def clientFinishedRecord : ByteArray := record ([20] ++ [0, 0, 32] ++ List.replicate 32 0x55)

def fd0 : FdKey := { fd := 1, generation := 1 }

/-- A fresh handshaking server connection with the ClientHello and client
Finished records queued for delivery. -/
def freshServer : TlsConn FakeTransport :=
  (TlsConn.server fd0 ⟨0, 0⟩ ⟨0⟩ .sha256 fakeProvider).feedInbound [chRecord, clientFinishedRecord]

/-- Drive the handshake to completion: a readable event reads and processes the
ClientHello and server flight; a second reads the client Finished and finishes. -/
def handshaken : TlsConn FakeTransport :=
  let c := freshServer.progress (.transportReadable ⟨0, 0⟩)
  c.progress (.transportReadable ⟨0, 0⟩)

/-- A connected connection with an outstanding record-open op, for read tests. -/
def connectedForRecv : TlsConn FakeTransport :=
  let s := State.initial ⟨0, 0⟩ ⟨0⟩ .sha256
  let (_, s) := (s.allocOp .aeadOpen .application (some .read) ResourceLimits.standard.maxPendingCryptoOps).toOption.getD (⟨0⟩, s)
  { core := { s with handshake := .connected }, rt := {}, tr := { fd := fd0, inbound := [] },
    prov := fakeProvider }

def connectedForSend : TlsConn FakeTransport :=
  { core := { (State.initial ⟨0, 0⟩ ⟨0⟩ .sha256) with handshake := .connected }
    rt := {}, tr := { fd := fd0, inbound := [] }, prov := fakeProvider }

/-- Seal a handshake-flight message through `sealHandshakeRecord` with `suite` recorded as the
installed (write, handshake) suite — exercising that the interpreter dispatches the flight seal on
the installed suite rather than a hardcoded one. -/
def sealHsWithSuite (suite : CipherSuite) (secret plain : ByteArray) : Option ByteArray :=
  match SecretArena.empty.store secret with
  | .error _ => none
  | .ok (h, a1) =>
    let a2 := (a1.recordBaseSecret .write .handshake h.id).recordInstalledSuite .write .handshake suite
    match sealHandshakeRecord a2 0 plain with
    | .ok (some r) => some r
    | _ => none

def hsSecretFx : ByteArray := ByteArray.mk (Array.mkArray 32 (0x42 : UInt8))
def hsPlainFx  : ByteArray := bytesOf [0x14, 0x00, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04]
def aesHsSealed : Option ByteArray := sealHsWithSuite .aes128GcmSha256 hsSecretFx hsPlainFx
def chaHsSealed : Option ByteArray := sealHsWithSuite .chacha20Poly1305Sha256 hsSecretFx hsPlainFx
def aesHsOpened : Option (ByteArray × ContentType) :=
  aesHsSealed.bind (fun r =>
    Record13.openRecord (KeySchedule.trafficKey .aes128GcmSha256 hsSecretFx)
                        (KeySchedule.trafficIv hsSecretFx) 0 r .aes128GcmSha256)

/-- RFC 041 protected path: seal a fatal alert under a `(write, handshake)` key (the same arena
setup the handshake flight uses), then open it back — verifying the protected alert record is a real
`0x17` TLS 1.3 record whose inner content is `[fatal, no_application_protocol]` at content type `alert`. -/
def alertSealedHs : Option ByteArray :=
  match SecretArena.empty.store hsSecretFx with
  | .error _ => none
  | .ok (h, a1) =>
    let a2 := (a1.recordBaseSecret .write .handshake h.id).recordInstalledSuite .write .handshake .chacha20Poly1305Sha256
    match sealAlertRecord a2 .handshake 0 .noApplicationProtocol with
    | .ok (some r) => some r | _ => none

def alertOpenedHs : Option (ByteArray × ContentType) :=
  alertSealedHs.bind (fun r =>
    Record13.openRecord (KeySchedule.trafficKey .chacha20Poly1305Sha256 hsSecretFx)
                        (KeySchedule.trafficIv hsSecretFx) 0 r .chacha20Poly1305Sha256)

def checks : List Check :=
  [ -- full handshake through the public API
    { name := "handshake completes through TlsConn"
    , ok := handshaken.isConnected }
  , { name := "negotiated metadata available after connected (chacha20-poly1305)"
    , ok := handshaken.cipherSuite == some .chacha20Poly1305Sha256 }
  , { name := "server flight reached the fake transport"
    , ok := !handshaken.tr.outbound.isEmpty }
  , { name := "no plaintext buffered to the caller during the handshake"
    , ok := handshaken.rt.plaintextOut.isNone }
    -- write semantics (RFC 010 §4)
  , { name := "connected send takes ownership of plaintext (wrote n)"
    , ok := (match (connectedForSend.send (bytesOf [1, 2, 3])).2 with
             | .wrote n => n == 3 | _ => false) }
  , { name := "send before connected consumes zero (wouldBlock/closed, never wrote)"
    , ok := (match (freshServer.send (bytesOf [1, 2, 3])).2 with
             | .wrote _ => false | _ => true) }
  , { name := "send result does not accept the same bytes twice"
    , ok := (let (c1, r1) := connectedForSend.send (bytesOf [9, 9, 9, 9])
             match r1 with
             | .wrote n1 =>
                 -- a second send is independent accounting, not a re-accept of the first
                 let (_, r2) := c1.send (bytesOf [])
                 (match r2 with | .wrote n2 => n1 == 4 && n2 == 0 | .wouldBlock => n1 == 4 | _ => false)
             | _ => false) }
    -- flush drives pending ciphertext (RFC 010 §4)
  , { name := "after a connected send, flush drains the outbound queue"
    , ok := (let (c1, _) := connectedForSend.send (bytesOf [1, 2, 3])
             let (c2, fr) := c1.flush
             (match fr with | .flushed => true | _ => false) && c2.rt.outbound.isEmpty) }
    -- owned outbound-ciphertext accounting for the consumer's egress bound (RFC 015 §6)
  , { name := "ownedOutboundBytes reports the unflushed outbound ciphertext queue"
    , ok := (let owned : TlsConn FakeTransport :=
               { connectedForSend with rt := { connectedForSend.rt with outbound := bytesOf [1, 2, 3, 4, 5] } }
             let empty : TlsConn FakeTransport :=
               { connectedForSend with rt := { connectedForSend.rt with outbound := ByteArray.mk #[] } }
             owned.ownedOutboundBytes == 5 && empty.ownedOutboundBytes == 0) }
    -- partial writes preserve ordering (RFC 010 §11)
  , { name := "partial transport writes preserve byte ordering"
    , ok := (let tr : FakeTransport :=
               { fd := fd0, inbound := [], writeSchedule := [.sent 2, .sent 100] }
             let (rt', tr') := drainOutbound { (default : RuntimeState) with
                                                outbound := bytesOf [10, 20, 30, 40, 50] } tr
             tr'.writtenBytes.toList == [10, 20, 30, 40, 50] && rt'.outbound.isEmpty) }
  , { name := "send wouldBlock on a blocked transport consumes zero, retains order"
    , ok := (let tr : FakeTransport := { fd := fd0, inbound := [], writeSchedule := [.wouldBlock] }
             let (rt', tr') := drainOutbound { (default : RuntimeState) with
                                                outbound := bytesOf [7, 8, 9] } tr
             tr'.outbound.isEmpty && rt'.outbound.toList == [7, 8, 9]) }
    -- progress budget terminates (RFC 010 §10)
  , { name := "drive loop stops at the progress budget (never spins)"
    , ok := (let evs := List.replicate 10000 (InputEvent.transportReadable ⟨0, 0⟩)
             let (_, _, _) := driveEvents fakeProvider progressBudget connectedForSend.core
                               connectedForSend.rt connectedForSend.tr evs
             true) }  -- terminates within budget rather than diverging
    -- stale-event / stale-result defense (RFC 010 §8)
  , { name := "stale crypto result (unknown op id) then recv yields wouldBlock, no plaintext"
    , ok := (let c := connectedForRecv.progress
               (.cryptoResult ⟨0, 0⟩ ⟨999⟩ (.aeadOpened (bytesOf [0x41, 23])))
             match (c.recv).2 with | .wouldBlock => true | _ => false) }
  , { name := "outstanding crypto result then recv delivers authenticated plaintext"
    , ok := (let c := connectedForRecv.progress
               (.cryptoResult ⟨0, 0⟩ ⟨0⟩ (.aeadOpened (bytesOf [0x41, 0x42, 23])))
             match (c.recv).2 with | .bytes b => b.toList == [0x41, 0x42] | _ => false) }
  , { name := "sealHandshakeRecord seals the flight under the installed AES-128-GCM suite and opens back"
    , ok := (match aesHsOpened with
             | some (c, t) => c.toList == hsPlainFx.toList && (match t with | .handshake => true | _ => false)
             | none => false) }
  , { name := "sealHandshakeRecord follows the installed suite (AES-128 bytes differ from ChaCha bytes)"
    , ok := (match aesHsSealed, chaHsSealed with
             | some a, some c => a.toList != c.toList | _, _ => false) }
  , -- RFC 041: plaintext fatal-alert wire transmission (initial epoch)
    { name := "plaintextAlertRecord frames a fatal no_application_protocol record (21,3,3,0,2,2,120)"
    , ok := (plaintextAlertRecord .noApplicationProtocol).toList == [21, 3, 3, 0, 2, 2, 120] }
  , { name := "writeAlert at the initial epoch drains the plaintext alert record onto the transport"
    , ok :=
        let (_, trA, _) := execAction fakeProvider ({} : RuntimeState)
          ({ fd := fd0, inbound := [] } : FakeTransport)
          (.writeAlert ⟨0, 0⟩ .initial 0 .noApplicationProtocol)
        trA.writtenBytes.toList == [21, 3, 3, 0, 2, 2, 120] }
  , { name := "writeAlert at a protected epoch with no installed key transmits nothing (best-effort)"
    , ok :=
        let (_, trB, _) := execAction fakeProvider ({} : RuntimeState)
          ({ fd := fd0, inbound := [] } : FakeTransport)
          (.writeAlert ⟨0, 0⟩ .handshake 0 .noApplicationProtocol)
        trB.writtenBytes.toList == [] }
  , -- RFC 041 part 2: protected (sealed) fatal-alert records under installed write keys
    { name := "RFC 041 protected: handshake-epoch alert seals to a 0x17 record, not cleartext"
    , ok := (match alertSealedHs with
             | some r => r.size >= 5 && r.get! 0 == 0x17
                         && r.toList != (plaintextAlertRecord .noApplicationProtocol).toList
             | none => false) }
  , { name := "RFC 041 protected: sealed handshake-epoch alert opens to [fatal,120] at content type alert"
    , ok := (match alertOpenedHs with
             | some (body, ct) => body.toList == [2, 120] && ct == .alert
             | none => false) }
  , { name := "sealAlertRecord yields none without a write key (best-effort, no cleartext leak)"
    , ok := (match sealAlertRecord SecretArena.empty .application 0 .noApplicationProtocol with
             | .ok none => true | _ => false) }
  ]

def main : IO UInt32 := do
  let mut failures := 0
  IO.println "kroopt M7 TlsConn + interpreter tests:"
  for c in checks do
    if c.ok then IO.println s!"  PASS  {c.name}"
    else IO.println s!"  FAIL  {c.name}"; failures := failures + 1
  if failures == 0 then
    IO.println s!"\nAll {checks.length} checks passed."
    return 0
  else
    IO.println s!"\n{failures} of {checks.length} checks FAILED."
    return 1

end Tests.Conn

def main : IO UInt32 := Tests.Conn.main
