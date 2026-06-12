import Kroopt.Core.Handshake
import Kroopt.Core.Transcript

/-!
# Tests.Handshake

Synthetic handshake trace (RFC 006 §12–13) and transcript checks (RFC 007 §10).
The handshake transition functions are driven directly with fake crypto results
(no sockets, no real crypto): a constructed `ValidClientHello`, a fake ECDHE
secret handle, a fake signature, and a fake "verified" result. The positive
trace must reach `connected` and report completion; the negative traces must fail
deterministically without reaching `connected`.
-/

namespace Tests.Handshake

open Kroopt Kroopt.Core

structure Check where
  name : String
  ok : Bool

def bytes (l : List UInt8) : ByteArray := ByteArray.mk l.toArray

def vch : ValidClientHello :=
  { selectedSuite := .aes128GcmSha256
    selectedGroup := .x25519
    clientShare := bytes (List.replicate 32 0x07)
    selectedSigScheme := .ed25519
    sni := some (bytes [0x65, 0x78]) -- "ex"
    alpn := [bytes [0x68, 0x32]] }   -- "h2"

def s0 : State := State.initial ⟨0, 0⟩ ⟨0⟩ .sha256
def chWire : ByteArray := bytes [1, 0, 0, 4, 0x03, 0x04, 0, 0]
def cfWire : ByteArray := bytes [20, 0, 0, 32]
def fakeSecret : SecretKeyHandle := ⟨42, 0⟩
def fakeSig : ByteArray := bytes (List.replicate 64 0xAB)

/-- Run the whole synthetic handshake, returning the final state and whether each
phase along the way matched the expected legal edge. -/
def runHandshake : Except TlsError (State × List OutputAction × List HandshakeState) := do
  let (s1, _) ← onClientHello s0 vch chWire
  let (s2, _) ← onEcdheDone s1 fakeSecret
  -- pump the handshake-key schedule: 5 derivations then 2 installs, the last of
  -- which lands at the pause and frames EE/Cert + requests CertVerify
  let (p1, _) ← onHsScheduleResult s2 (.hkdfSecret ⟨0, 0⟩)
  let (p2, _) ← onHsScheduleResult p1 (.hkdfSecret ⟨0, 0⟩)
  let (p3, _) ← onHsScheduleResult p2 (.hkdfSecret ⟨0, 0⟩)
  let (p4, _) ← onHsScheduleResult p3 (.hkdfSecret ⟨0, 0⟩)
  let (p5, _) ← onHsScheduleResult p4 (.hkdfSecret ⟨0, 0⟩)
  let (p6, _) ← onHsScheduleResult p5 .keysInstalled
  let (s2done, _) ← onHsScheduleResult p6 .keysInstalled
  let (s3, _) ← onCertVerifySigned s2done fakeSig
  -- pump the application-key stage: 4 derivations then 2 installs, the last of
  -- which lands at `complete` and installs the application epoch
  let (q1, _) ← onApScheduleResult s3 (.hkdfSecret ⟨0, 0⟩)
  let (q2, _) ← onApScheduleResult q1 (.hkdfSecret ⟨0, 0⟩)
  let (q3, _) ← onApScheduleResult q2 (.hkdfSecret ⟨0, 0⟩)
  let (q4, _) ← onApScheduleResult q3 (.hkdfSecret ⟨0, 0⟩)
  let (q5, _) ← onApScheduleResult q4 .keysInstalled
  let (s3done, _) ← onApScheduleResult q5 .keysInstalled
  let (s4, _) ← onClientFinishedBytes s3done cfWire
  let (s5, acts) ← onClientFinishedVerified s4 true cfWire
  .ok (s5, acts,
       [s1.handshake, s2.handshake, s2done.handshake, s3.handshake, s3done.handshake,
        s4.handshake, s5.handshake])

def reportsComplete (acts : List OutputAction) : Bool :=
  acts.any (fun a => match a with
    | .reportHandshakeComplete _ _ => true
    | _ => false)

def checks : List Check :=
  [ { name := "full synthetic handshake reaches connected"
    , ok := (match runHandshake with
             | .ok (s, _, _) => s.handshake == .connected
             | .error _ => false) }
  , { name := "handshake phases follow the legal server-flight order"
    , ok := (match runHandshake with
             | .ok (_, _, phases) =>
                 phases == [.requestedEcdhe, .derivedHandshakeSecrets,
                            .requestedCertificateVerifySignature, .sentCertificateVerify,
                            .sentServerFinished, .requestedClientFinishedVerify, .connected]
             | .error _ => false) }
  , { name := "completion is reported on success"
    , ok := (match runHandshake with
             | .ok (_, acts, _) => reportsComplete acts
             | .error _ => false) }
  , { name := "transcript committed all seven flight messages (incl. both Finished)"
    , ok := (match runHandshake with
             | .ok (s, _, _) => s.transcript.eventCount == 7
             | .error _ => false) }
  , { name := "transcript holds CH, SH, EE, Cert, CertVerify, srvFin, cliFin in order"
    , ok := (match runHandshake with
             | .ok (s, _, _) =>
                 (s.transcript.events.map (fun e => e.meta.kind))
                   == [.clientHello, .serverHello, .encryptedExtensions,
                       .certificate, .certificateVerify, .finished, .finished]
             | .error _ => false) }
  , { name := "ClientHello transcript bytes are the exact parsed bytes"
    , ok := (match runHandshake with
             | .ok (s, _, _) =>
                 (match s.transcript.events.head? with
                  | some e => e.wireBytes.toList == chWire.toList
                  | none => false)
             | .error _ => false) }
  -- Negative traces
  , { name := "out-of-order: ECDHE result before ClientHello fails"
    , ok := (match onEcdheDone s0 fakeSecret with
             | .ok (s, _) => s.handshake.isTerminal && s.handshake != .connected
             | .error _ => true) }
  , { name := "bad Finished (verified = false) fails, not connected"
    , ok := (match (do
               let (s1, _) ← onClientHello s0 vch chWire
               let (s2, _) ← onEcdheDone s1 fakeSecret
               let (s3, _) ← onCertVerifySigned s2 fakeSig
               let (s4, _) ← onClientFinishedBytes s3 cfWire
               onClientFinishedVerified s4 false cfWire : Except TlsError _) with
             | .ok (s, _) => s.handshake != .connected && s.handshake.isTerminal
             | .error _ => true) }
  , { name := "ClientHello twice: second is rejected (wrong phase)"
    , ok := (match (do
               let (s1, _) ← onClientHello s0 vch chWire
               onClientHello s1 vch chWire : Except TlsError _) with
             | .ok (s, _) => s.handshake.isTerminal && s.handshake != .connected
             | .error _ => true) }
  -- Transcript snapshot discipline
  , { name := "snapshot counter advances across the flight"
    , ok := (match runHandshake with
             | .ok (s, _, _) => s.transcript.snapshotCounter > 0
             | .error _ => false) }
  ]

def main : IO UInt32 := do
  let mut failures := 0
  IO.println "kroopt M4 handshake + transcript trace tests:"
  for c in checks do
    if c.ok then
      IO.println s!"  PASS  {c.name}"
    else
      IO.println s!"  FAIL  {c.name}"
      failures := failures + 1
  if failures == 0 then
    IO.println s!"\nAll {checks.length} checks passed."
    return 0
  else
    IO.println s!"\n{failures} of {checks.length} checks FAILED."
    return 1

end Tests.Handshake

def main : IO UInt32 := Tests.Handshake.main
