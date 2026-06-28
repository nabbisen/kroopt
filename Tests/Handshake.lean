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
    offeredShares := [(.x25519, bytes (List.replicate 32 0x07))]
    offeredSigSchemes := [.ed25519]
    sni := some (bytes [0x65, 0x78]) -- "ex"
    alpn := some [bytes [0x68, 0x32]]
    sessionId := ByteArray.empty }   -- "h2"

def s0 : State := State.initial ⟨0, 0⟩ ⟨0⟩ .sha256
def chWire : ByteArray := bytes [1, 0, 0, 4, 0x03, 0x04, 0, 0]
def cfWire : ByteArray := bytes [20, 0, 0, 32]
def fakeSecret : SecretKeyHandle := ⟨42, 0⟩
def fakeServerShare : ByteArray := bytes (List.replicate 32 0x09)
def fakeServerRandom : ByteArray := bytes (List.replicate 32 0x5a)
def fakeFinishedMac : ByteArray := bytes (List.replicate 32 0xEF)
def fakeSig : ByteArray := bytes (List.replicate 64 0xAB)

/-- Drive one crypto result through the production correlation dispatcher
(`handshakeOnGatingResult`), which **retires the outstanding op** (RFC 037 §4.1) before
dispatching to the transition function — exactly the real `step` path. Using this instead of
calling the transition functions directly makes the trace model crypto-op lifetime, so the
pending set stays bounded rather than accumulating one registration per step. -/
def gate (s : State) (r : CryptoResult) : Except TlsError (State × List OutputAction) :=
  handshakeOnGatingResult s ((s.pendingOps.ops.head?.map (·.id)).getD ⟨0⟩) r

/-- Run the whole synthetic handshake, returning the final state and whether each
phase along the way matched the expected legal edge. -/
def runHandshake : Except TlsError (State × List OutputAction × List HandshakeState) := do
  let (s1, _) ← onClientHello s0 vch chWire
  let (sR, _) ← gate s1 (.randomBytes fakeServerRandom)
  let (s2, _) ← gate sR (.ecdheComplete fakeServerShare fakeSecret)
  -- pump the handshake-key schedule: 5 derivations then 2 installs, the last of
  -- which lands at the pause and frames EE/Cert + requests CertVerify
  let (p1, _) ← gate s2 (.hkdfSecret ⟨0, 0⟩)
  let (p2, _) ← gate p1 (.hkdfSecret ⟨0, 0⟩)
  let (p3, _) ← gate p2 (.hkdfSecret ⟨0, 0⟩)
  let (p4, _) ← gate p3 (.hkdfSecret ⟨0, 0⟩)
  let (p5, _) ← gate p4 (.hkdfSecret ⟨0, 0⟩)
  let (p6, _) ← gate p5 .keysInstalled
  let (s2done, _) ← gate p6 .keysInstalled
  let (s3, _) ← gate s2done (.signature fakeSig)
  let (sF, _) ← gate s3 (.finishedMac fakeFinishedMac)
  -- pump the application-key stage: 4 derivations then 2 installs, the last of
  -- which lands at `complete` and installs the application epoch
  let (q1, _) ← gate sF (.hkdfSecret ⟨0, 0⟩)
  let (q2, _) ← gate q1 (.hkdfSecret ⟨0, 0⟩)
  let (q3, _) ← gate q2 (.hkdfSecret ⟨0, 0⟩)
  let (q4, _) ← gate q3 (.hkdfSecret ⟨0, 0⟩)
  let (q5, _) ← gate q4 .keysInstalled
  let (s3done, _) ← gate q5 .keysInstalled
  let (s4, _) ← onClientFinishedBytes s3done cfWire
  let (s5, acts) ← gate s4 .verified
  .ok (s5, acts,
       [s1.handshake, sR.handshake, s2.handshake, s2done.handshake, s3.handshake, sF.handshake,
        s3done.handshake, s4.handshake, s5.handshake])

def reportsComplete (acts : List OutputAction) : Bool :=
  acts.any (fun a => match a with
    | .reportHandshakeComplete _ _ => true
    | _ => false)

def s0Ed : State :=
  { State.initial ⟨0, 0⟩ ⟨0⟩ .sha256 with
    serverConfig :=
      { (default : Kroopt.Core.ValidatedServerConfig) with
        defaultEndpoint := some
          { (default : Kroopt.Core.EndpointConfig) with signatureSchemes := [.ed25519] } } }

/-- A ClientHello offering only RSA-PSS — recognized and well-formed, but with no overlap against an
endpoint that can only sign Ed25519. -/
def vchRsaOnly : ValidClientHello := { vch with offeredSigSchemes := [.rsaPssRsaeSha256] }

/-- A `requireOverlap` endpoint that allows only `http/1.1`; the shared `vch` offers only `h2`, so
ALPN negotiation finds no overlap and (under the strict mode) the handshake must fail with
`no_application_protocol` before any ServerHello/random action (RFC 7301 §3.2). -/
def s0EdRequireOverlap : State :=
  { State.initial ⟨0, 0⟩ ⟨0⟩ .sha256 with
    serverConfig :=
      { (default : Kroopt.Core.ValidatedServerConfig) with
        alpnMode := .requireOverlap
        defaultEndpoint := some
          { (default : Kroopt.Core.EndpointConfig) with
            signatureSchemes := [.ed25519]
            allowedAlpn := [⟨"http/1.1".toUTF8⟩] } } }

def checks : List Check :=
  [ { name := "full synthetic handshake reaches connected"
    , ok := (match runHandshake with
             | .ok (s, _, _) => s.handshake == .connected
             | .error _ => false) }
    -- RFC 037 §4.1: because each result is consumed through the correlation dispatcher
    -- (which retires the answered op), a completed handshake leaves the pending-op set empty —
    -- the budget measures outstanding work, not cumulative history.
  , { name := "a successful handshake leaves no crypto ops pending (RFC 037 §4.1)"
    , ok := (match runHandshake with
             | .ok (s, _, _) => s.pendingOps.ops.length == 0
             | .error _ => false) }
  , { name := "onClientHello with no signature-scheme overlap fails with handshake_failure (RFC 8446 §9.2)"
    , ok := (match onClientHello s0Ed vchRsaOnly chWire with
             | .ok ({ handshake := .failed .handshakeFailure, .. }, _) => true
             | _ => false) }
  , { name := "alpnNoOverlapRequireOverlapFailsNoApplicationProtocol (RFC 7301 §3.2)"
    , ok := (match onClientHello s0EdRequireOverlap vch chWire with
             | .ok ({ handshake := .failed .noApplicationProtocol, .. }, _) => true
             | _ => false) }
  , { name := "alpnNoOverlapDoesNotEmitServerHello: no random/ServerHello action on no-overlap"
    , ok := (match onClientHello s0EdRequireOverlap vch chWire with
             | .ok (_, acts) =>
                 acts.all (fun a => match a with
                   | .callCrypto .. => false | .writeTransport .. => false | _ => true)
             | _ => false) }
  , { name := "alpnNoOverlapEmitsPlaintextAlert: no-overlap emits writeAlert(initial, no_application_protocol) (RFC 041)"
    , ok := (match onClientHello s0EdRequireOverlap vch chWire with
             | .ok (_, acts) =>
                 acts.any (fun a => match a with
                   | .writeAlert _ .initial _ .noApplicationProtocol => true | _ => false)
             | _ => false) }
  , { name := "onClientHello with a matching scheme advances past start (no spurious failure)"
    , ok := (match onClientHello s0Ed vch chWire with
             | .ok ({ handshake := .failed _, .. }, _) => false
             | .ok _ => true
             | .error _ => false) }
    -- RFC 037 §4: a ClientHello whose wire bytes exceed the ClientHello budget (16384) is
    -- rejected in the core by the proven `chargeClientHelloBytes`, failing the handshake
    -- terminally with the generic internal_error alert (no budget detail leaks).
  , { name := "an oversized ClientHello is rejected by the ClientHello-bytes budget (RFC 037 §4)"
    , ok := (match onClientHello s0 vch (bytes (List.replicate 20000 0)) with
             | .ok (s', _) => (match s'.handshake with | .failed .internalError => true | _ => false)
             | .error _ => false) }
    -- positive control: the normal ClientHello is under budget and advances the handshake.
  , { name := "a normal ClientHello is under the ClientHello-bytes budget"
    , ok := (match onClientHello s0 vch chWire with
             | .ok (s', _) => (match s'.handshake with | .failed _ => false | _ => true)
             | .error _ => false) }
  , { name := "handshake phases follow the legal server-flight order"
    , ok := (match runHandshake with
             | .ok (_, _, phases) =>
                 phases == [.requestedServerRandom, .requestedEcdhe, .derivedHandshakeSecrets,
                            .requestedCertificateVerifySignature, .requestedServerFinishedMac,
                            .sentCertificateVerify, .sentServerFinished,
                            .requestedClientFinishedVerify, .connected]
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
    , ok := (match onEcdheDone s0 fakeServerShare fakeSecret with
             | .ok (s, _) => s.handshake.isTerminal && s.handshake != .connected
             | .error _ => true) }
  , { name := "bad Finished (verified = false) fails, not connected"
    , ok := (match (do
               let (s1, _) ← onClientHello s0 vch chWire
               let (sR, _) ← onServerRandomDone s1 fakeServerRandom
               let (s2, _) ← onEcdheDone sR fakeServerShare fakeSecret
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


