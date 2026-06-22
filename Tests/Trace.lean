import Kroopt.Conn.Trace

/-!
# Tests.Trace

Tests for the no-secrets trace facility (RFC 036 §3). The load-bearing property is
**secret-freedom by construction**: `traceOfAction` projects every byte-bearing action to a
*length* and every secret reference to a bare event, so no rendered trace line can contain
plaintext, ciphertext, certificate DER, a transcript digest, or a secret handle. The
centerpiece tests embed a `SECRET` sentinel inside secret-bearing actions and assert the
rendered trace never reproduces it.
-/

namespace Tests.Trace

open Kroopt Kroopt.Core Kroopt.Conn

structure Check where
  name : String
  ok : Bool

def conn0 : ConnId := ⟨0, 0⟩

/-- Substring containment (Lean's `String.contains` is char-only). -/
def hasSub (s sub : String) : Bool := (s.splitOn sub).length > 1

/-- Render a single action's trace, or "" if not trace-worthy. -/
def line (a : OutputAction) : String :=
  (traceOfAction a |>.map TraceEvent.render).getD ""

-- A recognizable secret sentinel placed inside secret-bearing actions.
def secretBytes : ByteArray := "SECRETPLAINTEXT".toUTF8        -- 15 bytes
def derBytes    : ByteArray := "FAKEDERCHAIN".toUTF8           -- 12 bytes
def cipherBytes : ByteArray := "SECRETCIPHERTEXT".toUTF8       -- 16 bytes

def checks : List Check :=
  [ -- per-variant projection / render
    { name := "readTransport → transport-read"
    , ok := line (.readTransport conn0) == "transport-read conn=0" }
  , { name := "writeTransport renders length, not bytes"
    , ok := line (.writeTransport conn0 cipherBytes) == "transport-write conn=0 len=16" }
  , { name := "enableWriteInterest → enabled=true"
    , ok := line (.enableWriteInterest conn0) == "write-interest conn=0 enabled=true" }
  , { name := "disableWriteInterest → enabled=false"
    , ok := line (.disableWriteInterest conn0) == "write-interest conn=0 enabled=false" }
  , { name := "callCrypto renders op id + kind"
    , ok := line (.callCrypto conn0 ⟨5⟩ (CryptoOp.randomBytes 32))
              == "crypto-call conn=0 op=5 kind=randomBytes" }
  , { name := "acceptPlaintextBytes → n"
    , ok := line (.acceptPlaintextBytes conn0 7) == "plaintext-accept conn=0 n=7" }
  , { name := "closeTransport graceful → mode=graceful"
    , ok := line (.closeTransport conn0 .graceful) == "transport-close conn=0 mode=graceful" }
  , { name := "closeTransport fatal → mode=fatal (no alert detail)"
    , ok := line (.closeTransport conn0 (.fatal .handshakeFailure)) == "transport-close conn=0 mode=fatal" }
  , { name := "releaseSecret → bare event, no handle"
    , ok := line (.releaseSecret ⟨99, 0⟩) == "secret-released" }
  , { name := "failWithAlert close_notify → level=warning"
    , ok := line (.failWithAlert conn0 .closeNotify) |> (hasSub · "level=warning") }
  , { name := "failWithAlert handshake_failure → level=fatal"
    , ok := line (.failWithAlert conn0 .handshakeFailure) |> (hasSub · "level=fatal") }
  , { name := "writeHandshake → message type label only"
    , ok := line (.writeHandshake conn0 .handshake 0 (.encryptedExtensions none))
              == "handshake-out conn=0 seq=0 msg=EncryptedExtensions" }
  , { name := "recordMetric-style metric channel is not present; readTransport stays traceable"
    , ok := (traceOfAction (.readTransport conn0)).isSome }

    -- ── no-secrets discipline (the centerpiece) ──
  , { name := "emitPlaintext: render shows length, NEVER the plaintext bytes"
    , ok := let l := line (.emitPlaintext conn0 secretBytes)
            l == "plaintext-emit conn=0 len=15" && !hasSub l "SECRET" }
  , { name := "writeTransport: ciphertext sentinel never appears"
    , ok := !hasSub (line (.writeTransport conn0 cipherBytes)) "SECRET" }
  , { name := "writeCertificate: render shows der length, NEVER the DER bytes"
    , ok := let l := line (.writeCertificate conn0 .handshake 0 derBytes)
            l == "certificate-out conn=0 seq=0 der-len=12" && !hasSub l "FAKEDER" }
  , { name := "callCrypto: secret-bearing op renders kind only, NEVER the inputs"
    , ok := let l := line (.callCrypto conn0 ⟨3⟩
                      (CryptoOp.verifyFinished .sha256 secretBytes secretBytes))
            l == "crypto-call conn=0 op=3 kind=verifyFinished" && !hasSub l "SECRET" }
  , { name := "reportError renders category only, never detail"
    , ok := let l := line (.reportError conn0 (.crypto .authFailed))
            l == "error conn=0 category=crypto" && !hasSub l "authFailed" }

    -- ── aggregate: a mixed secret-bearing action stream is wholly secret-free ──
  , { name := "traceActions over a mixed stream: NO line reproduces the SECRET sentinel"
    , ok := let acts : List OutputAction :=
              [ .readTransport conn0
              , .writeTransport conn0 cipherBytes
              , .callCrypto conn0 ⟨1⟩ (CryptoOp.verifyFinished .sha256 secretBytes secretBytes)
              , .emitPlaintext conn0 secretBytes
              , .writeCertificate conn0 .handshake 0 derBytes
              , .releaseSecret ⟨7, 0⟩
              , .failWithAlert conn0 .handshakeFailure ]
            let rendered := traceActions acts
            rendered.length == 7 && rendered.all (fun l => !hasSub l "SECRET" && !hasSub l "FAKEDER") }
  ]

def main : IO Unit := do
  let mut failed := 0
  for c in checks do
    if c.ok then
      IO.println s!"  ok   {c.name}"
    else
      failed := failed + 1
      IO.println s!"  FAIL {c.name}"
  if failed == 0 then
    IO.println s!"All {checks.length} passed."
  else
    IO.eprintln s!"{failed} of {checks.length} FAILED."
    IO.Process.exit 1

end Tests.Trace

def main : IO Unit := Tests.Trace.main
