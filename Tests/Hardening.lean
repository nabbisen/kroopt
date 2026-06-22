import Kroopt.Core.Budget
import Kroopt.Core.Step
import Kroopt.Parse.Handshake

/-!
# Tests.Hardening

Cross-cutting hardening tests: resource-budget enforcement (RFC 019) and
deferred-feature scope control (RFC 016). Budgets are hard bounds — an accepted
charge stays within the ceiling and an over-limit charge is rejected. Scope
control confirms a ClientHello that does not genuinely offer TLS 1.3 (no
`supported_versions` 0x0304, or only TLS 1.2) is refused rather than silently
downgraded.
-/

namespace Tests.Hardening

open Kroopt Kroopt.Core

structure Check where
  name : String
  ok : Bool

def bytesOf (l : List UInt8) : ByteArray := ByteArray.mk l.toArray
def u16be (n : Nat) : List UInt8 := [(n / 256).toUInt8, (n % 256).toUInt8]
def lim : ResourceLimits := .standard
def b0 : BudgetState := .empty

-- ClientHello builders with controllable extensions, for scope control.
def keyShareEntry : List UInt8 := [0x00, 0x1d, 0, 32] ++ List.replicate 32 0x07  -- 32-byte x25519 share (RFC 8446 §4.2.8.2)
def extKeyShare : List UInt8 := [0, 51, 0, 38, 0, 36] ++ keyShareEntry
def extSigAlgs : List UInt8 := [0, 0x0d, 0, 4, 0, 2, 0x08, 0x07]  -- signature_algorithms: ed25519
def extSigAlgsOther : List UInt8 := [0, 0x0d, 0, 6, 0, 4, 0x04, 0x03, 0x08, 0x04]  -- ecdsa_p256, rsa_pss (no ed25519)
def extSupVer13 : List UInt8 := [0, 43, 0, 3, 2, 0x03, 0x04]   -- offers TLS 1.3
def extSupVer12 : List UInt8 := [0, 43, 0, 3, 2, 0x03, 0x03]   -- offers only TLS 1.2
def chWithSuites (suiteBytes exts : List UInt8) : ByteArray :=
  let body := [0x03, 0x03] ++ (List.replicate 32 0xAA) ++ [0] ++
              (u16be suiteBytes.length ++ suiteBytes) ++ [1, 0] ++ (u16be exts.length ++ exts)
  bytesOf ([1] ++ [0, (body.length / 256).toUInt8, (body.length % 256).toUInt8] ++ body)
def chWith (exts : List UInt8) : ByteArray := chWithSuites [0x13, 0x03] exts  -- chacha20-poly1305

def parseOk (exts : List UInt8) : Bool :=
  match Kroopt.Parse.parseClientHello (chWith exts) with
  | .ok _ => true | .error _ => false

/-- The suite kroopt negotiates from an explicit cipher-suite list, or `none` if the
ClientHello is rejected. -/
def negotiatedSuite (suiteBytes exts : List UInt8) : Option Kroopt.Core.CipherSuite :=
  match Kroopt.Parse.parseClientHello (chWithSuites suiteBytes exts) with
  | .ok wb => some wb.value.selectedSuite | .error _ => none

/-- A ClientHello whose legacy_version is 0x0301, not the RFC-mandated 0x0303. -/
def chBadVersion (exts : List UInt8) : ByteArray :=
  let body := [0x03, 0x01] ++ (List.replicate 32 0xAA) ++ [0] ++
              [0, 2, 0x13, 0x03] ++ [1, 0] ++ (u16be exts.length ++ exts)
  bytesOf ([1] ++ [0, (body.length / 256).toUInt8, (body.length % 256).toUInt8] ++ body)

/-- A ClientHello offering a non-null compression method (0x01), which TLS 1.3 forbids. -/
def chBadCompression (exts : List UInt8) : ByteArray :=
  let body := [0x03, 0x03] ++ (List.replicate 32 0xAA) ++ [0] ++
              [0, 2, 0x13, 0x03] ++ [1, 1] ++ (u16be exts.length ++ exts)
  bytesOf ([1] ++ [0, (body.length / 256).toUInt8, (body.length % 256).toUInt8] ++ body)

def rejects (ch : ByteArray) : Bool :=
  match Kroopt.Parse.parseClientHello ch with | .ok _ => false | .error _ => true

def checks : List Check :=
  [ -- resource budgets are hard bounds (RFC 019)
    { name := "handshake-byte charge within budget is accepted"
    , ok := (match chargeHandshakeBytes lim b0 100 with
             | .ok b => b.handshakeBytesSeen == 100 | .error _ => false) }
  , { name := "handshake-byte charge over budget is rejected"
    , ok := (match chargeHandshakeBytes lim b0 (lim.maxHandshakeBytes + 1) with
             | .error .handshakeBytes => true | _ => false) }
  , { name := "accumulated handshake bytes cannot exceed the ceiling"
    , ok := (let b1 := (chargeHandshakeBytes lim b0 (lim.maxHandshakeBytes - 10)).toOption.getD b0
             match chargeHandshakeBytes lim b1 100 with
             | .error .handshakeBytes => true | _ => false) }
  , { name := "extension-count charge over budget is rejected"
    , ok := (match chargeExtensions lim b0 (lim.maxExtensions + 1) with
             | .error .extensionCount => true | _ => false) }
  , { name := "oversized record is rejected before allocation"
    , ok := (match checkRecordSize lim (lim.maxRecordPlaintextBytes + 1) with
             | .error .recordSize => true | _ => false) }
  , { name := "max-size record is accepted"
    , ok := (match checkRecordSize lim lim.maxRecordPlaintextBytes with
             | .ok _ => true | .error _ => false) }
  , { name := "progress-step charge over budget is rejected (no spin)"
    , ok := (let full : BudgetState :=
               { b0 with progressStepsThisCall := lim.maxProgressStepsPerCall }
             match chargeProgressStep lim full with
             | .error .progressSteps => true | _ => false) }
  , { name := "pending-ciphertext charge over budget is rejected"
    , ok := (match chargePendingCiphertext lim b0 (lim.maxPendingCiphertextBytes + 1) with
             | .error .pendingCiphertext => true | _ => false) }
    -- deferred-feature scope control (RFC 016)
  , { name := "ClientHello offering TLS 1.3 with X25519 parses"
    , ok := parseOk (extSupVer13 ++ extKeyShare ++ extSigAlgs) }
  , { name := "ClientHello with no supported_versions is refused (no TLS 1.2 downgrade)"
    , ok := !parseOk extKeyShare }
  , { name := "ClientHello offering only TLS 1.2 is refused"
    , ok := !parseOk (extSupVer12 ++ extKeyShare) }
  , { name := "ClientHello with no key_share is refused (no HRR)"
    , ok := !parseOk extSupVer13 }
  , { name := "ClientHello offering only ECDSA/RSA signature_algorithms is refused (no Ed25519 overlap, RFC 033)"
    , ok := !parseOk (extSupVer13 ++ extKeyShare ++ extSigAlgsOther) }
  , { name := "ClientHello with no signature_algorithms is refused (cert-authenticating server, RFC 8446 §4.2.3)"
    , ok := !parseOk (extSupVer13 ++ extKeyShare) }
  , { name := "ClientHello offering only AES-128-GCM is refused (constrained profile performs ChaCha20-Poly1305 only, RFC 033)"
    , ok := (negotiatedSuite [0x13, 0x01] (extSupVer13 ++ extKeyShare ++ extSigAlgs)).isNone }
  , { name := "ClientHello listing AES-128-GCM before ChaCha20 negotiates ChaCha20 (capability overlap, not first-offered)"
    , ok := (negotiatedSuite [0x13, 0x01, 0x13, 0x03] (extSupVer13 ++ extKeyShare ++ extSigAlgs)
              == some .chacha20Poly1305Sha256) }
  , { name := "ClientHello with legacy_version ≠ 0x0303 is refused (RFC 8446 §4.1.2)"
    , ok := rejects (chBadVersion (extSupVer13 ++ extKeyShare ++ extSigAlgs)) }
  , { name := "ClientHello offering non-null compression is refused (TLS 1.3 forbids compression, RFC 8446 §4.1.2)"
    , ok := rejects (chBadCompression (extSupVer13 ++ extKeyShare ++ extSigAlgs)) }
  ]

def main : IO UInt32 := do
  let mut failures := 0
  IO.println "kroopt M11 hardening: budgets + scope control tests:"
  for c in checks do
    if c.ok then IO.println s!"  PASS  {c.name}"
    else IO.println s!"  FAIL  {c.name}"; failures := failures + 1
  if failures == 0 then
    IO.println s!"\nAll {checks.length} checks passed."
    return 0
  else
    IO.println s!"\n{failures} of {checks.length} checks FAILED."
    return 1

end Tests.Hardening

def main : IO UInt32 := Tests.Hardening.main
