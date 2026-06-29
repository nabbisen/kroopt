import Kroopt.Core.Config
import Kroopt.Core.Alert

/-!
# Tests.Config

SNI/ALPN configuration and certificate-presentation tests (RFC 011 §9,
RFC 012 §10): exact and wildcard SNI matching, default fallback, ALPN
intersection by policy, no-overlap behaviour, config-generation stamping,
cert/key compatibility lint, and signature-scheme selection.
-/

namespace Tests.Config

open Kroopt Kroopt.Core

structure Check where
  name : String
  ok : Bool

def bytesOf (l : List UInt8) : ByteArray := ByteArray.mk l.toArray
def name (s : String) : ByteArray := s.toUTF8

def alpnH11 : AlpnProtocol := ⟨name "http/1.1"⟩
def alpnH2  : AlpnProtocol := ⟨name "h2"⟩
def alpnUnknown : AlpnProtocol := ⟨name "spdy/1"⟩  -- offered by client, not in any endpoint allow-list

def leafEd : LeafCertificateMeta :=
  { publicKeyKind := .ed25519, subjectNameCount := 1, notBeforeUnix := none, notAfterUnix := none }
def chainEd : CertificateChainHandle :=
  { id := 1, generation := ⟨0⟩, chainLen := 1, derSize := 500, leafMeta := leafEd }
def keyEd : PrivateKeyHandle := { secret := ⟨1, 0⟩, keyKind := .ed25519, generation := ⟨0⟩ }
def keyEcdsa : PrivateKeyHandle := { secret := ⟨2, 0⟩, keyKind := .ecdsaP256, generation := ⟨0⟩ }

def epEd : EndpointConfig :=
  { chain := chainEd, key := keyEd, allowedAlpn := [alpnH2, alpnH11]
    signatureSchemes := [.ed25519], cipherSuites := [.aes128GcmSha256] }
def epDefault : EndpointConfig := { epEd with allowedAlpn := [alpnH11] }

def routeExact : SniRoute := { pattern := .exact (name "a.example.com"), endpoint := epEd }
def routeWild : SniRoute := { pattern := .wildcard (name "wild.com"), endpoint := epEd }

def goodConfig : ServerConfig :=
  { defaultEndpoint := some epDefault, sniRoutes := [routeExact, routeWild]
    alpnMode := .serverPreference }

def alpnEmpty : AlpnProtocol := ⟨ByteArray.empty⟩
def alpnHuge  : AlpnProtocol := ⟨ByteArray.mk (Array.mkArray 256 0x61)⟩  -- 256 bytes, over the 255 max
def cfgEmptyAlpn : ServerConfig :=
  { goodConfig with defaultEndpoint := some { epEd with allowedAlpn := [alpnEmpty] }, sniRoutes := [] }
def cfgHugeAlpn : ServerConfig :=
  { goodConfig with defaultEndpoint := some { epEd with allowedAlpn := [alpnHuge] }, sniRoutes := [] }

def validated (gen : Nat) : Option ValidatedServerConfig :=
  match validateServerConfig goodConfig ⟨gen.toUInt64⟩ with
  | .ok v => some v | .error _ => none

def checks : List Check :=
  [ -- RFC 042 B1 — validated ResourceLimits are threaded through config
    { name := "serverConfigCarriesResourceLimits"
    , ok := (goodConfig.limits.maxClientHelloBytes == 16384
               && (match validateServerConfig goodConfig ⟨0⟩ with
                   | .ok v => v.limits.maxClientHelloBytes == 16384 | .error _ => false)) }
  , { name := "validatedConfigRejectsImpossibleCiphertextLimit"
    , ok := (let cfg := { goodConfig with
                          limits := { ResourceLimits.standard with maxPendingCiphertextBytes := 10 } }
             match validateServerConfig cfg ⟨0⟩ with
             | .error .invalidLimits => true | _ => false) }
  , { name := "a zero handshake-byte limit is rejected"
    , ok := (let cfg := { goodConfig with
                          limits := { ResourceLimits.standard with maxHandshakeBytes := 0 } }
             match validateServerConfig cfg ⟨0⟩ with
             | .error .invalidLimits => true | _ => false) }
  , { name := "customPendingCryptoOpsLimitIsUsed"
    , ok := (let cfg := { goodConfig with
                          limits := { ResourceLimits.standard with maxPendingCryptoOps := 99 } }
             match validateServerConfig cfg ⟨0⟩ with
             | .ok v => v.limits.maxPendingCryptoOps == 99 | .error _ => false) }
  , { name := "customHandshakeByteLimitIsUsed"
    , ok := (let cfg := { goodConfig with
                          limits := { ResourceLimits.standard with maxHandshakeBytes := 99999 } }
             match validateServerConfig cfg ⟨0⟩ with
             | .ok v => v.limits.maxHandshakeBytes == 99999 | .error _ => false) }
  , { name := "customClientHelloLimitIsUsed"
    , ok := (let cfg := { goodConfig with
                          limits := { ResourceLimits.standard with maxClientHelloBytes := 4096 } }
             match validateServerConfig cfg ⟨0⟩ with
             | .ok v => v.limits.maxClientHelloBytes == 4096 | .error _ => false) }
  , { name := "customCiphertextLimitIsUsed"
    , ok := (let cfg := { goodConfig with
                          limits := { ResourceLimits.standard with maxPendingCiphertextBytes := 500000 } }
             match validateServerConfig cfg ⟨0⟩ with
             | .ok v => v.limits.maxPendingCiphertextBytes == 500000 | .error _ => false) }
    -- config validation + generation (RFC 011 §6, §7)
  , { name := "valid config validates and is stamped with its generation"
    , ok := (match validateServerConfig goodConfig ⟨7⟩ with
             | .ok v => v.generation.value == 7 | .error _ => false) }
  , { name := "ambiguous SNI routes are rejected"
    , ok := (let cfg := { goodConfig with sniRoutes := [routeExact, routeExact] }
             match validateServerConfig cfg ⟨0⟩ with
             | .error .ambiguousSni => true | _ => false) }
  , { name := "an empty ALPN identifier is rejected at config validation (RFC 7301)"
    , ok := (match validateServerConfig cfgEmptyAlpn ⟨0⟩ with
             | .error .invalidAlpn => true | _ => false) }
  , { name := "an over-long (>255 byte) ALPN identifier is rejected"
    , ok := (match validateServerConfig cfgHugeAlpn ⟨0⟩ with
             | .error .invalidAlpn => true | _ => false) }
    -- SNI selection (RFC 011 §4)
  , { name := "absent SNI selects the default endpoint"
    , ok := (match validated 0 with
             | some v => (selectEndpoint v none).isSome | none => false) }
  , { name := "exact SNI match selects its route"
    , ok := (match validated 0 with
             | some v => match selectEndpoint v (some (name "a.example.com")) with
                         | some e => e.signatureSchemes == [.ed25519] | none => false
             | none => false) }
  , { name := "wildcard SNI matches a single leftmost label"
    , ok := (match validated 0 with
             | some v => (selectEndpoint v (some (name "host.wild.com"))).isSome
             | none => false) }
  , { name := "wildcard does not match a multi-label prefix"
    , ok := patternMatches (.wildcard (name "wild.com")) (name "a.b.wild.com") == false }
  , { name := "unknown SNI falls back to the default endpoint"
    , ok := (match validated 0 with
             | some v => (selectEndpoint v (some (name "nope.test"))).isSome
             | none => false) }
    -- ALPN negotiation (RFC 7301 §3.2, RFC 011 §5) — A1 strict no-overlap, AlpnDecision
  , { name := "alpnOverlapRequireOverlapSelects: requireOverlap selects by server preference"
    , ok := (match negotiateAlpn .requireOverlap (some [alpnH2, alpnH11]) [alpnH11, alpnH2] with
             | .selected a => a.eq alpnH11 | _ => false) }
  , { name := "ALPN serverPreference picks the server's first overlapping protocol"
    , ok := (match negotiateAlpn .serverPreference (some [alpnH2, alpnH11]) [alpnH11, alpnH2] with
             | .selected a => a.eq alpnH11 | _ => false) }
  , { name := "ALPN clientPreference picks the client's first overlapping protocol"
    , ok := (match negotiateAlpn .clientPreferenceWithinAllowed (some [alpnH2, alpnH11]) [alpnH11, alpnH2] with
             | .selected a => a.eq alpnH2 | _ => false) }
  , { name := "alpnSelectedIsOfferedAndAllowed: a selection is both offered and allowed"
    , ok := (match negotiateAlpn .serverPreference (some [alpnH11]) [alpnH2, alpnH11] with
             | .selected a => alpnMem a [alpnH11] && alpnMem a [alpnH2, alpnH11] | _ => false) }
  , { name := "alpnUnknownPlusAllowedIgnoresUnknownAndSelectsAllowed"
    , ok := (match negotiateAlpn .serverPreference (some [alpnUnknown, alpnH11]) [alpnH11] with
             | .selected a => a.eq alpnH11 | _ => false) }
  , { name := "alpnAbsentRequireOverlapProceeds: no ALPN extension ⇒ notOffered, no failure"
    , ok := (match negotiateAlpn .requireOverlap none [alpnH11] with
             | .notOffered => true | _ => false) }
  , { name := "alpnNoOverlapRequireOverlapFailsNoApplicationProtocol: strict no-overlap ⇒ noOverlap"
    , ok := (match negotiateAlpn .requireOverlap (some [alpnH2]) [alpnH11] with
             | .noOverlap => true | _ => false) }
  , { name := "alpnLenientNoOverlapServerPreferenceReturnsNoOverlap (fact, not notOffered)"
    , ok := (match negotiateAlpn .serverPreference (some [alpnH2]) [alpnH11] with
             | .noOverlap => true | _ => false) }
  , { name := "alpnLenientNoOverlapClientPreferenceReturnsNoOverlap (fact, not notOffered)"
    , ok := (match negotiateAlpn .clientPreferenceWithinAllowed (some [alpnH2]) [alpnH11] with
             | .noOverlap => true | _ => false) }
  , { name := "notOfferedNeverMeansOfferedNoOverlap: an offer never yields notOffered, in any mode"
    , ok := ([AlpnSelectionMode.serverPreference, .clientPreferenceWithinAllowed, .requireOverlap].all
               (fun m => match negotiateAlpn m (some [alpnH2]) [alpnH11] with
                         | .notOffered => false | _ => true)
             -- and absence yields notOffered in every mode
             && [AlpnSelectionMode.serverPreference, .clientPreferenceWithinAllowed, .requireOverlap].all
               (fun m => match negotiateAlpn m none [alpnH11] with
                         | .notOffered => true | _ => false)) }
  , { name := "alertNoApplicationProtocolRoundTrips120: 120 ⇄ no_application_protocol via ofByte/toByte, fatal"
    , ok := (AlertDescription.ofByte 120 == some .noApplicationProtocol
             && AlertDescription.noApplicationProtocol.toByte == 120
             && AlertDescription.ofByte AlertDescription.noApplicationProtocol.toByte == some .noApplicationProtocol
             && alertLevel .noApplicationProtocol == .fatal) }
    -- certificate / key lint (RFC 012 §5, §6)
  , { name := "compatible Ed25519 cert/key validates"
    , ok := (match validateEndpointCertKey chainEd keyEd [.ed25519] with
             | .ok info => info.compatibleSchemes == [.ed25519] | .error _ => false) }
  , { name := "incompatible cert/key kinds are rejected"
    , ok := (match validateEndpointCertKey chainEd keyEcdsa [.ed25519] with
             | .error .certKeyMismatch => true | _ => false) }
  , { name := "empty certificate chain is rejected"
    , ok := (match validateEndpointCertKey { chainEd with chainLen := 0 } keyEd [.ed25519] with
             | .error .emptyChain => true | _ => false) }
  , { name := "oversized DER chain is rejected"
    , ok := (match validateEndpointCertKey { chainEd with derSize := 70000 } keyEd [.ed25519] with
             | .error .oversizedDer => true | _ => false) }
  , { name := "signature scheme selected is offered, configured, and key-compatible"
    , ok := (match selectSignatureScheme [.ecdsaSecp256r1Sha256, .ed25519] [.ed25519] .ed25519 with
             | some s => s == .ed25519 | none => false) }
  , { name := "no compatible signature scheme yields none"
    , ok := (selectSignatureScheme [.ecdsaSecp256r1Sha256] [.ed25519] .ed25519).isNone }
  ]

def main : IO UInt32 := do
  let mut failures := 0
  IO.println "kroopt M8 SNI/ALPN config + cert presentation tests:"
  for c in checks do
    if c.ok then IO.println s!"  PASS  {c.name}"
    else IO.println s!"  FAIL  {c.name}"; failures := failures + 1
  if failures == 0 then
    IO.println s!"\nAll {checks.length} checks passed."
    return 0
  else
    IO.println s!"\n{failures} of {checks.length} checks FAILED."
    return 1

end Tests.Config

def main : IO UInt32 := Tests.Config.main
