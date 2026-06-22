import Kroopt.Core.Cert

/-!
# Kroopt.Core.Config

The immutable server-configuration model for SNI certificate selection and ALPN
negotiation (RFC 011). The initial release line uses a *validated table*, not
callbacks — so selection is deterministic, non-blocking, reentrancy-free, and
provable. The consuming application owns ALPN *policy* (which protocols to offer and what to do with
the result); kroopt owns the deterministic *mechanism*.

`selectEndpoint` and `negotiateAlpn` are pure functions the verified core uses
during the handshake, and the proofs in `Kroopt.Proofs.Config` constrain them —
notably that ALPN never selects a protocol the client did not offer and the
endpoint did not allow (RFC 011 §8).
-/

namespace Kroopt.Core

open Kroopt (ConfigError)

/-- Byte-level equality for opaque identifiers (no `BEq` on `ByteArray`). -/
def baEq (a b : ByteArray) : Bool := a.toList == b.toList

/-- An ALPN protocol identifier: an opaque byte string (e.g. `http/1.1`). -/
structure AlpnProtocol where
  bytes : ByteArray
  deriving Inhabited

def AlpnProtocol.eq (a b : AlpnProtocol) : Bool := baEq a.bytes b.bytes

/-- Membership of an ALPN id in a list, by byte equality. -/
def alpnMem (x : AlpnProtocol) (xs : List AlpnProtocol) : Bool := xs.any (·.eq x)

/-- An SNI server-name pattern (RFC 011 §4). Wildcard matching, if used, is
limited to a single leftmost label. -/
inductive ServerNamePattern where
  | exact (name : ByteArray)
  /-- Matches `<one-label>.<suffix>`; `suffix` is the dotted remainder. -/
  | wildcard (suffix : ByteArray)
  deriving Inhabited

/-- The endpoint a route resolves to: a cert chain, a key, and the per-endpoint
ALPN / signature / suite allow-lists. -/
structure EndpointConfig where
  chain            : CertificateChainHandle
  key              : PrivateKeyHandle
  allowedAlpn      : List AlpnProtocol
  signatureSchemes : List SignatureScheme
  cipherSuites     : List CipherSuite
  /-- The public certificate-chain DER presented on the wire (RFC 012). Public, not secret —
  the private key stays behind `key`'s handle. Empty until a chain is configured. -/
  der              : ByteArray := ByteArray.empty
  deriving Inhabited

structure SniRoute where
  pattern  : ServerNamePattern
  endpoint : EndpointConfig
  deriving Inhabited

/-- How ALPN is selected from the client/endpoint intersection (RFC 011 §5). -/
inductive AlpnSelectionMode where
  | serverPreference
  | clientPreferenceWithinAllowed
  | requireOverlap
  deriving DecidableEq, Repr, Inhabited

/-- The raw, pre-validation configuration. -/
structure ServerConfig where
  defaultEndpoint  : Option EndpointConfig
  sniRoutes        : List SniRoute
  alpnMode         : AlpnSelectionMode
  deriving Inhabited

/-- A configuration that has passed validation, stamped with its generation
(RFC 011 §6). Immutable; reload produces a *new* generation, and existing
connections keep theirs. -/
structure ValidatedServerConfig where
  generation      : ConfigGeneration
  defaultEndpoint : Option EndpointConfig
  sniRoutes       : List SniRoute
  alpnMode        : AlpnSelectionMode
  deriving Inhabited

/-! ## SNI matching -/

/-- Index of the first `0x2e` ('.') in a byte list, if any. -/
def firstDotIdx (l : List UInt8) : Option Nat :=
  let rec go : List UInt8 → Nat → Option Nat
    | [], _ => none
    | b :: rest, i => if b = 0x2e then some i else go rest (i + 1)
  go l 0

/-- Does `name` match `pattern`? Exact compares the whole name; wildcard requires
exactly one leftmost label followed by `.` and the suffix. -/
def patternMatches (pattern : ServerNamePattern) (name : ByteArray) : Bool :=
  match pattern with
  | .exact p => baEq p name
  | .wildcard suffix =>
      let n := name.toList
      let s := suffix.toList
      match firstDotIdx n with
      | none => false
      | some i =>
          let label := n.take i
          let rest := n.drop (i + 1)
          label.length > 0 ∧ ¬ label.contains 0x2e ∧ rest == s

/-- Two patterns that would match the very same set are an ambiguity. We treat
identical exact names, and identical wildcard suffixes, as ambiguous. -/
def patternsConflict : ServerNamePattern → ServerNamePattern → Bool
  | .exact a,    .exact b    => baEq a b
  | .wildcard a, .wildcard b => baEq a b
  | _,           _           => false

/-! ## Config validation (RFC 011 §7, RFC 012 §5) -/

/-- Are there two routes whose patterns conflict? -/
def hasAmbiguousRoutes (routes : List SniRoute) : Bool :=
  let rec go : List SniRoute → Bool
    | [] => false
    | r :: rest => rest.any (fun r2 => patternsConflict r.pattern r2.pattern) || go rest
  go routes

/-- Validate one endpoint's cert/key compatibility and that it has a suite. -/
def validateEndpoint (e : EndpointConfig) : Except ConfigError Unit :=
  match e.cipherSuites with
  | [] => .error .noCipherSuite
  | _ =>
      match validateEndpointCertKey e.chain e.key e.signatureSchemes with
      | .error err => .error err
      | .ok _ => .ok ()

/-- Validate the whole configuration deterministically (RFC 011 §7). Rejects
ambiguous SNI routes and any endpoint whose cert/key/suites fail the lint. On
success, stamps the generation; the result is immutable. -/
def validateServerConfig (cfg : ServerConfig) (gen : ConfigGeneration) :
    Except ConfigError ValidatedServerConfig :=
  if hasAmbiguousRoutes cfg.sniRoutes then
    .error .ambiguousSni
  else
    let rec checkAll : List SniRoute → Except ConfigError Unit
      | [] => .ok ()
      | r :: rest =>
          match validateEndpoint r.endpoint with
          | .error e => .error e
          | .ok _ => checkAll rest
    match checkAll cfg.sniRoutes with
    | .error e => .error e
    | .ok _ =>
        match cfg.defaultEndpoint with
        | some d =>
            match validateEndpoint d with
            | .error e => .error e
            | .ok _ => .ok { generation := gen, defaultEndpoint := cfg.defaultEndpoint
                             sniRoutes := cfg.sniRoutes, alpnMode := cfg.alpnMode }
        | none => .ok { generation := gen, defaultEndpoint := none
                        sniRoutes := cfg.sniRoutes, alpnMode := cfg.alpnMode }

/-! ## Selection (used by the handshake) -/

/-- Select the endpoint for an (optional, already-validated) SNI name
(RFC 011 §4): exact match preferred over wildcard, falling back to the default
endpoint. Deterministic; ambiguity was rejected at validation. -/
def selectEndpoint (cfg : ValidatedServerConfig) (sni : Option ByteArray) :
    Option EndpointConfig :=
  match sni with
  | none => cfg.defaultEndpoint
  | some name =>
      let exactHit := cfg.sniRoutes.find? (fun r =>
        match r.pattern with | .exact p => baEq p name | _ => false)
      match exactHit with
      | some r => some r.endpoint
      | none =>
          let wildHit := cfg.sniRoutes.find? (fun r => patternMatches r.pattern name)
          match wildHit with
          | some r => some r.endpoint
          | none => cfg.defaultEndpoint

/-- Negotiate ALPN from the client's offered list and the endpoint's allow-list
(RFC 011 §5). Returns `none` for "no ALPN" (the caller's policy decides whether
that is acceptable). Any `some` result is guaranteed to be in **both** lists. -/
def negotiateAlpn (mode : AlpnSelectionMode)
    (clientOffered : List AlpnProtocol) (allowed : List AlpnProtocol) :
    Option AlpnProtocol :=
  match mode with
  | .serverPreference =>
      allowed.find? (fun a => alpnMem a clientOffered)
  | .clientPreferenceWithinAllowed =>
      clientOffered.find? (fun a => alpnMem a allowed)
  | .requireOverlap =>
      clientOffered.find? (fun a => alpnMem a allowed)

end Kroopt.Core
