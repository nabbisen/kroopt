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
  /-- Allowed named-group SET for this endpoint (RFC 039). Order is ignored for selection
  preference (fixed by the core, `groupPreference`); the set must be non-empty and
  duplicate-free (enforced at config validation). Default `[x25519, secp256r1]`; set
  `[.x25519]` for a hardened x25519-only endpoint. -/
  namedGroups      : List NamedGroup := [.x25519, .secp256r1]
  /-- The public certificate-chain DER presented on the wire (RFC 012). Public, not secret —
  the private key stays behind `key`'s handle. Empty until a chain is configured. -/
  der              : ByteArray := ByteArray.empty

/-- `Inhabited` is written by hand (not `deriving`) so that `(default : EndpointConfig)`
picks up the field-level `namedGroups` default `[x25519, secp256r1]` rather than the
`Inhabited (List _) = []` that `deriving` would supply — every `{ default with … }`
construction site then gets the intended non-empty group policy. -/
instance : Inhabited EndpointConfig where
  default := { chain := default, key := default, allowedAlpn := [],
               signatureSchemes := [], cipherSuites := [] }

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

/-- The two orthogonal axes hidden inside `AlpnSelectionMode`, split out so `negotiateAlpn` can report
*facts* without baking in policy (RFC 042-style fact/policy separation; ALPN `notOffered`-overload review).
`preference` is which side's order wins a selection; `noOverlapPolicy` is what an offered-but-non-overlapping
list *means* — and is applied by the handshake caller, not by `negotiateAlpn`. -/
inductive AlpnPreference where
  | server
  | client
  deriving DecidableEq, Repr

inductive AlpnNoOverlapPolicy where
  | proceedWithoutProtocol
  | fatal
  deriving DecidableEq, Repr

def AlpnSelectionMode.preference : AlpnSelectionMode → AlpnPreference
  | .serverPreference              => .server
  | .clientPreferenceWithinAllowed => .client
  | .requireOverlap                => .server

def AlpnSelectionMode.noOverlapPolicy : AlpnSelectionMode → AlpnNoOverlapPolicy
  | .serverPreference              => .proceedWithoutProtocol
  | .clientPreferenceWithinAllowed => .proceedWithoutProtocol
  | .requireOverlap                => .fatal

/-- The **fact** ALPN negotiation establishes (RFC 7301 §3.2, RFC 011 §5): the
client offered no ALPN, a protocol was selected, or the client offered ALPN but
nothing overlapped the endpoint's allowed set. `.noOverlap` is the no-overlap
*fact* — it is not itself fatal; the handshake caller applies `mode.noOverlapPolicy`
to decide whether it fails (`requireOverlap`) or proceeds with no protocol (the
lenient modes). `.notOffered` means *only* "no extension", never a downgraded
no-overlap. Internal: the public surface exposes `negotiatedAlpn : Option …`. -/
inductive AlpnDecision where
  | notOffered
  | selected (p : AlpnProtocol)
  | noOverlap
  deriving Inhabited

/-- Configured per-connection ceilings (RFC 019 §7, external design §5.5, RFC 042). Only limits that are
actually enforced live here: `maxHandshakeBytes`/`maxClientHelloBytes` (charged on the inbound handshake
path), `maxPendingCryptoOps` (the outstanding-crypto-op budget in `allocOp`), `maxPendingCiphertextBytes`
(the interpreter's outbound-ciphertext backstop, RFC 042 A1), and `maxProgressStepsPerCall` (the
`driveEvents` progress-loop fuel). Inbound record size is bounded by the parser (`Reader.lengthExceedsMax`)
and extension count transitively by `maxClientHelloBytes`, so neither needs a separate ceiling here. -/
structure ResourceLimits where
  maxHandshakeBytes         : Nat := 65536
  maxClientHelloBytes       : Nat := 16384
  maxPendingCryptoOps       : Nat := 16
  maxPendingCiphertextBytes : Nat := 1048576
  maxProgressStepsPerCall   : Nat := 256
  deriving Repr

/-- The default limits are the standard ceilings, **not** all-zeros: a structure's field defaults do not
flow into a `deriving Inhabited` instance, so we give one explicitly. This keeps any config that defaults
its limits (via `Inhabited`) usable rather than rejecting every ClientHello. -/
instance : Inhabited ResourceLimits := ⟨{}⟩

def ResourceLimits.standard : ResourceLimits := {}

/-- The smallest protected TLS 1.3 application record carries one plaintext byte: a 5-byte record header
plus the sealed payload (`1` plaintext + `1` inner content-type + `16` AEAD tag). `maxPendingCiphertextBytes`
must be at least this, or every `send` would permanently back-pressure (RFC 042 A1 config validation). -/
def minProtectedRecordLen : Nat := 23

/-- Deterministic sealed length of a TLS 1.3 application record carrying `n` plaintext bytes with no
padding: `5` header + `n` + `1` inner content-type + `16` AEAD tag (RFC 8446 §5.2). Used by the egress
backstop to fit a prefix under the outbound-ciphertext cap (RFC 042 A1). -/
def ciphertextRecordLen (n : Nat) : Nat := n + 22

/-- The raw, pre-validation configuration. -/
structure ServerConfig where
  defaultEndpoint  : Option EndpointConfig
  sniRoutes        : List SniRoute
  alpnMode         : AlpnSelectionMode
  limits           : ResourceLimits := ResourceLimits.standard
  deriving Inhabited

/-- A configuration that has passed validation, stamped with its generation
(RFC 011 §6). Immutable; reload produces a *new* generation, and existing
connections keep theirs. -/
structure ValidatedServerConfig where
  generation      : ConfigGeneration
  defaultEndpoint : Option EndpointConfig
  sniRoutes       : List SniRoute
  alpnMode        : AlpnSelectionMode
  limits          : ResourceLimits
  deriving Inhabited

/-- A placeholder validated config whose single default endpoint advertises the baseline server-auth
signature schemes kroopt's bundled providers support. Used as the default when no config is supplied
(`State.initial`, `TlsConn.server`); production always supplies its own validated config, so this is
only negotiated against by core-level tests. The endpoint presents no certificate DER (the real
config fills that in). -/
def ValidatedServerConfig.baseline : ValidatedServerConfig :=
  { (default : ValidatedServerConfig) with
    limits := ResourceLimits.standard
    defaultEndpoint := some
      { (default : EndpointConfig) with
        signatureSchemes := [.ed25519, .ecdsaSecp256r1Sha256, .rsaPssRsaeSha256] } }

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

/-- Validate one endpoint: it must offer a cipher suite, carry only well-formed ALPN identifiers
(RFC 7301 — each 1..255 bytes), and have a compatible cert/key pair. -/
def validateEndpoint (e : EndpointConfig) : Except ConfigError Unit :=
  match e.cipherSuites with
  | [] => .error .noCipherSuite
  | _ =>
      if e.allowedAlpn.any (fun a => a.bytes.size == 0 || decide (a.bytes.size > 255)) then
        .error .invalidAlpn
      else
        match validateEndpointCertKey e.chain e.key e.signatureSchemes with
        | .error err => .error err
        | .ok _ => .ok ()

/-- Validate the configured resource limits (RFC 042 B1). Each enforced ceiling must be usable: the
handshake/ClientHello byte budgets and the crypto-op and progress budgets must be non-zero, the
ClientHello budget cannot exceed the total handshake budget, and the outbound-ciphertext cap must fit at
least one minimal protected record (else every `send` would permanently back-pressure). -/
def validLimits (l : ResourceLimits) : Bool :=
  l.maxHandshakeBytes > 0
    && l.maxClientHelloBytes > 0
    && decide (l.maxClientHelloBytes ≤ l.maxHandshakeBytes)
    && l.maxPendingCryptoOps > 0
    && decide (l.maxPendingCiphertextBytes ≥ minProtectedRecordLen)
    && l.maxProgressStepsPerCall > 0

/-- Validate the whole configuration deterministically (RFC 011 §7). Rejects
ambiguous SNI routes and any endpoint whose cert/key/suites fail the lint. On
success, stamps the generation; the result is immutable. -/
def validateServerConfig (cfg : ServerConfig) (gen : ConfigGeneration) :
    Except ConfigError ValidatedServerConfig :=
  if hasAmbiguousRoutes cfg.sniRoutes then
    .error .ambiguousSni
  else if ¬ validLimits cfg.limits then
    .error .invalidLimits
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
                             sniRoutes := cfg.sniRoutes, alpnMode := cfg.alpnMode
                             limits := cfg.limits }
        | none => .ok { generation := gen, defaultEndpoint := none
                        sniRoutes := cfg.sniRoutes, alpnMode := cfg.alpnMode
                        limits := cfg.limits }

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

/-- ALPN negotiation (RFC 7301 §3.2, RFC 011 §5). `offered` is the client's ALPN
list: `none` = the client sent no ALPN extension; `some os` = it offered `os` (the
parser guarantees `os` non-empty and well-formed, rejecting an empty list or empty
name as malformed). `allowed` is the endpoint's configured set.

This reports a **fact**, not a policy outcome (ALPN `notOffered`-overload review):

* no extension ⇒ `.notOffered` — and `.notOffered` means *only* this, never a
  downgraded no-overlap;
* overlap ⇒ `.selected p`, picked by `mode.preference`: `.server` order (the
  default and `requireOverlap`) lets the server pick among the client's advertised
  protocols by its own preference (RFC 7301); `.client` order
  (`clientPreferenceWithinAllowed`) picks by the client's order;
* the client offered ALPN but nothing overlaps the endpoint's allowed set ⇒
  `.noOverlap` — **regardless of mode**. Whether that fact is fatal is the caller's
  policy: the handshake fails with `no_application_protocol` only under a `fatal`
  `mode.noOverlapPolicy` (the strict `requireOverlap`); the lenient modes proceed
  with no protocol selected. -/
def negotiateAlpn (mode : AlpnSelectionMode)
    (offered : Option (List AlpnProtocol)) (allowed : List AlpnProtocol) : AlpnDecision :=
  match offered with
  | none => .notOffered
  | some os =>
    let pick := match mode.preference with
      | .client => os.find? (fun a => alpnMem a allowed)
      | .server => allowed.find? (fun a => alpnMem a os)
    match pick with
    | some p => .selected p
    | none   => .noOverlap

end Kroopt.Core
