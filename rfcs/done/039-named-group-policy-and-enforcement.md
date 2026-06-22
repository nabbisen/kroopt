# RFC 039 — Named-Group Policy and Selection Enforcement

**Project.** kroopt  
**Status.** Implemented (v0.81.0-dev)  
**Type.** Implementation RFC  
**Target milestone.** v0.4 hardening (follows 0.76.0-dev Stage 1)  
**Depends on.** RFC 008 (crypto provider / capability validation), RFC 034 (capability
honesty), RFC 006 (handshake, no HRR), RFC 002 (proof/runtime correspondence), RFC 005
(record/epoch proofs over `step`).  
**Touches.** `Kroopt/Core/Config.lean` (`EndpointConfig`, profiles),
`Kroopt/Crypto/ConfigCheck.lean` (`requiredCryptoOfServerConfig`, validation),
`Kroopt/Crypto/Provider.lean` (`RequiredCrypto`, `CapabilityError` — new
`.emptyGroupPolicy`/`.duplicateNamedGroup` variants),
`Kroopt/Parse/Handshake.lean` (key_share surfacing), `Kroopt/Core/Handshake.lean` +
`Kroopt/Core/State.lean` (group selection in the core, `policyView`),
`Kroopt/Proofs/Handshake.lean` (new selection-authorization theorem),
`Tests/EndToEnd.lean`, `Tests/Capabilities.lean`, `Tests/Handshake.lean`,
`scripts/tls-interop.sh`, `docs/src/crypto/crypto-ffi-contract.md`,
`docs/src/architecture/handshake.md`.  
**Canonical source.** `handoff/REVIEW-secp256r1-capability-gap.md` (problem statement and
Option C decision) and the architect's two review responses (the Option-C verdict and the
default-policy ruling). 0.76.0-dev shipped Stage 1 (Option B) of that review; this RFC is
Stages 2–5.  
**Revision.** rev-2 incorporated the architect's RFC 039 review (approve-after-amendment):
normalization/duplicate policy (§4.5), supported_groups consistency (§4.6), the P-256
key_share validation contract (§4.7), alert mapping (§4.8), safe negotiation tracing (§4.9),
an explicit `groupPreference`, the crypto-op-consistency theorems (§5.2), and a derive-**and-
enforce** hash dimension (§4.4). rev-3 (approved-for-implementation) applies the two merge
clarifications — a total `selectGroup` with no `get!` (§4.3) and the absent-`supported_groups`
compatibility-policy note (§4.6) — and the error-taxonomy fix (endpoint-policy faults are
`CapabilityError`; client-side faults are TLS handshake errors, §4.5). The two prior open
questions are resolved (§12). **Status: approved for implementation.**

---

## 1. Summary

0.76.0-dev made the secp256r1 advertisement **honest** — `realCapabilities.groups =
[.x25519, .secp256r1]` reflects a real, NIST-CAVP-validated, OpenSSL-interop-tested P-256
ECDHE path. It did **not** make the group dimension **load-bearing**. Three facts remain:

1. `requiredCryptoOfServerConfig` hardcodes `groups := []`, so the `.unsupportedGroup`
   check in `validateCapabilities` is structurally unreachable — `CryptoCapabilities.groups`
   has exactly one consumer and that consumer can never fire.
2. `EndpointConfig` has no group field, so a listener cannot express a group policy (e.g.
   "x25519 only").
3. Group selection lives entirely in the ClientHello parser (`x25519.orElse p256`),
   consulting neither capabilities nor config.

The advertised group set is therefore declarative, not enforced. This RFC makes the group
dimension authoritative and proven, on the same model kroopt already uses for cipher
suites and signature schemes, and cleans up the parallel inert `hashAlgorithms := []`.

The decision recorded here (architect ruling): the **default** endpoint policy is
`[x25519, secp256r1]` with **x25519 preferred**, because P-256 is a TLS 1.3 baseline
interoperability group (RFC 8446 — secp256r1 MUST, X25519 SHOULD) and v0.4 intends real
P-256 support, not hidden reachability. Hardened deployments opt into an explicit
`[x25519]` profile.

## 2. The three-layer model (normative)

These are distinct and must not be conflated:

| Layer | Question it answers | Where it lives | Default |
|---|---|---|---|
| **Provider capability** | What can this binary do? | `CryptoCapabilities.groups` (`realCapabilities`) | `[x25519, secp256r1]` |
| **Endpoint policy** | What is this listener allowed to negotiate? | `EndpointConfig.namedGroups` (new) | `[x25519, secp256r1]` |
| **Selection preference** | Given an overlap, which is chosen? | core selection order | `x25519` then `secp256r1` |

Invariant established at config validation: **endpoint policy ⊆ provider capability**.
Invariant proven in the core: **selected group ∈ client key_share groups ∩ endpoint
policy**. Composing the two yields selected group ∈ provider capability without the core
ever depending on the provider capability object (see §6).

## 3. Goals

1. Add `EndpointConfig.namedGroups` with the default `[x25519, secp256r1]` and a
   documented `[x25519]`-only profile preset.
2. Populate `RequiredCrypto.groups` from config and enforce endpoint-policy ⊆ provider
   capability at validation, with `.unsupportedGroup`.
3. Reject `namedGroups = []` as an invalid endpoint policy (empty ≠ "any supported group").
4. Move group **selection** into the verified core, constrained to the client's offered
   key_share groups intersected with endpoint policy, ordered by server preference.
5. Prove `selectedGroup ∈ clientKeyShareGroups ∧ selectedGroup ∈ endpointAllowed` over
   `step`.
6. Resolve the parallel inert `hashAlgorithms := []` — derive from suites **and enforce**
   against provider capability (§4.4).

## 4. Design

### 4.1 Endpoint group policy (`Kroopt/Core/Config.lean`)

```lean
structure EndpointConfig where
  chain            : CertificateChainHandle
  key              : PrivateKeyHandle
  allowedAlpn      : List AlpnProtocol
  signatureSchemes : List SignatureScheme
  cipherSuites     : List CipherSuite
  namedGroups      : List NamedGroup    -- NEW. Allowed named-group SET for this endpoint.
                                         -- Order is ignored for negotiation preference;
                                         -- server preference is fixed by Core.groupPreference (§4.3).
                                         -- Must be non-empty and duplicate-free (§4.5).
  der              : ByteArray := ByteArray.empty
  deriving Inhabited
```

- The default builder and all fixtures set `namedGroups := [.x25519, .secp256r1]`.
- A documented hardened preset sets `namedGroups := [.x25519]`.
- `namedGroups` is the *allowed set*, not the *preference order* (Amendment 2); selection
  preference is a fixed core policy (`groupPreference`, §4.3), not per-endpoint, to keep the
  proof and behaviour simple. (If a future RFC wants per-endpoint preference, it extends
  this; out of scope here.)

### 4.2 Capability validation (`ConfigCheck.lean`, `Provider.lean`)

```lean
def requiredCryptoOfEndpoint (e : EndpointConfig) : RequiredCrypto :=
  { suites           := e.cipherSuites
    groups           := e.namedGroups
    signatureSchemes := e.signatureSchemes
    hashAlgorithms   := deriveHashesFromSuites e.cipherSuites }   -- §4.4
```

`requiredCryptoOfServerConfig` folds endpoints as today, now with non-empty `groups`.
`validateServerConfigCapabilities` gains two rejections:

- **`namedGroups = []` for any endpoint → `.emptyGroupPolicy`** (new `CapabilityError`
  variant). Empty must be an error, never "accept anything"; if an unconstrained policy is
  ever wanted it must be a *named* variant, not implicit-empty.
- **A group in `namedGroups` not in `caps.groups` → `.unsupportedGroup`** (the existing
  check, now reachable).

This restores the RFC 008 §3 / RFC 034 §2 guarantee for the group dimension: a config that
requires a group the binary cannot perform fails at listener startup, deterministically,
never at runtime.

### 4.3 Core-level group selection (`Parse/Handshake.lean`, `Core/Handshake.lean`, `State.lean`)

The parser stops *selecting* and instead *surfaces* the structurally valid offered shares:

```lean
-- Parse layer: returns ALL offered key_share entries it can structurally validate
--   x25519:    group 0x001d, 32-byte share
--   secp256r1: group 0x0017, 65-byte uncompressed point (first byte 0x04)
def offeredKeyShares : … → List (NamedGroup × ByteArray)
```

The core selects, using endpoint policy from `policyView` and a single, auditable
preference list (Amendment 3 — preference is **not** buried inside `selectGroup`):

```lean
/-- The one canonical server preference order. Future groups (X448, FFDHE) are added
    here and nowhere else, so selection preference has a single audit point. -/
def groupPreference : List NamedGroup := [.x25519, .secp256r1]

/-- Total lookup of a group's offered share (no partial access). -/
def shareFor? (g : NamedGroup) (offered : List KeyShare) : Option ByteArray :=
  (offered.find? (fun ks => ks.group == g)).map (·.share)

/-- Total, auditable selection: walk `groupPreference` and take the first group that is
    both allowed by the endpoint and offered with a usable key_share. `offered` is the
    normalized, duplicate-free share set (§4.5); `allowed` is the normalized endpoint
    policy (§4.5). No `get!`/partial access — verification-first by construction. -/
def selectGroup (offered : List KeyShare) (allowed : List NamedGroup)
  : Except GroupSelectionError SelectedGroup :=
  match groupPreference.findSome? (fun g =>
          if g ∈ allowed then
            match shareFor? g offered with
            | some share => some ⟨g, share⟩
            | none       => none
          else none) with
  | some selected => .ok selected
  | none          => .error .noAcceptableGroup
```

Layering (each layer does exactly one job):

- **Parser** — syntax only: structurally valid offered shares (§4.7 for P-256 shape).
- **Selection (core)** — policy only: `groupPreference` over `offered ∩ allowed`.
- **Provider** — cryptographic validation only (on-curve / not-infinity; §4.7).
- **Core proof** — selected group is offered ∧ allowed (§5.1) and the emitted crypto op
  matches the selected group (§5.2).
- **Config validation** — allowed ⊆ provider capability (§4.2).

Rules:

- **No-HRR rule (RFC 006).** Selection is over **key_share** groups only — a group present
  in `supported_groups` but lacking a key_share is not selectable (kroopt sends no
  HelloRetryRequest). If `selectGroup` returns `.noAcceptableGroup`, the handshake fails
  cleanly via the existing no-acceptable-share path (§4.8 for the alert).
- **Preference.** Fixed by `groupPreference` (x25519 before secp256r1); explicitly tested.
- `policyView` (the immutable validated-config view the core already carries) gains the
  endpoint's normalized `namedGroups`. The core does **not** gain provider capabilities
  (see §6).

### 4.4 Hash dimension — derive and enforce (Amendment 9)

`hashAlgorithms` in TLS 1.3 is determined by the cipher suite (transcript/HKDF hash) and
the signature scheme (signature hash). Rather than leave the field ornamental, this RFC
takes the **derive-and-enforce** position:

- `RequiredCrypto.hashAlgorithms := deriveHashesFromSuites e.cipherSuites` (the hashes the
  configured suites need — SHA-256 / SHA-384).
- The provider must advertise those hashes; if a future suite needs SHA-384 and the
  provider lacks it, config validation fails with `.unsupportedHash` **even if the suite
  was mistakenly advertised**. This is a belt-and-suspenders consistency check, not
  ornament.

A field described as "informational only" must not sit in a capability object; if a future
maintainer prefers, the explicit alternative is to *remove* `hashAlgorithms` from
`RequiredCrypto` entirely until kroopt has independent hash selection. This RFC chooses
derive-and-enforce; removal is out of scope unless re-decided.

### 4.5 Named-group normalization and duplicate policy (Amendments 1, 4)

Both the **endpoint policy list** and the **client's offered key_share list** are
normalized before use, and duplicates are rejected (not silently collapsed) — a
cryptographic policy/negotiation surface should fail loudly on surprising input.

Endpoint policy (config-time):

```lean
def normalizeNamedGroups : List NamedGroup → Except CapabilityError (List NamedGroup)
-- · reject empty                       → CapabilityError.emptyGroupPolicy
-- · reject duplicates                  → CapabilityError.duplicateNamedGroup
-- · (unknown/disabled group ids are not representable in NamedGroup, so cannot occur here;
--    a config requiring a known-but-unsupported group is caught by validateCapabilities
--    as .unsupportedGroup)
-- · result carries set semantics only (order is not preference)
```

**Error taxonomy.** Endpoint-policy faults (empty / duplicate / unsupported group) are
`CapabilityError` (a *configuration* failure, RFC 008 §3). Client-side faults (duplicate
key_share group, supported_groups/key_share contradiction, malformed P-256 point) are TLS
**handshake** errors (`ProtocolError`/`ParseError` → fatal alert, §4.8), never
`CapabilityError`. The two taxonomies stay separate.

Client key_share (parse/negotiation-time): a ClientHello carrying **two key_share entries
for the same group** is malformed. kroopt rejects it deterministically through the existing
illegal-parameter/malformed path — never "first wins" or "last wins" (which would let a
peer smuggle ambiguity past the parser). RFC 8446 §4.2.8 already forbids duplicate
`KeyShareEntry` groups; kroopt enforces it.

Tests: `configRejectsDuplicateNamedGroups`, `duplicateKeyShareGroupRejected`,
`duplicateX25519KeyShareRejected`, `duplicateP256KeyShareRejected`.

### 4.6 `supported_groups` vs `key_share` consistency (Amendment 5)

This resolves former open question 2. Because kroopt has no HRR, **selection is driven by
the usable initial `key_share`**, not by `supported_groups`. But the two extensions must be
consistent:

- A `key_share` entry for a group that the same ClientHello's `supported_groups` explicitly
  **omits** is a contradiction → reject as illegal parameter. kroopt must never select a
  group whose key_share is present while `supported_groups` excludes it.
- If `supported_groups` is **present**, the selected group's key_share group must appear in
  it.
- If `supported_groups` is **absent**, selection proceeds from `key_share` alone. This is a
  **deliberate compatibility policy**, not an inference from endpoint policy: if
  `supported_groups` is absent but a syntactically valid `key_share` is present, kroopt
  accepts `key_share` as the authoritative no-HRR signal for this constrained server
  profile. A future strict-profile RFC may instead reject such ClientHellos.
- A group in `supported_groups` with **no** key_share is not selectable (no HRR) — this is
  a clean handshake failure, not an error in itself.

Tests: `keyShareGroupMissingFromSupportedGroupsRejected`,
`supportedGroupsWithoutKeyShareFailsNoHRR`.

### 4.7 P-256 `key_share` validation contract (Amendment 6)

Validation is split across the layers and is **defined**, not incidental:

- **Parser** validates wire shape only: secp256r1 key_share is exactly 65 bytes with
  uncompressed prefix `0x04`. Anything else is not surfaced as a P-256 offer.
- **Provider** performs cryptographic point validation. This is already real: the shim
  re-checks shape (`len == 65`, `[0] == 0x04`) and calls `Hacl_P256_ecp256dh_r`, which
  validates the peer point is on-curve and not the point at infinity, returning fail-closed
  `none` on rejection (`kroopt_ffi_p256_shared`). No separate Lean-side curve check is
  required because HACL owns this; this RFC records that dependency explicitly.
- **Core** treats any provider ECDH rejection as a fatal handshake failure with **no
  selected-group success** — the connection fails, no `ecdheComplete` is fabricated.

Existing KATs already cover bad-prefix and wrong-size scalar (`Tests/Hacl.lean`). This RFC
adds: `p256BadPrefixRejected`, `p256BadLengthRejected`, and `p256ProviderRejectsInvalidPoint`
(a 65-byte, `0x04`-prefixed but off-curve point → provider `none` → fatal failure).

### 4.8 Alert mapping (Amendment 10)

Every new failure path has a deterministic, tested alert. Exact codes are
implementation-fixed; the contract is determinism + no secret leakage (RFC 013):

| Condition | Alert (illustrative) |
|---|---|
| No acceptable key_share under no-HRR | `handshake_failure` |
| Duplicate key_share group | `illegal_parameter` |
| Malformed P-256 point shape | `illegal_parameter` (or `decode_error` for framing) |
| Group present in key_share but omitted from supported_groups | `illegal_parameter` |
| Provider rejects point during ECDHE | `handshake_failure` |
| Selected group disallowed by endpoint policy | not reachable — selection never offers it |

The last row is a deliberate non-event: the gate makes a disallowed group unselectable, so
there is no "selected-but-disallowed" runtime state to alert on (that is what §5.1 proves).

### 4.9 Safe negotiation tracing (Amendment 11)

Because this RFC changes negotiation, add opt-in, redaction-safe trace fields (RFC 020 /
RFC 018 classification): configured endpoint named groups; client key_share groups (group
ids only); selected group; and the rejection-reason **category**. Never log raw key_share
bytes or full ClientHello blobs by default — group ids and category only.

## 5. Proof obligations (`Kroopt/Proofs/Handshake.lean`)

### 5.1 Selection authorization

Add, over `step`:

```text
group_selection_authorized :
  if step selects group g for ECDHE (emits ecdheX25519/ecdheP256), then
    g ∈ clientKeyShareGroups (from the processed ClientHello) ∧
    g ∈ endpointAllowedGroups (from policyView)
```

The provider-capability conjunct (`g ∈ providerCapabilities.groups`) is **not** a core
theorem; it follows transitively from the config-validation invariant `endpointAllowed ⊆
providerCaps` (§4.2, established once at startup, outside the verified core). This keeps the
core provider-agnostic — crypto remains an action, `State` carries no capability object —
consistent with RFC 002/008.

### 5.2 Crypto-op consistency (Amendment 7)

`group_selection_authorized` constrains `selectedGroup`, but not the crypto op actually
emitted. Add a lemma family so the implementation cannot record the right group while
emitting the wrong ECDHE op:

```text
ecdhe_op_matches_selected_group :
  if step emits CryptoOp.ecdheX25519, then selectedGroup = x25519
  if step emits CryptoOp.ecdheP256,   then selectedGroup = secp256r1

no_disallowed_group_crypto_op :
  if g ∉ endpointAllowedGroups, then step never emits an ECDHE CryptoOp for g
```

`no_disallowed_group_crypto_op` is the operational form of the §4.8 non-event: a disallowed
group reaches neither `selectedGroup` nor a crypto op.

## 6. Proof/runtime correspondence impact

This is the only stage that touches the verified zone, and it is the main implementation
cost:

- The ClientHello→core boundary changes: the parser returns a *list* of offered shares
  instead of one pre-selected share; the core's negotiation input/state carries the
  candidate set so the §5 theorem is stateable.
- `policyView` carries `endpointAllowed` groups.
- Existing handshake proofs are re-established for the new selection shape (the selection is
  still deterministic; the proofs should extend, not break — selection becomes a total
  function of (offered, allowed) with a fixed preference).
- No change to the no-early-plaintext, nonce/epoch, transcript, or action-discipline
  theorems is expected; the change is localised to negotiation.

## 7. Migration

- Every `EndpointConfig` construction site (default builder, fixtures, the separate
  `kroopt-iotakt` driver configs, tests) must set `namedGroups`. Default `[.x25519,
  .secp256r1]`; the x25519-only preset where a hardened profile is intended.
- Because empty is now an error, there is no silent default — the default builder must set
  the non-empty default explicitly.

## 8. Tests and acceptance criteria

Config validation:

1. `configRejectsUnsupportedGroup` — endpoint `[secp256r1]`, provider `[x25519]` →
   `.unsupportedGroup`.
2. `configRejectsEmptyGroupPolicy` — endpoint `namedGroups = []` → `.emptyGroupPolicy`.
3. `configRejectsDuplicateNamedGroups` — endpoint `[x25519, x25519]` →
   `.duplicateNamedGroup` (Amendment 1).
4. `bothGroupsConfigAccepted` — endpoint `[x25519, secp256r1]`, provider both → ok.
5. `providerX25519OnlyEndpointBothRejectedAtConfig` — the **default** endpoint
   `[x25519, secp256r1]` against a provider lacking P-256 → fails at startup with
   `.unsupportedGroup`, proving endpoint-policy ⊆ providerCaps is load-bearing
   (Amendment 8).

Selection (core/`step`):

6. `x25519OnlyEndpointRejectsP256OnlyClientHello` — endpoint `[x25519]`, client offers only
   a secp256r1 key_share → handshake fails (no HRR), no `ecdheP256`, no plaintext.
7. `p256OnlyClientWithBothAllowedSelectsP256` — endpoint `[x25519, secp256r1]`, client
   offers only secp256r1 → `connected`, `selectedGroup = secp256r1` (present from Stage 1;
   re-homed under the gate).
8. `bothOfferedPrefersX25519` — client offers both shares → `selectedGroup = x25519`.
9. `clientOffersUnsupportedPlusP256SelectsP256` — client offers an unknown group + a
   secp256r1 key_share, endpoint allows secp256r1 → selects secp256r1.

Duplicate / consistency (parse + negotiation):

10. `duplicateKeyShareGroupRejected`, `duplicateX25519KeyShareRejected`,
    `duplicateP256KeyShareRejected` — duplicate key_share group → malformed (Amendment 4).
11. `keyShareGroupMissingFromSupportedGroupsRejected`,
    `supportedGroupsWithoutKeyShareFailsNoHRR` — supported_groups/key_share consistency
    (Amendment 5).

P-256 point validation (Amendment 6):

12. `p256BadPrefixRejected`, `p256BadLengthRejected`, `p256ProviderRejectsInvalidPoint`
    (65-byte, `0x04`-prefixed, off-curve → provider `none` → fatal failure, no
    selected-group success).

Gate-not-bypassed (fake provider):

13. Provider `[x25519]`, endpoint `[x25519]`, client offers only secp256r1 → config passes
    but the handshake fails before any `ecdheP256` op (selection finds no allowed candidate).

Alerts (Amendment 10):

14. `alertMappingDeterministic` — each §4.8 failure condition yields its mapped, fatal,
    non-leaking alert, reproducibly.

Tracing (Amendment 11):

15. `traceRedactsKeyShareBytes` — the negotiation trace exposes group ids, selected group,
    and rejection category, and never raw key_share bytes or the ClientHello blob.

Interop (when live):

16. The 0.76.0-dev forced `-groups P-256` runs continue to pass on a both-allowed listener;
    add an x25519-only-listener run that *rejects* a `-groups P-256` client.

Proof:

17. `group_selection_authorized`, `ecdhe_op_matches_selected_group`, and
    `no_disallowed_group_crypto_op` build clean (no `sorry`/`axiom`), within the existing
    axiom allowlist; gates (`check-axioms.sh`) green.

## 9. Documentation

- `crypto-ffi-contract.md`, `handshake.md`: state the three-layer model and the canonical
  selection rule: *"Negotiated groups are not inferred from parser reachability; they are
  the intersection of provider capability, endpoint policy, and client key_share, ordered by
  server preference."*
- Document the §4.8 alert mapping and the §4.9 redaction-safe trace fields.
- Trust/test matrix: group selection authorization and crypto-op consistency move to
  **PROVEN**; the hash dimension is **derived-and-enforced** (validated against provider
  capability), not informational.

## 10. Non-goals

- Per-endpoint *preference* ordering (fixed core preference here).
- HelloRetryRequest (still out of scope; selection requires a key_share).
- Additional groups beyond x25519 / secp256r1 (x448, ffdhe*, etc. — future).
- Changing the signature-scheme model (already gated and tested).

## 11. References

- `handoff/REVIEW-secp256r1-capability-gap.md`; architect Option-C and default-policy
  rulings.
- RFC 8446 §4.2.7–§4.2.8 (supported_groups / key_share), §9.1 (mandatory secp256r1,
  recommended X25519).
- RFCs 008 §3/§7/§9, 034 §2, 006, 002, 005.
- Code anchors: `Provider.lean:56/65/86/124`, `ConfigCheck.lean:23/33`, `Config.lean:45`,
  `Parse/Handshake.lean:140`, `Core/Handshake.lean:195`.

## 12. Resolved questions (were open in rev-1)

1. **Hash dimension — resolved: derive-and-enforce** (§4.4). `hashAlgorithms` is derived
   from the configured suites and validated against provider capability; it is not left as
   an informational field. (Removal remains the documented alternative only if re-decided.)
2. **`supported_groups` vs `key_share` — resolved** (§4.6). Selection is key_share-driven
   (no HRR); a key_share group omitted from a present `supported_groups`, or a duplicate
   key_share group, is rejected as illegal/malformed. No longer an open question.

## 13. Closure note (post-review, 0.82.0-dev)

Three closure questions were raised at implementation and decided by architect review; the
RFC remained closed and the decisions landed as 0.82.0-dev hardening:

1. **Invalid peer ECDHE point alert (§4.8).** The §4.8 table's "provider rejects point →
   `handshake_failure`" row is superseded: a peer key_share that passes wire-shape parsing
   but is rejected by the provider (off-curve / point at infinity) is attacker input, not a
   server fault, so it is a typed `CryptoError.peerInvalidKeyShare` → **`illegal_parameter`**.
   A genuine provider/shim fault stays `internal_error`; "no acceptable group / no acceptable
   key_share" stays `handshake_failure`. Verified end-to-end (off-curve point → provider
   classifies `peerInvalidKeyShare` → core maps `illegal_parameter`).
2. **`namedGroups` ordering.** Confirmed an **unordered allow-list**; server preference is
   fixed by `Core.groupPreference` (x25519 before secp256r1). Documented; not configurable
   order. Per-endpoint ranking would be a separate field in a future RFC.
3. **Defensive unreachable arms.** The `.failed`/`.verifyFailed` arms in
   `handshakeOnGatingResult` are marked defensively-unreachable (the sole caller consumes both
   fatally first); fatalizing them is a deferred hygiene follow-up (avoids proof churn in the
   no-emit / no-accept theorems).
