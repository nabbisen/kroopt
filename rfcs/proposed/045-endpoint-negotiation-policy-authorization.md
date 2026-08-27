# RFC 045 — Endpoint Negotiation Policy Authorization

**Project.** kroopt

**Status.** Proposed — detailed design awaiting architecture review

**Type.** Blocking correctness/security fix

**Target milestone.** AR1; provisional release `0.128.0`

**Requires completion of.** [RFC 011](../done/011-sni-alpn-configuration-model.md) (endpoint config),
[RFC 034](../done/034-provider-capability-honesty-and-entropy.md) (capability honesty),
[RFC 039](../done/039-named-group-policy-and-enforcement.md) (the three-layer authorization model), and
[RFC 046](../done/046-strict-clienthello-and-extension-framing.md) (exact ClientHello framing)

**Coordinates with.** [RFC 048](048-validated-construction-and-protected-epoch-fail-closed.md), which will
make the validated config/provider construction precondition unforgeable and remove protected-epoch
fallbacks

**Touches.** `Kroopt/Core/{Config,Handshake,State}.lean`, `Kroopt/Parse/Handshake.lean`,
`Kroopt/Crypto/ConfigCheck.lean`, `Kroopt/Proofs/Handshake.lean`, negotiation/replay/interop tests,
the theorem inventory, trust matrix, handshake architecture, and changelog

**Requires completion of (added rev-3).** [RFC 056](056-provider-capability-runtime-honesty.md) — the
advertised AES-GCM capability must be truthful before this RFC promotes AES-GCM to the preferred suite.

**Revision.** rev-3 applies the architecture review recorded at
`.git-exclude/reviewed/014-rfc045-ar1-design-architecture-review.md`: the preference order is settled by
human-owner ruling (§5.2), the parser/core error precedence is scoped (§4.2, §5.3), the provider-composition
chain gains its missing bridge lemma (§10.3), route-miss gains its own internal category (§5.3), and the
RFC 056 dependency is recorded (§13). rev-2 expanded the remediation-schedule outline into the
implementation contract. Slice 1 is authorized at rev-3; Slice 2 additionally requires RFC 056.

---

## 1. Finding and current behavior

Architecture review B1 found that the endpoint cipher allow-list is not authoritative:

1. the exact-framing parser reads the ClientHello cipher-suite vector;
2. `Kroopt.Parse.selectSuite` chooses the first recognized suite in client order;
3. `ValidClientHello.selectedSuite` carries that policy decision across the parser/core boundary;
4. `Core.onClientHello` resolves SNI only later and records the parser-selected suite without checking
   `EndpointConfig.cipherSuites`.

An endpoint restricted to one suite can therefore negotiate a different suite if the client lists that
suite first. Parser reachability, rather than the resolved endpoint's policy, currently authorizes the
choice. This RFC closes B1 only. It does not close the RFC 048 validated-construction/protected-flight
finding or the RFC 049 record-phase finding, and it does not make kroopt production-ready.

## 2. Normative authority model

Cipher negotiation uses the same three distinct layers already accepted for named groups in RFC 039:

| Layer | Question | Authority |
|---|---|---|
| Client offer | What may this peer negotiate? | recognized cipher-suite entries from this exact ClientHello |
| Endpoint policy | What may this SNI-selected endpoint negotiate? | `EndpointConfig.cipherSuites`, interpreted as an unordered allow-set |
| Provider capability | What can this configured binary perform? | startup validation of every endpoint policy against `CryptoCapabilities.suites` and required hashes |
| Server preference | Which authorized overlap wins? | the one core-owned `cipherSuitePreference` list |

The parser reports offer facts; it never selects a suite. The core resolves the endpoint, intersects client
offers with that endpoint's allow-set, and chooses the first overlap in the fixed server preference.
Provider capabilities are deliberately not threaded through every core transition: startup validation
establishes endpoint policy ⊆ provider capability, and the core establishes selected suite ∈ endpoint
policy. Their composition establishes provider support under the validated-startup precondition.

That final qualification is important. Until RFC 048 seals public construction, provider support is a
theorem/precondition about states created through the documented validated startup path, not an
unconditional statement about arbitrary publicly forgeable `State` values. RFC 045 must not claim B4 is
closed.

**Divergence from the original finding (rev-3).** The architecture review that raised B1 required selection
to be intersected with endpoint policy **and provider capability**. This RFC deliberately keeps capability
out of core selection, composing it from startup validation instead — the pattern already accepted and
implemented for named groups in RFC 039. The divergence is recorded rather than silent, and it has a
consequence: the provider leg of B1's authorization rests on a precondition this RFC calls forgeable until
RFC 048 lands. B1 closure on RFC 045 alone is therefore **conditional**; see §14.

## 3. Goals and non-goals

### 3.1 Goals

1. Replace the parser-selected suite with bounded, recognized client-offer facts.
2. Resolve SNI exactly once before any suite decision.
3. Make `EndpointConfig.cipherSuites` authoritative for the resolved endpoint.
4. Make suite preference deterministic, server-owned, and independent of client/endpoint list ordering.
5. Fail a no-overlap negotiation before random, ServerHello, key-schedule, or plaintext output.
6. Prove client-offer and endpoint-policy authorization and connect it to startup provider validation.
7. Show that the selected suite consistently drives transcript hashing, ServerHello, key schedule, record
   metadata, and crypto actions on successful descendants of `onClientHello`.
8. Add safe diagnostic facts and a complete SNI/policy/order/mismatch regression matrix.

### 3.2 Non-goals

- adding suites, changing crypto primitives/providers, or claiming browser-grade breadth (RFC 035);
- per-endpoint preference ordering; `cipherSuites` remains an allow-list;
- retrying another suite after ServerHello or provider failure;
- redesigning ALPN, signature, or group preference;
- sealing validated constructors or removing every forged-state/default fallback (RFC 048);
- redesigning public alert projection or adding HelloRetryRequest;
- closing AR1, production readiness, or stable/v1 readiness.

## 4. Parser/core boundary

### 4.1 `ValidClientHello` carries facts

Replace:

```lean
selectedSuite : CipherSuite
```

with:

```lean
/-- Recognized cipher suites from the exact, structurally valid ClientHello vector,
    retained in client order. Unknown and GREASE ids are omitted. -/
offeredSuites : List CipherSuite
```

The raw cipher vector remains bounded by RFC 046's exact non-empty/even `uint16` framing and the enclosing
ClientHello limit. `offeredSuites` therefore needs no second independent runtime budget. Recognized entries
preserve client order and duplicates; neither fact affects core selection because membership, not order or
multiplicity, is authoritative. TLS 1.3 does not impose a duplicate-suite rejection, so duplicates are
accepted and treated as one set member.

Unknown and GREASE values are structurally valid offers but are not representable as `CipherSuite`; the
parser skips them while retaining every recognized value. In particular, a well-framed unknown-only or
GREASE-only vector is a successful parse with `offeredSuites = []`. It reaches semantic negotiation and
fails as no overlap, rather than being reclassified as malformed input.

This field replacement is a pre-1.0 source-compatibility break for callers constructing
`ValidClientHello` directly. It is intentional: retaining `selectedSuite` would preserve the authority
confusion. Synthetic callers migrate from `selectedSuite := s` to `offeredSuites := [s]`.

### 4.2 Parser behavior and error boundary

`Kroopt.Parse.selectSuite` is removed. `validateFramedClientHello` performs only:

```lean
let offeredSuites := framed.offeredSuites.filterMap suiteOfU16
```

The following classification is normative:

| Input | Parser result | Core result |
|---|---|---|
| empty/odd/truncated/residual suite vector | existing typed parse error | not reached |
| recognized suites in any order | `ValidClientHello.offeredSuites` in client order | endpoint-authorized selection |
| recognized duplicates | accepted; duplicates retained | membership semantics; no preference effect |
| unknown/GREASE mixed with recognized | accepted; unknown values omitted | select from recognized overlap |
| unknown/GREASE only | accepted with empty recognized list | `unsupportedCipherSuite` / fatal `handshake_failure` |
| no recognized `key_share` group, absent `supported_groups`, or duplicate/malformed recognized share | **retained** parser error `valueOutOfRange` / `illegal_parameter` (`Parse/Handshake.lean:219-236`) | not reached |
| no recognized `signature_algorithms` entry | **retained** parser error `valueOutOfRange` / `illegal_parameter` (`Parse/Handshake.lean:323-324`) | not reached |

This RFC does not weaken RFC 046 framing: structural invalidity remains a parser error. It changes only the
semantic no-supported-suite case from parser `valueOutOfRange` / `illegal_parameter` to core
`unsupportedCipherSuite` / `handshake_failure`.

**Scope of the change (rev-3).** The suite dimension is the *only* one whose recognition failure moves from
the parser to the core. The last two rows above are deliberately unchanged: a ClientHello offering no
recognized key-exchange group or no recognized signature scheme is still rejected by the parser, before any
core negotiation runs. RFC 045's error-precedence guarantee (§5.3, §11.1) therefore ranks **semantic
negotiation failures only** — cases where every dimension parsed successfully but one or more found no
policy overlap. It makes no claim about a ClientHello that fails parser recognition on another dimension;
such input yields `illegal_parameter` regardless of its cipher-suite list. Closing that asymmetry is
deliberately out of scope and belongs with the RFC 049 acceptance-matrix work if it is wanted at all.

## 5. Endpoint policy and fixed selection

### 5.1 Endpoint allow-set

`EndpointConfig.cipherSuites` continues to be non-empty under `validateEndpoint`. It has set semantics:
ordering and duplicates do not change authorization or preference. This RFC does not add a duplicate-policy
configuration error because duplicate entries are semantically harmless, existing configuration may
contain them, and capability derivation already tolerates them. Documentation and tests nevertheless use
canonical duplicate-free lists.

Reordering an endpoint's suite list with the same members must not change negotiation. Per-endpoint ranking,
if later required, needs a separate field and RFC; it must not reinterpret this allow-list.

### 5.2 One preference list

The only cipher preference authority is:

```lean
def cipherSuitePreference : List CipherSuite :=
  [ .aes128GcmSha256
  , .aes256GcmSha384
  , .chacha20Poly1305Sha256 ]
```

The total core selector is:

```lean
def selectCipherSuite (offered allowed : List CipherSuite) : Option CipherSuite :=
  cipherSuitePreference.find? (fun s => offered.contains s && allowed.contains s)
```

The implementation may use an equivalent decidable-membership spelling. It must not consult client or
endpoint order, provider implementation order, enum constructor order, or a default suite.

Adding a new suite appends it by default. Reordering existing suites or inserting ahead of an existing
suite requires a separately accepted RFC, interoperability evidence, and a release-note compatibility
callout. Once ServerHello commits to a suite, any provider failure is fatal; the server never tries a less
preferred suite, avoiding attacker-directed downgrade behavior.

#### Rationale for this order (rev-3)

Because §5.2 locks the order behind a separate-RFC barrier, the choice is recorded here rather than left to
the implementer. Decided by human-owner ruling on the architecture review's decision request.

**Why AES-128-GCM first.** It is the only suite RFC 8446 §9.1 makes mandatory to implement, so it is the
safest universal default. It is also the only preferred candidate this build accelerates in hardware:
`lakefile.lean:165-177` compiles HACL\*'s verified Vale x86_64 AES-GCM assembly with CPUID dispatch, while
ChaCha20-Poly1305 is built from the scalar implementations only (`Hacl_Chacha20Poly1305_32.c`,
`Hacl_Chacha20.c`, `Hacl_Poly1305_32.c` at `lakefile.lean:150-152`) — no `Vec128`/`Vec256` variant is
compiled. Leading with ChaCha20 would put the only non-accelerated suite first on the hardware kroopt
actually targets.

**Alternatives considered and rejected.**

| Alternative | Rejected because |
|---|---|
| ChaCha20 first (rev-2 proposal) | An artifact of which suite was live-tested first, not a decision. Costs measurable throughput on every AES-NI host. |
| AES-256-GCM first (OpenSSL 3.x's default TLS 1.3 order) | AES-128-GCM has strictly broader mandatory support and no meaningful security shortfall at this margin; interop breadth outranks the nominal key-size increase for a default. AES-256 remains selectable and second. |
| Equal-preference for the AES-128/ChaCha20 pair (BoringSSL's approach) | Preserves the client's hardware hint, but reintroduces client influence over a security-relevant negotiated parameter — the precise authority this RFC removes. It also complicates the first-preference theorem (§10.1). |
| Per-endpoint ranking | Out of scope; see §3.2. `cipherSuites` stays an allow-set. |

**Accepted cost.** Clients on hardware without AES acceleration (common on mobile and some ARM devices) now
receive AES-128-GCM rather than ChaCha20 when they offer both and the endpoint allows both. Such a client
that prefers ChaCha20 can no longer obtain it by ordering; an operator who wants ChaCha20 for a given
endpoint must express that as an allow-set. This is a deliberate consequence of server-authoritative
selection, not an oversight.

**Dependency.** This order presumes the advertised AES-GCM capability is truthful on the host.
[RFC 056](056-provider-capability-runtime-honesty.md) establishes that and must land with or before Slice 2;
see §13.

### 5.3 Resolution and transition order

After phase and ClientHello-budget checks, `onClientHello` performs this deterministic order:

1. resolve the endpoint once with canonical SNI;
2. select the cipher suite from `offeredSuites` and that endpoint's `cipherSuites`;
3. select the signature scheme;
4. apply ALPN negotiation/policy;
5. select the named group;
6. atomically record all selected facts, bind the exact ClientHello transcript and selected hash, and only
   then request server randomness.

All later steps reuse this one endpoint and selected suite; they do not call `selectEndpoint` or select a
suite again. This also removes a redundant SNI canonicalization: `onClientHello` currently calls
`selectEndpoint` twice (`Core/Handshake.lean:241` and `:246`), each re-running `ValidatedServerName.ofBytes`,
and the two agree today only because `selectEndpoint` is pure.

**Route miss (rev-3).** If endpoint resolution returns `none`, there is no policy capable of authorizing a
suite. rev-2 mapped this to `ProtocolError.unsupportedCipherSuite`; rev-3 gives it its own internal
category, `ProtocolError.noEndpointForSni`, projecting to the same generic fatal `handshake_failure` through
the existing centralized mapping. The reason is internal consistency: §9 already models `noEndpoint` as a
rejection category distinct from `noPolicyOverlap`, and collapsing the two in the error taxonomy while
separating them in diagnostics would make the trace and the error disagree. `Kroopt.Error` is internal and
the public alert is unchanged, so the added constructor widens no public surface. Cost is one constructor,
one `alertForProtocolError` arm, and one test.

**Precedence scope (rev-3).** Selecting suites before signatures intentionally gives suite mismatch
precedence when both dimensions parse successfully but neither finds policy overlap. It is deterministic,
safe to log as a category, and ensures the B1 authorization gate is crossed before later endpoint-policy
decisions. This precedence ranks **semantic negotiation failures only**; it does not reorder the parser
recognition failures retained in §4.2, which continue to reject earlier with `illegal_parameter`. No raw
SNI, offer bytes, key shares, or certificate material enters the error.

## 6. Provider capability and hash invariant

RFC 039 already implemented the needed derive-and-enforce mechanism:

```lean
requiredCryptoOfServerConfig cfg =
  { suites := union of every endpoint.cipherSuites
    ...
    hashAlgorithms := deriveHashesFromSuites suites }
```

`validateServerConfigCapabilities caps cfg` rejects the first suite absent from `caps.suites` and the first
suite-derived transcript/HKDF hash absent from `caps.hashAlgorithms`. RFC 045 preserves this code and adds
focused evidence rather than introducing a second provider check in the handshake core.

The startup contract for every live connection is:

```text
validateServerConfig cfg generation = ok validated
validateServerConfigCapabilities provider.capabilities cfg = ok
State/TlsConn is constructed from that same cfg, validated value, generation, and provider
```

The last binding remains a documented precondition until RFC 048 makes it opaque and unforgeable. Under
that precondition:

```text
selected ∈ resolvedEndpoint.cipherSuites
resolvedEndpoint.cipherSuites ⊆ provider.capabilities.suites
selected.hashAlg ∈ provider.capabilities.hashAlgorithms
```

No runtime provider mismatch triggers fallback. A genuine provider failure after validated startup follows
the existing fatal crypto-failure path.

## 7. State and downstream consistency

On successful `onClientHello`, the chosen suite is written once to
`State.negotiated.selectedSuite`. The same local `selected` value sets `Transcript.hashAlg`; later
transitions must consume the recorded value to construct:

- the ServerHello cipher-suite field;
- HKDF/transcript operations and hash metadata;
- handshake/application AEAD operation metadata;
- protected record metadata and public suite-aware sizing.

The RFC 045 guarantee is restricted to reachable successful descendants of the authorized ClientHello
transition. It forbids a disallowed suite from reaching state or any emitted crypto/server-flight action on
that path. It does not claim arbitrary forged `State` values are safe; RFC 048 owns removal of public
construction bypasses and protected-epoch `getD` fallbacks.

Implementation must not add a new default suite. Existing downstream defaults are inventoried during the
final review and either shown unreachable from RFC 045's successful transition invariant or assigned to
RFC 048 without overstating RFC 045. Any fallback reachable from the normal validated path is blocking for
RFC 045.

**Named inventory (rev-3).** The inventory starts from three known `selectedSuite.getD` sites, which are
**not** mutually consistent: `Core/Handshake.lean:318` defaults to `.chacha20Poly1305Sha256` when encoding
the ServerHello cipher-suite field, while `:328` (key-schedule start) and `:478` default to
`.aes128GcmSha256`. Were any of these reachable, the ServerHello would advertise a different suite than the
key schedule derives under. Slice 2 must resolve the divergence to a single value and record the
reachability argument for each site rather than carrying the inconsistency into RFC 048 unnamed.

## 8. Failure and output contract

No client/endpoint suite overlap, including an empty recognized offer list, produces:

- terminal handshake state;
- `ProtocolError.unsupportedCipherSuite`;
- fatal `AlertDescription.handshakeFailure` through the existing centralized mapping;
- the standard terminal alert/report action shape only;
- no random request, ServerHello, key-schedule/AEAD operation, application plaintext, or handshake
  plaintext flight.

Malformed suite-vector framing retains RFC 046's parser error and alert projection. Configuration/provider
mismatch fails before listener/connection startup as `CapabilityError.unsupportedSuite` or
`.unsupportedHash`, not as a peer handshake error. Provider failure after selection remains a crypto error
and never causes reselection.

## 9. Redaction-safe negotiation diagnostics

Add a suite-specific opt-in fact type rather than overloading RFC 039's group trace:

```lean
structure CipherSuiteNegotiationTrace where
  endpointSuites    : List CipherSuite
  offeredSuites     : List CipherSuite
  selectedSuite     : Option CipherSuite
  rejectionCategory : Option CipherSuiteRejection

inductive CipherSuiteRejection where
  | noEndpoint
  | noRecognizedOffer
  | noPolicyOverlap
```

Its constructor receives only typed recognized suites and a closed rejection category. Rendering emits
numeric suite ids, the selected id, and category only. The type contains no `ByteArray`, SNI, key share,
certificate, transcript, secret, or free-form attacker-controlled string. This is an opt-in pure diagnostic
view; RFC 045 does not add implicit logging or change the public `TraceEvent` stream.

## 10. Proof obligations

Names may change to fit the proof module, but propositions must not weaken.

### 10.1 Pure selector

- `selectCipherSuite_offered`: selection implies membership in `offered`.
- `selectCipherSuite_allowed`: selection implies membership in `allowed`.
- `selectCipherSuite_authorized`: combines the two memberships.
- `selectCipherSuite_first_preferred`: if `s` is selected, every suite preceding `s` in
  `cipherSuitePreference` fails at least one membership test.
- `selectCipherSuite_client_permutation`: offer-list permutations preserve selection.
- `selectCipherSuite_policy_permutation`: allow-list permutations preserve selection.
- `selectCipherSuite_none_iff`: `none` iff no preference member is both offered and allowed.

The permutation theorems may use a shared membership-equivalence premise rather than importing a broad
permutation library. The proof inventory must state the exact proposition used.

### 10.2 Handshake transition

For a successful `onClientHello s vch wire = ok (s', actions)` that reaches
`requestedServerRandom`:

- `s'.negotiated.selectedSuite = some selected` for one `selected` offered by `vch` and allowed by the
  single resolved endpoint;
- `s'.transcript.hashAlg = selected.hashAlg`;
- the first crypto action is only the bounded random request; no ServerHello/key-schedule action precedes
  authorization;
- a no-overlap result is terminal and its actions contain no random/ServerHello/key-schedule/plaintext
  output.

Downstream correspondence proves or preserves:

- encoded ServerHello suite = recorded selected suite;
- every reachable suite-tagged key-schedule/AEAD action = recorded selected suite;
- every reachable protected-record metadata suite = recorded selected suite;
- therefore no suite outside the resolved endpoint policy reaches those actions from an accepted
  ClientHello.

### 10.3 Provider composition

Add a configuration lemma or documented theorem chain showing that successful capability validation makes
every configured endpoint suite provider-supported and its hash available. Compose it with transition
authorization under the validated-startup precondition. Do not encode provider capabilities into
`selectCipherSuite`, and do not state the composed property for arbitrary forgeable states.

**Required chain (rev-3).** The composition does not close without an explicit bridge. Capability validation
quantifies over `ServerConfig` (`validateServerConfigCapabilities`, `requiredCryptoOfServerConfig` —
`Crypto/ConfigCheck.lean:45-70`), whereas selection resolves against `ValidatedServerConfig`
(`selectEndpoint` — `Core/Config.lean:439-459`). Three named lemmas are therefore obligations of this RFC,
not incidental steps:

1. **Endpoint preservation.** `validateServerConfig cfg gen = ok v` implies the endpoint multiset of `v`
   equals that of `cfg`. True by construction — `validateSniRoutes` copies `r.endpoint` verbatim and
   `defaultEndpoint` is carried through unchanged (`Core/Config.lean:404-437`) — but it must be stated.
2. **Endpoint ⊆ union.** Every endpoint's `cipherSuites` is contained in
   `(requiredCryptoOfServerConfig cfg).suites`.
3. **`dedup` membership preservation.** `x ∈ dedup xs ↔ x ∈ xs` (`Crypto/ConfigCheck.lean:24`), which is
   what carries `selected.hashAlg` through `deriveHashesFromSuites` into `caps.hashAlgorithms`.

With those three, the chain in §6 is elementary and requires no new provider plumbing in the core.

No new axiom or `sorry` is permitted. The theorem inventory and current-security/trust wording distinguish
proved core properties, tested lifted behavior, and the RFC 048 construction assumption.

## 11. Test and interoperability matrix

### 11.1 Pure and synthetic tests

- every supported singleton suite selects only when endpoint-allowed;
- all three overlap selects AES-128-GCM, regardless of client or endpoint order;
- AES-256-GCM beats ChaCha20-Poly1305 when AES-128-GCM is absent from the authorized set;
- ChaCha20-Poly1305 is selected only when neither AES-GCM suite is authorized;
- duplicate client/endpoint entries have no effect;
- disjoint/empty recognized offers return `none`;
- two SNI routes with disjoint suite policies each select only their own suite;
- absent SNI selects only from the configured default endpoint;
- route miss with no default fails before random/server flight;
- suite mismatch wins the specified error precedence over a simultaneous signature/group **policy**
  mismatch — i.e. where every dimension parsed successfully but none found overlap (§4.2 scope);
- no-overlap actions contain only terminal alert/report actions and no plaintext/crypto request;
- trace rendering contains ids/categories only.

### 11.2 Parser/replay tests

- migrate prior parser-level `selectedSuite` assertions to `offeredSuites` fact assertions;
- mixed GREASE/unknown/recognized vectors preserve recognized entries in client order;
- GREASE-only and unknown-only vectors parse, then fail semantically with `handshake_failure` in the live
  path;
- malformed empty/odd/truncated/residual vectors remain parser failures;
- existing captured ClientHello corpus remains accepted or retains its documented rejection class;
- reordering client offers demonstrates fixed server preference, replacing the former client-preference
  expectations.

### 11.3 Capability and downstream consistency

- every endpoint allow-set must be a subset of provider suites at startup;
- AES-256 policy requires SHA-384; SHA-384 omission rejects startup even if AES-256 is advertised;
- ServerHello encoding, transcript hash, key schedule, record metadata, and suite-aware sizing agree for
  each of the three suites;
- a provider failure after selection is fatal and does not attempt another suite.

### 11.4 Live interop

Run the existing OpenSSL/Python/curl blocking and reactor matrix with all three configured suites.

**Retained (already present).** Forced-single-suite OpenSSL cases for ChaCha20, AES-128, and AES-256 exist
today at `scripts/tls-interop.sh:122-124` (blocking) and `:131-133` (reactor). They are retained, but note
what they cannot do: each forces one suite via `-ciphersuites`, so the client offers exactly one and the
case is invariant under any preference order. They are availability evidence, not preference evidence.

**New (rev-3, required).** The existing matrix contains no case that asserts which suite a *multi-offer*
client lands on: `test_python` prints `ss.cipher()[0]` but asserts only on `PYTHON_OK`
(`tls-interop.sh:83`), and `test_curl_http` asserts handshake, body, and close but not the suite. Add:

1. a client offering all three suites against an all-three endpoint, asserting **AES-128-GCM** is negotiated;
2. the same client against an endpoint whose allow-set excludes AES-128-GCM, asserting **AES-256-GCM**;
3. an endpoint allowing one suite while the client offers that suite *after* a disallowed more-preferred
   suite, asserting the allowed suite is negotiated.

Cases 1 and 2 are the actual wire evidence for the §12 behaviour change; without them no live case
distinguishes rev-2's order from rev-3's. Capture command, tool versions, candidate revision, and result in
the final handoff/gate ledger; historical `0.127.0` evidence is regression context only.

## 12. Compatibility decision

This RFC intentionally changes multi-suite negotiation from first-recognized client order to fixed server
order. Under the rev-3 order (§5.2), a client offering ChaCha20 before AES-128-GCM will negotiate
**AES-128-GCM** when both are endpoint-allowed — the reverse of both today's behaviour and rev-2's proposal.
Single-suite clients and endpoints retain their selected suite. Endpoint list order becomes explicitly
non-semantic.

This is acceptable for the provisional pre-1.0 line because every selectable suite is already advertised as
implemented, forced-suite interop is required, and the change closes a security authority defect. The
`0.128.0` changelog/release notes must call it out explicitly, naming AES-128-GCM as the new default
outcome for multi-suite clients. Consumers relying on client-order preference must use endpoint allow-sets
to constrain the result; per-endpoint ranking is not provided.

## 13. Implementation slices and review points

### Slice 1 — offer facts and pure authorization

- replace `ValidClientHello.selectedSuite` with `offeredSuites`;
- remove parser selection while preserving RFC 046 framing classifications;
- add `cipherSuitePreference`, total `selectCipherSuite`, pure authorization/preference proofs;
- migrate focused parser/synthetic fixtures and add order/GREASE/no-overlap tests;
- reshape `Tests/Hardening.lean:71-73` (`negotiatedSuite`), which currently returns `none` both for a
  rejected ClientHello and for no recognized suite. rev-3 makes those distinct outcomes with different
  alerts, so the helper must be split, not merely retyped.

Slice 1 touches parser facts and the pure selector only. It reaches no provider and no live state, so it is
**not** gated on RFC 056.

**Review point:** architecture implementation review of the parser/core authority boundary, pure theorem
statements, classifications, and source-compatibility migration before live state binding.

### Slice 2 — live endpoint binding and consistency

- resolve the endpoint once and bind suite selection before other negotiation dimensions;
- record the authorized suite and transcript hash atomically;
- add failure-action, SNI-route, downstream ServerHello/key-schedule/record correspondence proofs/tests;
- add the redaction-safe suite trace and capability/hash composition evidence;
- update architecture, theorem inventory, trust matrix, security state, changelog, and interop scripts.

**Gated on [RFC 056](056-provider-capability-runtime-honesty.md).** Slice 2 makes AES-128-GCM the negotiated
default. It must not land while the advertised AES-GCM capability can be false on the host; RFC 056 lands
with or before it, in the same `0.128.0` release.

**Proof migration (rev-3).** Restructuring `onClientHello` to resolve the endpoint once and bind the suite
first changes the match tree that several existing proofs case-split on. At minimum
`onClientHello_selectedGroup_allowed` (`Proofs/Handshake.lean:169`), `no_disallowed_group_crypto_op` (`:281`),
`onClientHello_legal` (`:299`), `hs_no_emit_onClientHello` (`:567`), and `hs_no_accept_generic_onClientHello`
(`:828`) require re-proof. Existing theorem names must be preserved; the theorem inventory and RFC 054's
split rule both depend on name stability.

**Maintainability interaction (rev-3).** ROADMAP §0 AR-M prefers RFC 054 splits *before* modifying an
oversized module. Slice 2 modifies the two most concentrated modules in the project —
`Kroopt/Proofs/Handshake.lean` (1,216 lines) and `Kroopt/Core/Handshake.lean` (534), both above the project
rule's 500-ELOC strong-split threshold. **Decision:** proceed without a preceding RFC 054 split. Splitting a
proof module in the same release that restructures the function it proves over compounds two risky changes
and would obscure the re-proof diff. RFC 054 should take these two modules as its first candidates *after*
AR1 closes, when the file shape is stable. This is an implementation-order decision within delegated
authority; it accepts the concentration cost for one release rather than removing it.

**Review point:** final RFC 045 implementation review before lifecycle closeout or release-candidate work.

### Closeout and release candidate

Only after final implementation acceptance may the RFC move to `done/` and B1 be marked closed. The exact
candidate then requires the canonical full-release profile, supported sanitizer lanes, live interop,
release-document checks, a clean exact revision, and a release-candidate architecture review. Publication
evidence is recorded separately after the `0.128.0` tagged workflow; none of these future gates is claimed
by this design.

## 14. Acceptance criteria

1. The parser reports recognized offers and contains no suite-policy selection.
2. A successful selected suite is proved client-offered and allowed by the exactly resolved endpoint.
3. Under the validated-startup precondition, the suite and its hash are provider-supported.
4. Client or endpoint ordering and duplicates cannot change selection when membership is unchanged.
5. Two SNI routes with different suite policies negotiate only their own authorized overlap.
6. No overlap produces the specified fatal alert and no random, server flight, key schedule, or plaintext.
7. The selected suite consistently drives transcript, ServerHello, crypto actions, record metadata, and
   sizing on reachable successful paths.
8. Unknown/GREASE-only input is structurally accepted and semantically rejected without fallback.
9. Proof inventory, trust matrix, current-security state, architecture docs, replay corpus, and live interop
   reflect the exact candidate without claiming RFC 048 or AR1 closure.
10. Slice reviews, final implementation review, and exact-candidate canonical/release review pass before
    `0.128.0` publication.
11. RFC 056 is Implemented in the same release, so the advertised AES-GCM capability is truthful before
    AES-128-GCM becomes the negotiated default.
12. B1 closure is recorded as **conditional on RFC 048** (§2): client-offer and endpoint-policy authorization
    are proved outright, while provider support holds under the validated-startup precondition that RFC 048
    makes unforgeable. Neither this RFC nor its release may describe B1 as unconditionally closed, and
    neither closes AR1, production readiness, or stable/v1.
