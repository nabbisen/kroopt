# Review request — secp256r1 / P-256 ECDHE: advertised-vs-negotiated group mismatch

> **RESOLVED (2026-06-30) — superseded by [RFC 039](../../done/039-named-group-policy-and-enforcement.md)
> (Named-Group Policy and Selection Enforcement, Implemented v0.81.0-dev).** Both the advertise-vs-negotiate
> mismatch and its structural cause are closed:
> - **Advertise (Option B):** `realCapabilities.groups = [.x25519, .secp256r1]` — advertised set matches the
>   negotiable set.
> - **Structural (Option A):** `EndpointConfig.namedGroups` exists; `requiredCryptoOfServerConfig.groups` is
>   sourced from it (no longer `[]`), so `.unsupportedGroup` is reachable and authoritative; the parallel
>   `hashAlgorithms` inertness is fixed (`deriveHashesFromSuites`).
> - **Tests:** `Tests/EndToEnd.lean` `runE2EP256` drives a secp256r1-only ClientHello to `connected`, plus the
>   x25519-only-server rejection case, unknown-group dropping, duplicate, and malformed-point negatives.
> - **Docs:** trust-matrix, proof-assumptions, interop, and theorem-inventory state the true x25519 + P-256 set.
>
> No action remains. The `[Unreleased]` pointer in **Found by** below is historical — the findings shipped in
> v0.81.0-dev. The original problem statement is retained below as the historical record (RFC 000: completed
> design context is not deleted).

**Type.** Review request (problem statement for architect decision; not yet an RFC).
**Status.** Resolved — superseded by RFC 039 (Implemented v0.81.0-dev); see banner above.
**Found by.** 5-dimension audit, 2026-06-14 (see `CHANGELOG.md` `[Unreleased]`).
**Severity.** Low impact today (fails in the *safe* direction), but it leaves an
RFC 034 honesty guarantee only half-implemented and ships an untested negotiation
path. Decision wanted before P-256 is claimed as a supported v0.4 capability.
**Touches.** `Kroopt/Crypto/Provider.lean`, `Kroopt/Crypto/ConfigCheck.lean`,
`Kroopt/Core/Config.lean`, `Kroopt/Parse/Handshake.lean`, `Kroopt/Core/Handshake.lean`,
`Tests/Capabilities.lean`, `Tests/EndToEnd.lean`.

---

## 1. Decision needed

kroopt implements X25519 **and** secp256r1 (P-256) ECDHE, but the two key-exchange
groups are governed by completely different machinery:

- **X25519** is the advertised, intended group.
- **secp256r1** is negotiated by the parser whenever a client offers it, with **no
  capability check, no config switch, and no test** — and the advertised capability
  set (`realCapabilities.groups = [.x25519]`) says it is *not* offered.

So the *negotiable* group set is `{x25519, secp256r1}` while the *advertised* group
set is `{x25519}`. The advertised value is currently inert: nothing reads it to gate
negotiation. We need a decision on how to reconcile advertisement, configuration, and
behaviour for groups. Four options are in §6; the recommendation is in §7.

---

## 2. How the capability model is *supposed* to work (RFC 008 §3, RFC 034 §2)

Config validation is meant to reject, at listener startup, any configuration that
requires crypto the provider cannot perform — deterministically, with a typed error,
never a silent runtime downgrade. The mechanism:

```
ServerConfig ──requiredCryptoOfServerConfig──▶ RequiredCrypto ──validateCapabilities──▶ Except CapabilityError Unit
                                                  (caps from the provider)
```

`RequiredCrypto` and `CryptoCapabilities` each carry four dimensions — `suites`,
`groups`, `signatureSchemes`, `hashAlgorithms` — and `validateCapabilities`
(`Provider.lean:86`) checks all four with `firstMissing`:

```lean
firstMissing req.suites            caps.suites            .unsupportedSuite
firstMissing req.groups            caps.groups            .unsupportedGroup
firstMissing req.signatureSchemes  caps.signatureSchemes  .unsupportedSignatureScheme
firstMissing req.hashAlgorithms    caps.hashAlgorithms    .unsupportedHash
```

This works correctly for **suites** and **signature schemes**, and it is *tested*:
`Tests/Capabilities.lean` asserts `realRejectsEcdsa` — an ECDSA server config is
rejected against `realCapabilities` (`signatureSchemes = [.ed25519]`) with
`.unsupportedSignatureScheme`. That is the model functioning as designed.

---

## 3. Where it breaks for groups (and hashes)

Two facts make the `groups` dimension inert.

**(a) The required-group list is hardcoded empty.** `requiredCryptoOfServerConfig`
(`Kroopt/Crypto/ConfigCheck.lean:23`) builds `RequiredCrypto` from the endpoints, but
only `suites` and `signatureSchemes` are sourced from config — `groups` and
`hashAlgorithms` are literally `[]`:

```lean
def requiredCryptoOfServerConfig (cfg : ServerConfig) : RequiredCrypto :=
  let eps := cfg.defaultEndpoint.toList ++ cfg.sniRoutes.map (·.endpoint)
  { suites           := eps.foldr (fun e acc => e.cipherSuites ++ acc) []
    groups           := []          -- ← always empty
    signatureSchemes := eps.foldr (fun e acc => e.signatureSchemes ++ acc) []
    hashAlgorithms   := [] }         -- ← always empty
```

Because `firstMissing [] caps.groups _` always returns `.ok ()`, the
`.unsupportedGroup` check **can never fire**. `CryptoCapabilities.groups` has exactly
one consumer in the whole codebase — that unreachable line — so it is a declarative
field that nothing functionally reads. (`hashAlgorithms` is in the same state; today
that is masked because the suite already pins the hash, e.g. `aes256GcmSha384`.)

**(b) `EndpointConfig` has no group field.** `EndpointConfig`
(`Kroopt/Core/Config.lean:45`) carries `cipherSuites` and `signatureSchemes` but no
`groups`/`namedGroups`. A server config therefore *cannot express* a group policy
even if we wanted to populate `req.groups`.

**(c) Group selection is hardcoded in the parser.** The actual choice happens in
`Kroopt/Parse/Handshake.lean:140`, purely from the client `key_share`, consulting
neither `caps.groups` nor any config field:

```lean
-- x25519 (0x001d, 32-byte share) preferred; else secp256r1 (0x0017, 65-byte point)
x25519.orElse (fun _ => p256)
```

and `Kroopt/Core/Handshake.lean:195` emits the matching op:

```lean
| some .secp256r1 => CryptoOp.ecdheP256 peer
| _               => CryptoOp.ecdheX25519 peer
```

---

## 4. Consequence

A client that offers a secp256r1 `key_share` and **no** x25519 share completes a real
P-256 ECDHE handshake, even though `realCapabilities` advertises x25519-only. The
advertised group set is not authoritative.

This errs in the *safe* direction: kroopt genuinely can perform P-256, so it is
**under-advertising**, not over-claiming — there is no security regression today. But:

- RFC 034 §2's promise ("reject configs requiring crypto the provider cannot perform,
  never silently negotiate outside the advertised profile") is only realised for two
  of four dimensions. For groups it is vacuous.
- The advertised `groups` field is misleading to anyone reading `realCapabilities` as
  the source of truth (it already misled the audit and the docs — see §5).
- Group policy is not configurable the way suites/schemes are (no per-endpoint group
  list), so there is currently no supported way to *disable* secp256r1 if a deployment
  wanted x25519-only.

Contrast with ECDSA/RSA: those are deliberately **rejected-and-tested** at config
validation, because the scheme dimension is wired. The group dimension is the
odd one out.

---

## 5. Test and documentation status

- **No negotiation-level test** drives a secp256r1 ClientHello through to a connected
  P-256 handshake. The only `ecdheP256` reference in `Tests/` is a fake-provider
  *response* branch (`Tests/EndToEnd.lean:58`, returns a dummy 65-byte point), not a
  scenario that selects secp256r1. The P-256 primitives themselves (point derivation,
  ECDH) are unit-tested in the HACL\* suite; the *negotiation path* is not.
- **Docs already drifted** on this: `crypto-ffi-contract.md` claimed the provider
  "never claims P-256" — which is *true of the advertised set* but masks that the
  parser negotiates it anyway. (The audit corrected the false AES-GCM/SHA-384 claims
  in that file and added a pointer to this issue.)

---

## 6. Options

### Option A — Make capabilities authoritative (gate negotiation on the allowed set)
Thread an allowed-group set into group selection and reject out-of-set groups.
- Add a `groups`/`namedGroups` field to `EndpointConfig` (or a provider-global group
  policy), source `req.groups` from it in `requiredCryptoOfServerConfig`, and have the
  ClientHello group selection reject a `key_share` group not in the allowed set
  (failing cleanly, consistent with the no-HRR rule — a client with no acceptable
  share already fails).
- **Pro:** capabilities become the single source of truth; honesty holds for all
  dimensions; symmetric with suites/schemes; deployments can choose x25519-only.
- **Con:** most plumbing; the allowed set must reach the **pure parser/core**, so it
  touches the verified zone and likely needs a new proof obligation ("negotiation only
  selects an allowed group", parallel to suite selection). Requires deciding whether
  group policy is per-endpoint (like suites) or provider-global.

### Option B — Advertise secp256r1 and add a test (make advertisement match behaviour)
Keep the parser as-is; set `realCapabilities.groups := [.x25519, .secp256r1]` and add
the missing negotiation test.
- **Pro:** cheap, low-risk, no core/proof changes; immediately removes the dishonesty
  and the test gap; matches the requirements' "P-256 recommended (v0.4)" intent.
- **Con:** does not fix the underlying inertness — `req.groups` stays `[]`, the
  `.unsupportedGroup` check stays unreachable, and there is still no way to *restrict*
  groups. It aligns the advertised value with behaviour without making the value
  load-bearing.

### Option C — Both (B now, A as the structural follow-up)
Advertise + test immediately (B), then wire the gate (A) so the field becomes
authoritative.
- **Pro:** principled end state; unblocks the v0.4 P-256 claim now while scheduling the
  real fix.
- **Con:** two changes; the proof work in A still has to happen eventually.

### Option D — Restrict to x25519 (drop secp256r1 from the parser)
Make the parser reject secp256r1, leaving x25519 the only group.
- **Pro:** smallest negotiable surface; trivially honest; no P-256 path to test.
- **Con:** contradicts the requirements (§9.2 "X25519 required; **P-256 recommended
  (v0.4)**") and the v0.4 roadmap ("P-256/AES-256-GCM/SHA-384 breadth"). Only sensible
  if P-256 is being *deferred* past v0.4, in which case the secp256r1 parser/handshake
  code should be removed or feature-gated to avoid dead, reachable-only-by-accident
  negotiation.

---

## 7. Recommendation

**Option C**, sequenced as **B first, A second.**

B is a few lines (`realCapabilities.groups`, plus a deterministic negotiation test and
ideally one OpenSSL interop run forcing `-groups P-256`) and removes the immediate
honesty + coverage gaps at near-zero risk. It is also the correct value for a build
that intends to support P-256 per the v0.4 roadmap.

A is the structural fix that makes `CryptoCapabilities.groups` mean something and
restores the RFC 034 §2 guarantee across all four dimensions; it belongs in the same
RFC that decides whether group policy is per-endpoint or provider-global, and it
should carry a proof obligation that negotiation never selects a group outside the
allowed set. The same RFC should fix the parallel `hashAlgorithms := []` inertness (or
consciously document that the hash is always implied by the suite and drop the
separate hash dimension).

Option D only if the team decides to **defer P-256 entirely**, in which case the
secp256r1 parser/handshake branches should be removed or gated rather than left
reachable.

---

## 8. Acceptance criteria (whichever option)

- The advertised `realCapabilities.groups` and the set of groups the running handshake
  will negotiate are identical (no advertise-vs-behave gap).
- A negotiation-level test exists for every advertised group: a ClientHello offering
  only that group's `key_share` reaches `connected` (deterministic, fake provider;
  plus interop where the wire is exercised).
- For Option A/C: a config can express its allowed groups; a config requiring an
  unsupported group is rejected at validation with `.unsupportedGroup`; and the core
  carries a proof that no out-of-set group is ever selected.
- Documentation (`crypto-ffi-contract.md`, `handshake.md`) states the true group set.

---

## 9. References

- Code: `Provider.lean:56` (`RequiredCrypto`), `:65` (`CapabilityError`), `:86`
  (`validateCapabilities`), `:124` (`realCapabilities`); `ConfigCheck.lean:23`
  (`requiredCryptoOfServerConfig`), `:33` (`validateServerConfigCapabilities`);
  `Config.lean:45` (`EndpointConfig`); `Parse/Handshake.lean:140` (group selection);
  `Core/Handshake.lean:195` (`ecdheP256`/`ecdheX25519`); `Tests/Capabilities.lean`
  (`realRejectsEcdsa`); `Tests/EndToEnd.lean:58` (fake `ecdheP256` response).
- RFCs: 008 §3/§7/§9 (capability validation, no silent downgrade), 034 §2 (capability
  honesty / fail-closed), 006 (handshake, no HRR — requires an acceptable initial
  `key_share`).
- Requirements §9.2 ("X25519 required; P-256 recommended (v0.4)"); Roadmap v0.4
  ("P-256/AES-256-GCM/SHA-384 breadth").
