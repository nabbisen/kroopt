import Kroopt.Core.Config

/-!
# Kroopt.Proofs.Config

Structural proofs over the configuration selection model (RFC 011 §8, RFC 012).
The headline is `negotiateAlpn_offered_and_allowed`: ALPN negotiation never
selects a protocol the client did not offer and the endpoint did not allow — the
core security property of §8. Alongside it: SNI default fallback, ambiguous-config
rejection, generation stamping, signature-scheme soundness, and cert/key
mismatch rejection.
-/

namespace Kroopt.Core.Proofs

open Kroopt Kroopt.Core

/-- Byte equality is reflexive on a list. -/
theorem alpn_self_eq (a : AlpnProtocol) : AlpnProtocol.eq a a = true := by
  unfold AlpnProtocol.eq baEq
  exact beq_self_eq_true _

/-- An element actually present in a list is a member by byte-equality. -/
theorem alpnMem_of_mem {a : AlpnProtocol} {xs : List AlpnProtocol} (h : a ∈ xs) :
    alpnMem a xs = true := by
  unfold alpnMem
  exact List.any_eq_true.mpr ⟨a, h, alpn_self_eq a⟩

/-- **ALPN safety (RFC 011 §8).** Any protocol kroopt selects was both offered by the
client and allowed by the endpoint — kroopt never selects an unoffered protocol. Stated
over the `AlpnDecision.selected` outcome (a `.notOffered`/`.noOverlap` result selects
nothing). -/
theorem negotiateAlpn_offered_and_allowed
    (preference : AlpnPreference) (offered : Option (List AlpnProtocol)) (allowed : List AlpnProtocol)
    (p : AlpnProtocol)
    (h : negotiateAlpn preference offered allowed = .selected p) :
    (∃ os, offered = some os ∧ alpnMem p os = true) ∧ alpnMem p allowed = true := by
  cases offered with
  | none => simp only [negotiateAlpn, reduceCtorEq] at h
  | some os =>
    cases preference with
    | server =>
        simp only [negotiateAlpn] at h
        split at h
        · rename_i p' hpick
          simp only [AlpnDecision.selected.injEq] at h
          subst h
          have hp := List.find?_some hpick
          have hm := List.mem_of_find?_eq_some hpick
          exact ⟨⟨os, rfl, hp⟩, alpnMem_of_mem hm⟩
        · simp only [reduceCtorEq] at h
    | client =>
        simp only [negotiateAlpn] at h
        split at h
        · rename_i p' hpick
          simp only [AlpnDecision.selected.injEq] at h
          subst h
          have hp := List.find?_some hpick
          have hm := List.mem_of_find?_eq_some hpick
          exact ⟨⟨os, rfl, alpnMem_of_mem hm⟩, hp⟩
        · simp only [reduceCtorEq] at h

/-- **ALPN absence (RFC 7301 §3.2).** A client that sends no ALPN extension yields `.notOffered` under
either preference, so the handshake proceeds with no protocol selected (it never reaches the `.noOverlap`
fact the caller may turn into a fatal `no_application_protocol`). -/
theorem negotiateAlpn_absent_notOffered (preference : AlpnPreference) (allowed : List AlpnProtocol) :
    negotiateAlpn preference none allowed = .notOffered := rfl

/-- **No-overlap detection under server order (RFC 7301 §3.2, RFC 011 §5).** A non-empty offered list
with no protocol the endpoint also allows yields `.noOverlap` under `.server` preference (used by
`serverPreference` and the strict `requireOverlap` via `mode.preference`). The witness of "no overlap" is
`allowed.find? (· ∈ offered) = none`. The strict-vs-lenient *consequence* is the caller's policy. -/
theorem negotiateAlpn_server_noOverlap
    (offered allowed : List AlpnProtocol)
    (h : allowed.find? (fun a => alpnMem a offered) = none) :
    negotiateAlpn .server (some offered) allowed = .noOverlap := by
  simp only [negotiateAlpn, h]

/-- **No-overlap detection under client order.** The symmetric witness for `.client` preference (used by
`clientPreferenceWithinAllowed`): `offered.find? (· ∈ allowed) = none` ⇒ `.noOverlap`. -/
theorem negotiateAlpn_client_noOverlap
    (offered allowed : List AlpnProtocol)
    (h : offered.find? (fun a => alpnMem a allowed) = none) :
    negotiateAlpn .client (some offered) allowed = .noOverlap := by
  simp only [negotiateAlpn, h]

/-- **`.notOffered` means *only* absence (ALPN overload removed).** The conflation is gone: a `.notOffered`
result can arise *only* from a client that sent no ALPN extension, never from an offered-but-non-overlapping
list (that is now `.noOverlap`). -/
theorem negotiateAlpn_notOffered_iff_absent
    (preference : AlpnPreference) (offered : Option (List AlpnProtocol)) (allowed : List AlpnProtocol)
    (h : negotiateAlpn preference offered allowed = .notOffered) : offered = none := by
  cases offered with
  | none => rfl
  | some os =>
    simp only [negotiateAlpn] at h
    split at h <;> simp only [reduceCtorEq] at h

/-- **`.noOverlap` is always a real offer.** A no-overlap fact implies the client did offer ALPN. -/
theorem negotiateAlpn_noOverlap_offered
    (preference : AlpnPreference) (offered : Option (List AlpnProtocol)) (allowed : List AlpnProtocol)
    (h : negotiateAlpn preference offered allowed = .noOverlap) : ∃ os, offered = some os := by
  cases offered with
  | none => simp only [negotiateAlpn, reduceCtorEq] at h
  | some os => exact ⟨os, rfl⟩

/-- **No-overlap is preference-independent (doc/proof parity).** When neither directional scan finds a
match — i.e. the offered and allowed sets are disjoint — `negotiateAlpn` reports the `.noOverlap` fact under
**either** preference. Combined with the total `mode.preference` mapping, this is the proof behind the docs'
mode-independence claim: only the *consequence* (`mode.noOverlapPolicy`) varies. -/
theorem negotiateAlpn_noOverlap_anyPreference
    (preference : AlpnPreference) (offered allowed : List AlpnProtocol)
    (hs : allowed.find? (fun a => alpnMem a offered) = none)
    (hc : offered.find? (fun a => alpnMem a allowed) = none) :
    negotiateAlpn preference (some offered) allowed = .noOverlap := by
  cases preference <;> simp only [negotiateAlpn, hs, hc]

/-- Absent SNI selects the default endpoint (RFC 011 §4). -/
theorem selectEndpoint_none_uses_default (cfg : ValidatedServerConfig) :
    selectEndpoint cfg none = cfg.defaultEndpoint := by
  unfold selectEndpoint
  rfl

/-- An ambiguous route table is rejected deterministically (RFC 011 §7). -/
theorem validateServerConfig_rejects_ambiguous
    (cfg : ServerConfig) (gen : ConfigGeneration)
    (h : hasAmbiguousRoutes cfg.sniRoutes = true) :
    validateServerConfig cfg gen = .error .ambiguousSni := by
  unfold validateServerConfig
  rw [if_pos h]

/-- A validated config carries the generation it was stamped with (RFC 011 §6):
this is what lets in-flight connections keep a consistent view across reload. -/
theorem validateServerConfig_preserves_generation
    (cfg : ServerConfig) (gen : ConfigGeneration) (vcfg : ValidatedServerConfig)
    (h : validateServerConfig cfg gen = .ok vcfg) :
    vcfg.generation = gen := by
  unfold validateServerConfig at h
  split at h
  · exact absurd h (by simp)
  · split at h
    · exact absurd h (by simp)
    · split at h
      · exact absurd h (by simp)
      · split at h
        · split at h
          · exact absurd h (by simp)
          · simp only [Except.ok.injEq] at h; rw [← h]
        · simp only [Except.ok.injEq] at h; rw [← h]

/-- **Signature-scheme soundness (RFC 012 §6).** A selected CertificateVerify
scheme was offered by the client, configured by the endpoint, and is producible
by the leaf key — never a downgrade to an unoffered/incompatible scheme. -/
theorem selectSignatureScheme_sound
    (client endpoint : List SignatureScheme) (leaf : PublicKeyKind) (s : SignatureScheme)
    (h : selectSignatureScheme client endpoint leaf = some s) :
    s ∈ client ∧ endpoint.contains s = true ∧ (schemesForKey leaf).contains s = true := by
  unfold selectSignatureScheme at h
  simp only [] at h
  have hp := List.find?_some h
  have hmem := List.mem_of_find?_eq_some h
  rw [Bool.and_eq_true] at hp
  exact ⟨hmem, hp.1, hp.2⟩

/-- A cert/key pair whose kinds disagree is rejected at config lint
(RFC 012 §5) — provided the chain is non-empty and within size bounds. -/
theorem validateEndpointCertKey_rejects_mismatch
    (chain : CertificateChainHandle) (key : PrivateKeyHandle)
    (schemes : List SignatureScheme)
    (h0 : chain.chainLen ≠ 0)
    (h1 : chain.derSize ≤ maxCertChainDerBytes)
    (h2 : keyKindsMatch chain.leafMeta.publicKeyKind key.keyKind = false) :
    validateEndpointCertKey chain key schemes = .error .certKeyMismatch := by
  unfold validateEndpointCertKey
  rw [if_neg h0]
  have hd : ¬ (chain.derSize > maxCertChainDerBytes) := by omega
  rw [if_neg hd]
  have hk : ¬ (keyKindsMatch chain.leafMeta.publicKeyKind key.keyKind = true) := by
    rw [h2]; decide
  rw [if_pos hk]

end Kroopt.Core.Proofs
