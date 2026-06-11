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

/-- **ALPN safety (RFC 011 §8).** Any negotiated protocol was both offered by the
client and allowed by the endpoint — kroopt never selects an unoffered protocol. -/
theorem negotiateAlpn_offered_and_allowed
    (mode : AlpnSelectionMode) (client allowed : List AlpnProtocol) (a : AlpnProtocol)
    (h : negotiateAlpn mode client allowed = some a) :
    alpnMem a client = true ∧ alpnMem a allowed = true := by
  cases mode with
  | serverPreference =>
      simp only [negotiateAlpn] at h
      have hp := List.find?_some h
      have hm := List.mem_of_find?_eq_some h
      exact ⟨hp, alpnMem_of_mem hm⟩
  | clientPreferenceWithinAllowed =>
      simp only [negotiateAlpn] at h
      have hp := List.find?_some h
      have hm := List.mem_of_find?_eq_some h
      exact ⟨alpnMem_of_mem hm, hp⟩
  | requireOverlap =>
      simp only [negotiateAlpn] at h
      have hp := List.find?_some h
      have hm := List.mem_of_find?_eq_some h
      exact ⟨alpnMem_of_mem hm, hp⟩

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
