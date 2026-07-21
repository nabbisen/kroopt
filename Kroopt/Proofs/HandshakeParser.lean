import Kroopt.Parse.Handshake
import Kroopt.Proofs.ParserBounds

/-!
# Kroopt.Proofs.HandshakeParser

Concrete input-preservation evidence for the RFC 046 Slice 2 callbacks passed
to `Reader.takeVectorExact`. The generic helper isolates a byte slice but cannot
constrain an arbitrary callback from returning a reader over another buffer;
these proofs establish that the UInt16, key-share, and ALPN list callbacks used
by kroopt preserve their isolated reader input while advancing monotonically.
-/

namespace Kroopt.Parse.Proofs

open Kroopt.Parse (ParseError Reader)

theorem parseU16Items_input (r r' : Reader) (items : List UInt16)
    (h : parseU16Items r = .ok (items, r')) :
    r.input = r'.input := by
  unfold parseU16Items at h
  have hitem : ∀ (rr rr' : Reader) (a : UInt16),
      rr.takeU16 = .ok (a, rr') → rr.input = rr'.input ∧ rr.offset ≤ rr'.offset := by
    intro rr rr' a ha
    have hb := takeU16_bounds rr a rr' ha
    exact ⟨hb.2.symm, hb.1⟩
  exact (takeCountedItems_bounds (fun rr => rr.takeU16) hitem
    r.remaining r r' items h).1

theorem parseKeyShareEntry_bounds (r r' : Reader) (entry : UInt16 × ByteArray)
    (h : parseKeyShareEntry r = .ok (entry, r')) :
    r.input = r'.input ∧ r.offset ≤ r'.offset := by
  unfold parseKeyShareEntry at h
  cases hg : r.takeU16 with
  | error e => rw [hg] at h; simp at h
  | ok p =>
    obtain ⟨group, r1⟩ := p
    rw [hg] at h
    simp only at h
    cases hk : r1.takeVectorBytes .len16 maxVectorLen with
    | error e => rw [hk] at h; simp at h
    | ok p =>
      obtain ⟨ke, r2⟩ := p
      rw [hk] at h
      split at h
      · simp at h
      · rename_i _ data r2' heq
        simp only [Except.ok.injEq, Prod.mk.injEq] at heq
        obtain ⟨hdata, hr2⟩ := heq
        subst data
        subst r2'
        split at h
        · simp at h
        · simp only [Except.ok.injEq, Prod.mk.injEq] at h
          obtain ⟨_, hr⟩ := h
          rw [← hr]
          have hgBounds := takeU16_bounds r group r1 hg
          have hkBounds := takeVectorBytes_bounds r1 .len16 maxVectorLen ke r2 hk
          exact ⟨hgBounds.2.symm.trans hkBounds.2.2.symm,
            Nat.le_trans hgBounds.1 hkBounds.1⟩

theorem parseKeyShareItems_input (r r' : Reader)
    (items : List (UInt16 × ByteArray))
    (h : r.takeCountedItems maxKeyShares parseKeyShareEntry = .ok (items, r')) :
    r.input = r'.input := by
  exact (takeCountedItems_bounds parseKeyShareEntry
    (fun rr rr' entry hentry => parseKeyShareEntry_bounds rr rr' entry hentry)
    maxKeyShares r r' items h).1

theorem parseAlpnProtocol_bounds (r r' : Reader) (name : ByteArray)
    (h : parseAlpnProtocol r = .ok (name, r')) :
    r.input = r'.input ∧ r.offset ≤ r'.offset := by
  unfold parseAlpnProtocol at h
  cases hn : r.takeVectorBytes .len8 255 with
  | error e => rw [hn] at h; simp at h
  | ok p =>
    obtain ⟨parsed, outer⟩ := p
    rw [hn] at h
    simp only at h
    split at h
    · simp at h
    · simp only [Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨_, hr⟩ := h
      rw [← hr]
      have hb := takeVectorBytes_bounds r .len8 255 parsed outer hn
      exact ⟨hb.2.2.symm, hb.1⟩

theorem parseAlpnItems_input (r r' : Reader) (items : List ByteArray)
    (h : parseAlpnItems r = .ok (items, r')) :
    r.input = r'.input := by
  unfold parseAlpnItems at h
  exact (takeCountedItems_bounds parseAlpnProtocol
    (fun rr rr' name hname => parseAlpnProtocol_bounds rr rr' name hname)
    r.remaining r r' items h).1

end Kroopt.Parse.Proofs
