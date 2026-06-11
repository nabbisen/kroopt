import Kroopt.Parse.Reader

/-!
# Kroopt.Proofs.ParserBounds

Bounds-safety proofs for the parser foundation (RFC 003 §9.3, §15 parser bounds
safety). The construction theorem every primitive satisfies is:

```
parseX r = .ok (_, r') → r.offset ≤ r'.offset ∧ r'.offset ≤ r'.input.size ∧ r'.input = r.input
```

The second conjunct — the cursor stays within the buffer — is *free* from the
`Reader.inBounds` field (bounds-safety by construction). What the proofs add is
**monotonicity** (the cursor only moves forward, so loops make progress and
cannot re-read) and **input preservation** (reads never mutate or swap the
buffer, which transcript binding relies on). Complex parsers compose these
lemmas rather than re-deriving arithmetic (RFC 003 §9.3).

All proofs are `sorry`/`axiom`/`unsafe`-free (RFC 022 §4).
-/

namespace Kroopt.Parse
namespace Proofs

open Kroopt.Parse (Reader ParseError)

/-- Any reader is in bounds by construction — the field *is* the proof. This is
the data-level statement of "the cursor never points past the buffer". -/
theorem reader_in_bounds (r : Reader) : r.offset ≤ r.input.size :=
  r.inBounds

/-- **Foundational read is bounds-safe.** `takeBytes` advances the cursor by
exactly `n`, never past the end, and never changes the buffer. Every other
primitive is built on this. -/
theorem takeBytes_bounds (r : Reader) (n : Nat) (bs : ByteArray) (r' : Reader)
    (h : r.takeBytes n = .ok (bs, r')) :
    r.offset ≤ r'.offset
    ∧ r'.offset ≤ r'.input.size
    ∧ r'.input = r.input
    ∧ r'.offset = r.offset + n := by
  unfold Reader.takeBytes at h
  split at h
  · -- success branch; `hle : r.offset + n ≤ r.input.size`
    rename_i hle
    simp only [Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨_, hr⟩ := h
    subst hr
    -- `r'` is now the structure literal; projections reduce definitionally
    exact ⟨Nat.le_add_right _ _, hle, rfl, rfl⟩
  · -- eof branch: not a success
    simp at h

/-- Monotonicity + input-preservation extracted from `takeBytes_bounds`, the
form most composition proofs use. -/
theorem takeBytes_mono (r : Reader) (n : Nat) (bs : ByteArray) (r' : Reader)
    (h : r.takeBytes n = .ok (bs, r')) :
    r.offset ≤ r'.offset ∧ r'.input = r.input := by
  have hb := takeBytes_bounds r n bs r' h
  exact ⟨hb.1, hb.2.2.1⟩

/-- A uniform helper: every fixed-width integer read delegates to `takeBytes k`,
so its bounds follow from `takeBytes_bounds`. This captures the shared shape
`match r.takeBytes k with | .ok (bs, r') => .ok (f bs, r') | .error e =>
.error e`. -/
theorem takeBytesThen_bounds
    {α : Type} (r : Reader) (k : Nat) (f : ByteArray → α) (a : α) (r' : Reader)
    (h : (match r.takeBytes k with
          | .ok (bs, r₀) => .ok (f bs, r₀)
          | .error e => .error e) = (.ok (a, r') : Except ParseError (α × Reader))) :
    r.offset ≤ r'.offset ∧ r'.input = r.input := by
  cases hb : r.takeBytes k with
  | error e => rw [hb] at h; simp at h
  | ok p =>
    obtain ⟨bs, r₀⟩ := p
    rw [hb] at h
    simp only [Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨_, hr⟩ := h
    rw [← hr]
    exact takeBytes_mono r k bs r₀ hb

theorem takeU8_bounds (r : Reader) (v : UInt8) (r' : Reader)
    (h : r.takeU8 = .ok (v, r')) :
    r.offset ≤ r'.offset ∧ r'.input = r.input := by
  unfold Reader.takeU8 at h
  exact takeBytesThen_bounds r 1 (fun bs => (Reader.beNat bs).toUInt8) v r' h

theorem takeU16_bounds (r : Reader) (v : UInt16) (r' : Reader)
    (h : r.takeU16 = .ok (v, r')) :
    r.offset ≤ r'.offset ∧ r'.input = r.input := by
  unfold Reader.takeU16 at h
  exact takeBytesThen_bounds r 2 (fun bs => (Reader.beNat bs).toUInt16) v r' h

theorem takeU24_bounds (r : Reader) (v : UInt24) (r' : Reader)
    (h : r.takeU24 = .ok (v, r')) :
    r.offset ≤ r'.offset ∧ r'.input = r.input := by
  unfold Reader.takeU24 at h
  exact takeBytesThen_bounds r 3 (fun bs => (⟨Reader.beNat bs⟩ : UInt24)) v r' h

theorem takeU32_bounds (r : Reader) (v : UInt32) (r' : Reader)
    (h : r.takeU32 = .ok (v, r')) :
    r.offset ≤ r'.offset ∧ r'.input = r.input := by
  unfold Reader.takeU32 at h
  exact takeBytesThen_bounds r 4 (fun bs => (Reader.beNat bs).toUInt32) v r' h

/-- Length-prefix reads are bounds-safe for every prefix width. -/
theorem takeLen_bounds (r : Reader) (lp : LenPrefix) (len : Nat) (r' : Reader)
    (h : r.takeLen lp = .ok (len, r')) :
    r.offset ≤ r'.offset ∧ r'.input = r.input := by
  cases lp with
  | len8 =>
    unfold Reader.takeLen at h
    cases hu : r.takeU8 with
    | error e => rw [hu] at h; simp at h
    | ok p =>
      obtain ⟨v, r₀⟩ := p
      rw [hu] at h
      simp only [Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨_, hr⟩ := h
      rw [← hr]; exact takeU8_bounds r v r₀ hu
  | len16 =>
    unfold Reader.takeLen at h
    cases hu : r.takeU16 with
    | error e => rw [hu] at h; simp at h
    | ok p =>
      obtain ⟨v, r₀⟩ := p
      rw [hu] at h
      simp only [Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨_, hr⟩ := h
      rw [← hr]; exact takeU16_bounds r v r₀ hu
  | len24 =>
    unfold Reader.takeLen at h
    cases hu : r.takeU24 with
    | error e => rw [hu] at h; simp at h
    | ok p =>
      obtain ⟨v, r₀⟩ := p
      rw [hu] at h
      simp only [Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨_, hr⟩ := h
      rw [← hr]; exact takeU24_bounds r v r₀ hu

/-- **Length-prefixed byte vector is bounds-safe.** The headline composition
result of M1: reading a budgeted, length-prefixed vector advances the cursor
monotonically, stays within the buffer, and preserves the buffer (RFC 003 §6,
§9.3). This is the framer the record and extension parsers (M2/M4) build on. -/
theorem takeVectorBytes_bounds
    (r : Reader) (lp : LenPrefix) (maxLen : Nat) (bs : ByteArray) (r' : Reader)
    (h : r.takeVectorBytes lp maxLen = .ok (bs, r')) :
    r.offset ≤ r'.offset
    ∧ r'.offset ≤ r'.input.size
    ∧ r'.input = r.input := by
  unfold Reader.takeVectorBytes at h
  cases hlen : r.takeLen lp with
  | error e => simp [hlen] at h
  | ok p =>
    obtain ⟨len, r1⟩ := p
    simp only [hlen] at h
    have hlb := takeLen_bounds r lp len r1 hlen
    split at h <;>
      first
      | (have hbb := takeBytes_bounds r1 len bs r' h
         exact ⟨Nat.le_trans hlb.1 hbb.1, hbb.2.1, by rw [hbb.2.2.1, hlb.2]⟩)
      | contradiction

/-- **Parser bounds safety (umbrella).** For the foundational reads, success
always yields a cursor that advanced monotonically and remains within the
buffer. Stated over `takeBytes` (every primitive reduces to it). This is the M1
entry in the theorem inventory. -/
theorem parser_bounds_safe (r : Reader) (n : Nat) (bs : ByteArray) (r' : Reader)
    (h : r.takeBytes n = .ok (bs, r')) :
    r.offset ≤ r'.offset ∧ r'.offset ≤ r'.input.size := by
  have hb := takeBytes_bounds r n bs r' h
  exact ⟨hb.1, hb.2.1⟩

end Proofs
end Kroopt.Parse
