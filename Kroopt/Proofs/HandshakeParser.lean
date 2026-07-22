import Kroopt.Parse.Handshake
import Kroopt.Proofs.ParserBounds

/-!
# Kroopt.Proofs.HandshakeParser

Concrete input-preservation evidence for the RFC 046 callbacks passed
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

theorem parseExtension_bounds (r r' : Reader) (ext : RawExtension)
    (h : parseExtension r = .ok (ext, r')) :
    r.input = r'.input ∧ r.offset ≤ r'.offset := by
  unfold parseExtension at h
  cases ht : r.takeU16 with
  | error e => simp [Except.bind, ht] at h
  | ok p =>
    obtain ⟨ty, r1⟩ := p
    simp only [Except.bind, ht] at h
    cases hd : r1.takeVectorBytes .len16 maxVectorLen with
    | error e => simp [hd] at h
    | ok p =>
      obtain ⟨data, r2⟩ := p
      simp only [hd] at h
      simp only [Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨_, hr⟩ := h
      rw [← hr]
      have hb1 := takeU16_bounds r ty r1 ht
      have hb2 := takeVectorBytes_bounds r1 .len16 maxVectorLen data r2 hd
      exact ⟨hb1.2.symm.trans hb2.2.2.symm, Nat.le_trans hb1.1 hb2.1⟩

theorem parseExtensionItems_input (r r' : Reader) (exts : List RawExtension)
    (h : parseExtensionItems r = .ok (exts, r')) : r.input = r'.input := by
  unfold parseExtensionItems at h
  split at h
  · simp at h
  · exact (takeCountedItems_bounds parseExtension
      (fun rr rr' ext hext => parseExtension_bounds rr rr' ext hext)
      maxExtensions r r' exts h).1

theorem parseServerNameEntry_bounds (r r' : Reader) (name : RawServerName)
    (h : parseServerNameEntry r = .ok (name, r')) :
    r.input = r'.input ∧ r.offset ≤ r'.offset := by
  unfold parseServerNameEntry at h
  cases ht : r.takeU8 with
  | error e => simp [Except.bind, ht] at h
  | ok p =>
    obtain ⟨ty, r1⟩ := p
    simp only [Except.bind, ht] at h
    cases hn : r1.takeVectorBytes .len16 maxVectorLen with
    | error e => simp [Except.bind, hn] at h
    | ok p =>
      obtain ⟨bytes, r2⟩ := p
      simp only [Except.bind, hn] at h
      split at h
      · simp at h
      · simp only [Except.ok.injEq, Prod.mk.injEq] at h
        obtain ⟨_, hr⟩ := h
        rw [← hr]
        have hb1 := takeU8_bounds r ty r1 ht
        have hb2 := takeVectorBytes_bounds r1 .len16 maxVectorLen bytes r2 hn
        exact ⟨hb1.2.symm.trans hb2.2.2.symm, Nat.le_trans hb1.1 hb2.1⟩

theorem parseServerNameItems_input (r r' : Reader) (names : List RawServerName)
    (h : parseServerNameItems r = .ok (names, r')) : r.input = r'.input := by
  unfold parseServerNameItems at h
  exact (takeCountedItems_bounds parseServerNameEntry
    (fun rr rr' name hname => parseServerNameEntry_bounds rr rr' name hname)
    r.remaining r r' names h).1

theorem frameClientHelloBody_input (r r' : Reader) (framed : FramedClientHello)
    (h : frameClientHelloBody r = .ok (framed, r')) : r.input = r'.input := by
  unfold frameClientHelloBody at h
  cases hv : r.takeU16 with
  | error e => simp [Except.bind, hv] at h
  | ok p =>
    obtain ⟨version, r1⟩ := p
    simp only [Except.bind, hv] at h
    split at h
    · simp at h
    · cases hrand : r1.takeBytes 32 with
      | error e => simp [Except.bind, hrand] at h
      | ok p =>
        obtain ⟨random, r2⟩ := p
        simp only [Except.bind, hrand] at h
        cases hsid : r2.takeVectorBytes .len8 32 with
        | error e => simp [Except.bind, hsid] at h
        | ok p =>
          obtain ⟨sessionId, r3⟩ := p
          simp only [Except.bind, hsid] at h
          cases hsuites : r3.takeVectorExact .len16 (2 * maxCipherSuites) parseU16Items with
          | error e => simp [Except.bind, hsuites] at h
          | ok p =>
            obtain ⟨suites, r4⟩ := p
            simp only [Except.bind, hsuites] at h
            split at h
            · simp at h
            · cases hcomp : r4.takeVectorBytes .len8 maxVectorLen with
              | error e => simp [Except.bind, hcomp] at h
              | ok p =>
                obtain ⟨compression, r5⟩ := p
                simp only [Except.bind, hcomp] at h
                split at h
                · simp at h
                · cases hexts : r5.takeVectorExact .len16 maxVectorLen parseExtensionItems with
                  | error e => simp [Except.bind, hexts] at h
                  | ok p =>
                    obtain ⟨exts, r6⟩ := p
                    simp only [Except.bind, hexts] at h
                    simp only [Except.ok.injEq, Prod.mk.injEq] at h
                    obtain ⟨_, hr6⟩ := h
                    rw [← hr6]
                    have h1 := takeU16_bounds r version r1 hv
                    have h2 := takeBytes_bounds r1 32 random r2 hrand
                    have h3 := takeVectorBytes_bounds r2 .len8 32 sessionId r3 hsid
                    have h4 := takeVectorExact_outer_input r3 .len16
                      (2 * maxCipherSuites) parseU16Items suites r4 hsuites
                    have h5 := takeVectorBytes_bounds r4 .len8 maxVectorLen compression r5 hcomp
                    have h6 := takeVectorExact_outer_input r5 .len16 maxVectorLen
                      parseExtensionItems exts r6 hexts
                    rw [h6, h5.2.2, h4, h3.2.2, h2.2.2.1, h1.2]

theorem parseClientHelloBody_input (r r' : Reader) (vch : Kroopt.Core.ValidClientHello)
    (h : parseClientHelloBody r = .ok (vch, r')) : r.input = r'.input := by
  unfold parseClientHelloBody at h
  cases hf : frameClientHelloBody r with
  | error e => simp [Except.bind, hf] at h
  | ok p =>
    obtain ⟨framed, outer⟩ := p
    simp only [Except.bind, hf] at h
    cases hv : validateFramedClientHello framed with
    | error e => simp [Except.bind, hv] at h
    | ok parsed =>
      simp only [Except.bind, hv] at h
      simp only [Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨_, hr⟩ := h
      rw [← hr]
      exact frameClientHelloBody_input r outer framed hf

/-- Successful public ClientHello parsing binds the exact input bytes and
proves that the decoded uint24 body occupies the complete input after its
four-byte handshake header. -/
theorem parseClientHello_exact_input (input : ByteArray)
    (wb : Kroopt.Core.WireBound Kroopt.Core.ValidClientHello)
    (h : parseClientHello input = .ok wb) :
    wb.wireBytes = input ∧ ∃ declared,
      clientHelloDeclaredLength input = some declared ∧ input.size = 4 + declared := by
  unfold parseClientHello at h
  cases hu : (Reader.ofBytes input).takeU8 with
  | error e => simp [Except.bind, hu] at h
  | ok p =>
    obtain ⟨msgType, r1⟩ := p
    simp only [Except.bind, hu] at h
    split at h
    · simp at h
    · cases hv : r1.takeVectorExact .len24 r1.remaining parseClientHelloBody with
      | error e => simp [Except.bind, hv] at h
      | ok p =>
        obtain ⟨vch, outer⟩ := p
        simp only [Except.bind, hv] at h
        cases he : outer.expectEnd with
        | error e => simp [Except.bind, he] at h
        | ok u =>
          simp only [Except.bind, he] at h
          simp only [Except.ok.injEq] at h
          rw [← h]
          constructor
          · rfl
          · obtain ⟨n, r2, bytes, inner, hlen, _, _, hoff, hinput, _, _⟩ :=
              takeVectorExact_witnesses r1 .len24 r1.remaining
                parseClientHelloBody vch outer hv
            refine ⟨n, ?_, ?_⟩
            · unfold clientHelloDeclaredLength
              simp only [hu, hlen]
            · have hend := expectEnd_success outer he
              have huExact := takeU8_exact (Reader.ofBytes input) msgType r1 hu
              have hreader : r1.input = input := huExact.2
              rw [hoff, hinput, hreader] at hend
              have hoff1 : r1.offset = 1 := by simpa [Reader.ofBytes] using huExact.1
              simp [LenPrefix.byteWidth, hoff1] at hend
              omega

end Kroopt.Parse.Proofs
