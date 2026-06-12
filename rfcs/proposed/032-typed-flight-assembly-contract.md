# RFC 032 — Typed Handshake/Record Assembly Contract

**Project.** kroopt  
**Status.** Proposed  
**Type.** Implementation RFC  
**Target milestone.** M36  
**Depends on.** RFC 002 (verified core), RFC 004 (record model), RFC 007 (transcript)  
**Touches.** `Kroopt/Core/Action.lean`, `Kroopt/Core/Handshake.lean`, `Kroopt/Proofs/*`, `Kroopt/Conn/Flight.lean`, `Kroopt/Conn/Interpreter.lean`, `scripts/check-deps.sh`  
**Canonical source.** kroopt fixed requirements §7, §8; architect RFC review of 2026-06-12 (RFC 032 amendments).  

---

> **Status note — partial (0.45.0-dev, M36 slice 3).** Certificate is now a typed action.
> Unlike EncryptedExtensions/CertificateVerify it is *not* pure-serializable — the core
> holds only an opaque `CertificateChainHandle` (no DER) — so it is a distinct
> `OutputAction.writeCertificate (conn) (chain)` rather than a `HandshakeOut` case, and the
> interpreter owns the DER resolution (RFC 032 §4: no generic byte payload under a
> core-approved action; the chain is named by its typed handle). `step` emits
> `writeCertificate (selectedCert)`. The test driver resolves the handle to its configured
> chain and serializes the real Certificate (byte-identical to the placeholder path it
> replaces); the production interpreter, which has no configured DER wired into its runtime
> yet (that is RFC 031), serializes a structurally-valid empty Certificate instead of the
> old four-byte placeholder. Three of five server-flight messages
> (EncryptedExtensions, Certificate, CertificateVerify) are now first-byte-free; proofs
> unchanged (91, axiom-clean); 24/24 suites including socket/wire.
>
> **Status note — partial (0.44.0-dev, M36 slice 2).** CertificateVerify is now a typed
> action too. `HandshakeOut` gains `certificateVerify (scheme : UInt16) (signature :
> ByteArray)`; `step` emits it from `onCertVerifySigned` as
> `writeHandshake (.certificateVerify <scheme> <sig>)`, carrying the negotiated scheme
> and the signature the core already holds from its `signCertificateVerify` result —
> realizing the two-stage rule (criterion 2) for this message: the request is the crypto
> op, and serialization happens only on the core's subsequent typed write action, never on
> bare result arrival. `serializeHandshakeOut` gains the CertificateVerify case (and a
> `sigSchemeToU16` wire encoder), so the interpreter and drivers serialize it through the
> same single function. Two of five server-flight messages (EncryptedExtensions,
> CertificateVerify) are now first-byte-free; proofs unchanged (91, axiom-clean); 24/24
> suites, flight still reaches `connected`.
>
> **Status note — partial (0.43.0-dev, M36 slice 1).** The first typed handshake-output
> action landed. `Core/Action.lean` gains `inductive HandshakeOut` and
> `OutputAction.writeHandshake (conn) (msg : HandshakeOut)`; the action classifiers
> (`isPlaintextEmit`, `isOrdinaryTransportWrite`) treat it as a non-plaintext,
> non-ordinary-write action, so the action-discipline lemmas hold unchanged. `step` now
> emits EncryptedExtensions as `writeHandshake (.encryptedExtensions <selected ALPN>)`
> instead of a placeholder `writeTransport`, and a single pure serializer
> (`Core.serializeHandshakeOut`) realizes its wire bytes. The production interpreter and
> both test drivers call that one serializer via total pattern matching on the typed
> message — **no path recognizes EncryptedExtensions by its first byte.** This realizes
> acceptance criterion 1 for one message and proves the typed-action → total-serializer
> pattern end to end (91 theorems, axiom-clean; 24/24 suites; the server flight still
> reaches `connected` with identical wire bytes).
>
> **Deliberately deferred (and why each is its own slice):**
> - *ServerHello* and *Finished* — their wire bytes need the server's ephemeral public
>   share and the Finished MAC, neither of which the pure core currently holds; surfacing
>   them needs new crypto-op flow, not just payload typing. They stay on the placeholder
>   path for now.
> - *Certificate* — the core holds only an opaque `CertificateChainHandle` (no DER), so
>   its typed action carries the handle and the interpreter owns the DER serialization;
>   converted in a later slice alongside the interpreter-side chain resolver.
> - *CertificateVerify* — the core does hold the signature (from `onCertVerifySigned`), so
>   this converts next, paired with the two-stage request/write rule (criterion 2).
> - *Transcript over real handshake-message bytes* (§5) and the *placeholder/first-byte CI
>   gate* (§7) land only once all five messages are typed (the gate would otherwise fail
>   on the still-present `frame*` helpers). The transcript currently keeps its abstract
>   snapshot contribution unchanged, so transcript-consistency proofs are untouched.
>
> The RFC stays in `proposed/` until criteria 1–5 are all met.


## 1. Summary

The verified core emits **structural placeholder frames** for handshake messages —
`frameServerHello = #[2,0,0,0]`, `frameEncryptedExtensions = #[8,0,0,0]`,
`frameCertificate = #[11,0,0,0]`, `frameCertificateVerify = #[15,0,0,0]`,
`frameServerFinished = #[20,0,0,0]` — and the byte-accurate message is assembled outside
the proof line by first-byte recognition. This RFC replaces that with a **typed assembly
contract**: the core emits semantic handshake/record actions that carry **protocol
facts** (selected suite/group/scheme, ALPN/SNI, certificate-chain handle, epoch,
direction, transcript reference); the interpreter realizes them into bytes via total
pattern matching and decides **only byte layout**. No production code branches on the
first byte of a handshake message.

This is the design artifact RFC 031 consumes. It deliberately touches the frozen core
and its proofs; the action-discipline and transcript-consistency obligations move onto
the typed action sequence.

## 2. Goals

1. A typed handshake-output action set with no ambiguous placeholder values and total
   pattern matching.
2. Two-stage modeling of crypto-dependent messages (CertificateVerify, Finished) so a
   message is emitted only after its crypto result exists and a core write action
   authorizes serialization.
3. Transcript contribution defined as **handshake-message bytes**, excluding record
   framing, AEAD material, CCS, and inner content-type/padding.
4. A protected-record payload type that is typed by origin and epoch (no generic byte
   smuggling under a core-approved action).
5. The action-discipline and transcript-consistency proofs re-established over the typed
   actions; a CI gate forbidding placeholder/first-byte dispatch in production.

## 3. Typed actions are protocol facts, not serialization facts

The **core** decides: selected cipher suite, group, signature scheme, ALPN, SNI,
certificate handle, epoch, direction, sequencing, and when a message may be written. The
**interpreter** decides only the byte layout that realizes those facts. An action payload
must never carry interpreter-chosen protocol values.

## 4. Proposed action model (names indicative)

```lean
inductive HandshakeOut where
  | serverHello         (p : ServerHelloPlan)          -- suite, group, serverShareHandle, version, sessionIdEcho
  | encryptedExtensions (p : EncryptedExtensionsPlan)  -- alpn, other negotiated exts

inductive OutputAction where
  | writeHandshake                    (conn : ConnId) (msg : HandshakeOut)
  | writeCertificate                  (conn : ConnId) (chain : CertificateChainHandle)
  -- two-stage, crypto-dependent messages:
  | requestCertificateVerifySignature (conn : ConnId) (scheme : SignatureScheme) (input : TranscriptRef)
  | writeCertificateVerify            (conn : ConnId) (scheme : SignatureScheme) (sig : SignatureRef)
  | requestFinishedMac                (conn : ConnId) (epoch : Epoch) (input : TranscriptRef)
  | writeFinished                     (conn : ConnId) (verifyData : FinishedRef)
  -- record + lifecycle:
  | writeProtectedRecord              (conn : ConnId) (epoch : Epoch) (payload : ProtectedPayloadPlan)
  | callCrypto                        (conn : ConnId) (op : OperationId) (req : CryptoOp)
  | emitPlaintext                     (conn : ConnId) (b : ByteArray)
  | acceptPlaintextBytes              (conn : ConnId) (n : Nat)
  | reportHandshakeComplete           (conn : ConnId) (meta : TlsMetadata)
  | failWithAlert                     (conn : ConnId) (a : AlertDescription)
  | closeTransport                    (conn : ConnId) (mode : CloseMode)
  | releaseSecret                     (conn : ConnId) (h : SecretHandle)

inductive ProtectedPayloadPlan where
  | handshakeMessage (kind : HandshakeKind) (ref : SerializedHandshakeRef)
  | alert            (alert : AlertDescription)
  | applicationData  (accepted : AcceptedPlaintextRef)
```

**Two-stage rule.** The interpreter must not infer that a crypto result should be
serialized merely because it has arrived. CertificateVerify is written only on a core
`writeCertificateVerify` carrying the `SignatureRef` from the answered
`requestCertificateVerifySignature`; Finished likewise via
`requestFinishedMac` → `writeFinished`. Serialization always needs a core-authorized
write action (or a core-authorized continuation rule), never the bare presence of a
result.

**No generic `PayloadRef`.** Protected payloads are typed by origin and epoch via
`ProtectedPayloadPlan`, so interpreter-owned bytes cannot be smuggled under a
core-approved record action.

## 5. Transcript contribution (precise)

The transcript is over **serialized TLS handshake messages**, and excludes:

- TLS record headers;
- AEAD ciphertext and tag;
- TLS 1.3 compatibility CCS records;
- the `TLSInnerPlaintext` content-type octet and zero padding.

Model it as handshake-message bytes, not record bytes:

```lean
structure HandshakeTranscriptEvent where      -- (a.k.a. TranscriptHandshakeBytes)
  bytes                  : ByteArray            -- the serialized handshake message body
  kind                   : HandshakeKind
  transcriptContribution : TranscriptContribution   -- contributesOnce | nonTranscript
```

Every handshake message contributes exactly once; permitted non-transcript records
(CCS, per RFC 033) are explicitly `nonTranscript`. RFC 031's ledger binds each
`HandshakeTranscriptEvent` to the core action that authorized it.

## 6. Core changes and proof impact

- Replace the `frame*` placeholder functions in `Core/Handshake.lean` with emission of
  the typed actions above (keeping the `step` transition *shape* — same phases, same
  order — so the re-proof is localized to action payloads).
- Re-establish `Proofs/ActionDiscipline.lean` over the typed actions.
- Re-establish transcript consistency so the theorem reads "consistency over the
  serialized handshake-message bytes," upgrading the deep review's
  "core-authorized abstract trace" characterization to the intended §15.6 guarantee.

## 7. CI gate against placeholder/first-byte dispatch

Extend `scripts/check-deps.sh` (or a new `scripts/check-no-placeholder.sh` in CI) so
production modules **fail** if they contain `frameServerHello`,
`frameEncryptedExtensions`, `frameCertificate`, `frameCertificateVerify`,
`frameServerFinished`, or any first-byte handshake-dispatch helper, outside an explicitly
archived compatibility test.

## 8. Acceptance criteria

1. `Core/Handshake.lean` emits typed handshake/record actions; the `frame*` functions are
   gone (or quarantined behind the RFC 031 §8 adapter with a removal ticket).
2. CertificateVerify and Finished use the two-stage request/write actions; the
   interpreter never serializes on bare result arrival.
3. Protected payloads use `ProtectedPayloadPlan` (typed by origin/epoch); no generic
   byte payload reference exists.
4. Transcript contribution is handshake-message bytes per §5; the CI gate of §7 is green.
5. `Proofs/ActionDiscipline.lean` and transcript consistency build clean over the typed
   actions; axiom whitelist preserved; theorem set does not regress.

## 9. Risks

- **Proof churn on the frozen core** — costliest part of M36; mitigated by preserving the
  transition shape and only typing the write-action payloads.
- **Record-layer alignment** — `writeProtectedRecord`/`ProtectedPayloadPlan` must stay
  aligned with RFC 004 and RFC 033; co-review those.
