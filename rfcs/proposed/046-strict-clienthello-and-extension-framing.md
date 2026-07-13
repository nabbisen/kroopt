# RFC 046 — Strict ClientHello and Extension Framing

**Project.** kroopt  
**Status.** Proposed  
**Type.** Blocking parser/security fix  
**Target milestone.** AR1 (first protocol slice)  
**Requires completion of.** [RFC 003](../done/003-bounds-safe-parser-and-framer.md) (bounded parser), [RFC 023](../done/023-parser-fuzzing-corpus-and-mutation-policy.md) (fuzzing), [RFC 033](../done/033-real-client-handshake-processing.md) (real-client processing)  
**Touches.** `Kroopt/Parse/{Reader,Handshake}.lean`, parser proofs, negative tests and fuzz corpus  

## Review finding

Architecture review B2 found that bounds-safe parsing is not yet strict TLS framing: several vector lengths
are discarded, complete structures do not always require end-of-input, key-share trailing bytes are ignored,
and malformed SNI is treated like absent SNI.

## Decision

Every complete TLS structure must consume exactly its declared bytes. Absence, malformed presence, unknown
values, and unsupported values are distinct facts. Leniency is allowed only where RFC 8446 explicitly permits
unknown values (for example GREASE alongside a valid offer), never for inconsistent framing.

## Work breakdown

1. Add strict length-delimited sub-reader/vector helpers whose success proves exact consumption.
2. Validate inner lengths for `supported_versions`, `supported_groups`, `signature_algorithms`, `key_share`,
   SNI, and ALPN.
3. Validate the top-level handshake length and call `Reader.expectEnd` at complete boundaries.
4. Return a typed SNI result: absent, valid value, or parse error; malformed SNI is fatal.
5. Preserve exact committed wire bytes for transcript binding.
6. Add deterministic regression cases and committed fuzz seeds for each mismatch/trailing-byte class.

## Proof and fuzz obligations

- successful substructure parsing consumes exactly its declared region;
- successful top-level ClientHello parsing consumes the whole handshake message;
- reader bounds/monotonicity and exact-wire transcript properties remain intact;
- fuzzing covers truncated, over-declared, under-declared, trailing, duplicate, and malformed nested vectors.

## Acceptance criteria

1. Every review-listed malformed framing case fails deterministically with no fallback to default SNI.
2. Real OpenSSL/Python/curl ClientHellos and GREASE cases continue to pass.
3. Parser error projection remains coarse and carries no attacker bytes.
4. The strict parser and fuzz corpus run in the canonical gate.
5. Parser docs and proof inventory describe protocol validity separately from memory bounds safety.

## Non-goals

No new TLS extensions, HRR, or ClientHello semantic breadth is added.
