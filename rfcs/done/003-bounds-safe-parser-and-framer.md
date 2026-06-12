# RFC 003 — Bounds-Safe Parser and Framer Foundation

**Project.** kroopt  
**Status.** Implemented (0.24.0-dev)  
**Type.** Implementation RFC  
**Target milestone.** M1  
**Depends on.** RFC 002  
**Touches.** `Kroopt/Parse/` (`Reader`, `Handshake`, `Der`); `Kroopt/Proofs/ParserBounds.lean`  
**Canonical source.** kroopt fixed requirements and external design.  

---

## 1. Summary

This RFC defines the parsing and framing foundation for TLS bytes. kroopt must not pass around partially checked byte slices as if they were structured protocol values. Parsers return validated values or typed errors. Framers produce canonical byte sequences where kroopt is responsible for constructing protocol messages.

Parser safety is a proof target and a security boundary. A malformed ClientHello, extension list, record header, or certificate metadata blob must become a bounded parse failure, not an exception, buffer overrun, unbounded allocation, or ambiguous state transition.

## 2. Goals

- Define a small pure parser library for TLS vectors and length-prefixed fields.
- Enforce record, handshake, extension, and DER metadata bounds by construction.
- Preserve exact wire bytes for transcript binding.
- Provide typed parse errors for deterministic alert mapping.
- Support fuzzing and model tests without sockets or crypto.

## 3. Non-goals

- Full ASN.1/X.509 path validation.
- General-purpose DER library.
- Automatic recovery from malformed TLS messages.
- Lenient browser-style parsing. kroopt should be strict and deterministic.

## 4. Parser API sketch

```lean
namespace Kroopt.Parse

structure Reader where
  input  : ByteArray
  offset : Nat
  proof  : offset <= input.size

inductive ParseError where
  | unexpectedEof
  | trailingBytes
  | lengthOverflow
  | valueOutOfRange
  | duplicateExtension ExtensionType
  | unsupportedVersion UInt16
  | unsupportedGroup NamedGroup
  | unsupportedSignatureScheme SignatureScheme
  | malformedDer
  | budgetExceeded BudgetKind
  | policyViolation PolicyError

structure Parsed (α : Type) where
  value      : α
  consumed   : Nat
  wireBytes  : ByteArray

abbrev Parser α := Reader -> Except ParseError (Parsed α × Reader)
```

The `wireBytes` field is critical for transcript correctness. It must be the exact byte slice consumed from the transport for the parsed value.

## 5. Validated value discipline

Each parser must return a value type that encodes what has been checked:

```lean
structure ValidRecordHeader where
  outerType : ContentType
  legacyVersion : UInt16
  length : Fin (maxCiphertextRecordSize + 1)

structure ValidClientHello where
  legacyVersion : UInt16
  random : ByteArray
  sessionId : BoundedBytes 32
  cipherSuites : NonEmptyList CipherSuite
  extensions : ClientHelloExtensions
  wireBytes : ByteArray

structure ClientHelloExtensions where
  supportedVersions : SupportedVersions
  keyShare : X25519ClientShare
  supportedGroups : List NamedGroup
  signatureAlgorithms : NonEmptyList SignatureScheme
  serverName : Option ServerName
  alpn : Option (NonEmptyList ALPNProtocol)
```

Runtime code must not construct these validated structures except through parser constructors or test-only trusted builders.

## 6. Bounds and budgets

The parser enforces:

- maximum TLSPlaintext fragment size;
- maximum TLSCiphertext size including AEAD expansion;
- maximum handshake message size;
- maximum ClientHello size;
- maximum extension count;
- maximum ALPN protocol list bytes;
- maximum SNI name length;
- maximum certificate metadata parse depth for config lint;
- no silent Nat/UInt overflow on length computations.

Budget failures must map to deterministic TLS alerts or typed internal errors according to RFC 013.

## 7. Duplicate and unknown extensions

Duplicate TLS extensions in ClientHello are rejected unless a specific future RFC proves and documents an exception. Unknown extensions are ignored only if TLS 1.3 permits ignoring them and they do not affect security policy. Unknown values inside known critical extensions are rejected.

## 8. Framing API

Framers convert structured values into bytes for messages kroopt sends:

```lean
def frameServerHello : ServerHello -> Except FrameError ByteArray
def frameEncryptedExtensions : EncryptedExtensions -> Except FrameError ByteArray
def frameCertificate : CertificateChain -> Except FrameError ByteArray
def frameCertificateVerify : CertificateVerify -> Except FrameError ByteArray
def frameFinished : Finished -> Except FrameError ByteArray
def frameAlert : AlertLevel -> AlertDescription -> ByteArray
def frameRecord : TLSPlaintext -> Except FrameError ByteArray
```

Framing must also emit the exact bytes that enter the transcript. Server-side bytes are transcript-bound from the output bytes, not from a later reconstructed structure.

## 9. Internal design

### 9.1 Reader implementation

Use a `Reader` with an offset proof. Each operation returns a new reader with a monotonically increasing offset. The parser should avoid raw slicing helper functions that do not carry size checks.

Important operations:

- `takeU8`, `takeU16`, `takeU24`, `takeU32`;
- `takeBytesExact n`;
- `takeVector lenBytes maxLen itemParser`;
- `remaining`;
- `expectEnd`.

### 9.2 U24 handling

TLS handshake lengths use 24-bit integers. Define a dedicated `UInt24` or bounded Nat wrapper. Do not represent handshake lengths as unchecked `UInt32` and cast later.

### 9.3 Parser construction theorem

Each parser should provide or inherit a theorem:

```lean
theorem parser_consumes_within_bounds :
  parseX r = Except.ok (p, r') -> r.offset <= r'.offset ∧ r'.offset <= r.input.size
```

For complex parsers, prove composition lemmas rather than repeating low-level arithmetic.

## 10. Security considerations

- Never allocate based solely on attacker-controlled length before checking global budgets.
- Never parse DER recursively without depth and length limits.
- Never log raw malformed bytes at error level; logs use error categories and small redacted previews.
- Reject ambiguous encodings rather than trying to repair them.
- Parser errors must not expose secrets, internal pointer ids, or secret-handle ids.

## 11. Testing requirements

- Unit tests for every primitive reader operation.
- Golden ClientHello parse tests.
- Negative tests for truncated vectors, length overflows, duplicate extensions, unsupported versions, missing key_share, unsupported groups, and trailing bytes.
- Fuzz target for record header + ClientHello + extension parser.
- Round-trip tests for server-generated frames where applicable.

## 12. Acceptance criteria

- No TLS protocol code consumes raw ClientHello bytes except through parser APIs.
- Every parsed structure needed by handshake logic carries exact wire bytes or a transcript-binding token.
- Parser functions have bounds-safety proof coverage or are isolated as tested trusted helpers with explicit follow-up proof tasks.
- Fuzz harnesses exist even if long-running fuzzing is not yet enabled in every CI tier.
