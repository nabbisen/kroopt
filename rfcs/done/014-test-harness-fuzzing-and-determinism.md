# RFC 014 — Deterministic Test Harness, Fake Crypto, Fake Transport, and Fuzzing

**Project.** kroopt  
**Status.** Implemented (0.24.0-dev)  
**Type.** Implementation RFC  
**Target milestone.** M5  
**Depends on.** RFC 002, RFC 003, RFC 004, RFC 006  
**Touches.** `Tests/` (fake provider, fake transport, model traces); `fuzz/`  
**Canonical source.** kroopt fixed requirements and external design.  

---

## 1. Summary

This RFC defines the testing infrastructure that lets kroopt validate the pure core before real crypto and sockets, then continue testing the interpreter and parsers under hostile inputs. Deterministic tests are a first-class design mechanism, not a later QA task.

## 2. Goals

- Define fake transport.
- Define fake crypto provider.
- Drive `Kroopt.Core.step` directly with scripted event traces.
- Test interpreter faithfulness separately.
- Add fuzz targets for parser attack surfaces.
- Make negative TLS behavior reproducible.

## 3. Fake transport

```lean
structure FakeTransport where
  inboundChunks : List ByteArray
  outboundLog : List ByteArray
  readableSchedule : List Bool
  writableSchedule : List WritableOutcome
  eofAt : Option Nat
```

`WritableOutcome` can model full write, partial write, wouldBlock, and transport error. This allows repeatable partial-write and retry tests.

## 4. Fake crypto provider

The fake provider is deterministic and purpose-aware:

- ECDHE returns fixed secret handles for known test peer shares.
- HKDF returns deterministic labeled handles.
- AEAD seal/open wraps plaintext in test envelopes that include expected metadata.
- AEAD open can be configured to fail.
- Sign/verify operations return deterministic test signatures.
- Finished verification can succeed or fail by script.

The fake provider must still enforce operation id, epoch, direction, and metadata expectations. It should catch misuse early.

## 5. Trace test format

A trace test contains:

```text
initial config
initial state
scripted input events
expected output action predicates
expected final state
expected public results
```

Do not require byte-perfect action logs for every test; use predicates where unrelated details would make tests brittle.

## 6. Interpreter faithfulness tests

These tests feed action lists into the interpreter and assert runtime effects:

- `writeTransport` reaches fake transport in order;
- partial writes preserve pending bytes;
- `callCrypto` reaches provider with metadata;
- provider result returns to core with same operation id;
- `emitPlaintext` becomes the next `recv` result;
- terminal close calls fake close exactly once.

## 7. Fuzz targets

Required fuzz targets:

1. TLS record header and record reassembly parser.
2. ClientHello parser.
3. Extension parser.
4. Minimal DER metadata parser.
5. Optional: action interpreter state-machine fuzzer using generated event sequences.

Fuzzers must enforce resource limits so they cannot become unbounded memory tests by accident.

## 8. CI tiers

- Fast unit/model tests on every commit.
- Parser fuzz smoke tests on every commit or nightly depending on cost.
- Longer fuzzing and sanitizer jobs in scheduled CI.
- Interop tests in integration CI tier.

## 9. Security considerations

- Tests must include attacker-controlled malformed inputs, not only happy paths.
- Fuzz failures must preserve crashing inputs as fixtures.
- Fake crypto must not make the core accidentally depend on impossible provider behavior.
- Negative tests must assert no plaintext output, not merely that an error occurred.

## 10. Acceptance criteria

- Full synthetic handshake trace passes before real HACL/iotakt integration.
- Every RFC 013 alert category has at least one negative test.
- Fuzz harness entry points exist for required parsers.
- Interpreter faithfulness tests cover partial read/write and wouldBlock behavior.
