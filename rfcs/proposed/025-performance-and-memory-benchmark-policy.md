# RFC 025 — Performance and Memory Benchmark Policy

**Project.** kroopt  
**Status.** Proposed  
**Type.** Implementation RFC  
**Target milestone.** v0.3 onward; micro earlier  
**Depends on.** RFC 004, RFC 008, RFC 010, RFC 019  
**Touches.** `bench/`; performance docs  
**Canonical source.** kroopt fixed requirements and external design.  

---

## 1. Summary

This RFC defines performance and memory benchmarks for kroopt. Security and
proof correctness dominate, but an edge TLS layer must avoid pathological
latency, allocation, and throughput behavior. Benchmarks are used to catch
regressions and guide optimization, not to justify weakening invariants.

---

## 2. Goals

1. Measure handshake latency, record throughput, allocation behavior, and queue
   high-water marks.
2. Detect regressions caused by parser changes, proof-friendly data structures,
   FFI wrapping, or interpreter loops.
3. Keep optimization subordinate to security and proof correspondence.
4. Establish realistic targets before jemmet production use.

---

## 3. Benchmark classes

### 3.1 Pure core microbenchmarks

- parser throughput for ClientHello and records;
- state-machine step overhead;
- transcript update overhead with fake hash;
- record fragmentation decisions;
- bounded queue operations.

### 3.2 Crypto provider benchmarks

- AEAD seal/open for 1 byte, 1 KiB, 16 KiB;
- HKDF extract/expand;
- X25519 operation;
- CertificateVerify signing;
- Finished verification.

### 3.3 Integration benchmarks

- full handshake over fake transport;
- full handshake over loopback iotakt;
- application data echo throughput;
- partial-write heavy workload;
- many idle handshakes with timeouts.

---

## 4. Memory metrics

Track:

1. peak inbound reassembly bytes;
2. peak pending ciphertext bytes;
3. pending plaintext record count;
4. number of secret handles per connection;
5. allocation count per handshake where measurable;
6. retained memory after terminal close.

---

## 5. Optimization rules

Allowed optimizations:

- reduce copies where ownership remains clear;
- compact pending ciphertext queues;
- preallocate bounded buffers from validated limits;
- specialize parser hot paths after preserving bounds checks.

Forbidden optimizations:

- bypass core `step` decisions in interpreter;
- log or expose secret data for debugging performance;
- change write semantics from plaintext consumption;
- retain raw pointers across FFI calls;
- skip transcript exact-byte binding.

---

## 6. Benchmark reporting

Benchmark outputs should be stored as developer artifacts, not public security
claims. Suggested report fields:

- git revision;
- Lean/toolchain version;
- HACL*/EverCrypt build source;
- CPU and OS;
- profile/feature flags;
- median/p95/p99 for relevant latency tests;
- allocation/queue high-water marks.

---

## 7. Acceptance criteria

1. Pure parser and record microbenchmarks exist before v0.2.
2. Crypto provider KATs are accompanied by basic performance smoke tests.
3. v0.3 includes loopback handshake and data throughput measurements.
4. Terminal close benchmark confirms no growing retained queues across repeated
   connections.
5. Performance docs explicitly state that security/proof invariants outrank
   optimization.
