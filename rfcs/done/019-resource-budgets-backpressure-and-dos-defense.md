# RFC 019 — Resource Budgets, Backpressure, and DoS Defense

**Project.** kroopt  
**Status.** Implemented (0.24.0-dev)  
**Type.** Implementation RFC  
**Target milestone.** v0.1 (fake); v0.3 (network)  
**Depends on.** RFC 003, RFC 004, RFC 010, RFC 013, RFC 014, RFC 017  
**Touches.** `Kroopt/Core/State.lean` (`BudgetState`); `Kroopt/Conn/` progress loop; `Kroopt/Config.lean`  
**Canonical source.** kroopt fixed requirements and external design.  

---

## 1. Summary

This RFC defines kroopt's resource-budget model. A TLS edge component is exposed
to adversarial byte streams and slow peers. Correct cryptography is not enough:
kroopt must bound memory, CPU, handshake duration, pending writes, parser work,
and error-path behavior.

---

## 2. Budget categories

| Budget | Scope | Default policy | Failure |
|---|---|---|---|
| Handshake wall-clock timeout | connection | finite, deployment-tunable | fatal handshake timeout |
| Handshake byte budget | connection | finite cap for all handshake bytes | fatal decode_error or internal budget error |
| Record fragment size | record | TLS limit 2^14 plaintext | fatal record_overflow |
| Ciphertext expansion | record | AEAD overhead bound | fatal record_overflow |
| Extension count | ClientHello | finite cap | fatal illegal_parameter/decode_error |
| Extension total bytes | ClientHello | finite cap | fatal decode_error |
| Pending ciphertext queue | connection | finite cap | `wouldBlock` / backpressure |
| Pending plaintext read queue | connection | at most one record by design | pause reads / backpressure |
| Pending crypto operations | connection | finite, usually one or small fixed number | internal error/fatal |
| would-block retries | progress cycle | bounded progress loop | return `wouldBlock` |
| Connections | listener/process | owned outside kroopt but kroopt exposes per-conn memory estimate | accept throttling by caller |

---

## 3. Configuration surface

Illustrative public config:

```lean
structure ResourceLimits where
  maxHandshakeBytes : Nat
  maxClientHelloBytes : Nat
  maxExtensions : Nat
  maxExtensionBytes : Nat
  maxPlaintextFragment : Nat
  maxPendingCiphertext : Nat
  maxPendingPlaintextRecords : Nat
  maxPendingCryptoOps : Nat
  handshakeTimeoutMs : UInt64
  idleTimeoutMs : Option UInt64
  maxProgressStepsPerCall : Nat
```

Rules:

1. Defaults must be safe enough for internet-edge use.
2. Invalid or dangerously low/high values fail config validation.
3. The public API must allow deployment-specific tightening.
4. Resource errors are typed and redacted.

---

## 4. Backpressure model

### 4.1 Outbound

`send` may consume plaintext only if the resulting pending ciphertext can fit
within `maxPendingCiphertext` after encryption/framing. Otherwise it returns
`wouldBlock` with zero consumption.

Partial consumption is allowed only at record boundaries or well-defined byte
counts that jemmet can safely handle. The recommended v0.1 policy is:

1. split application plaintext into TLS-fragment-sized chunks;
2. consume at most the chunks that can fit in the queue;
3. return `wrote n` for the consumed prefix;
4. require `flush/progress` before more data is accepted.

### 4.2 Inbound

If a plaintext record is already waiting for jemmet, kroopt may stop reading more
transport bytes until jemmet consumes it. This prevents hidden application
buffering beneath jemmet.

### 4.3 Crypto operations

The core tracks pending crypto operation ids. If the pending-op budget is full,
`step` must not emit another crypto action. Because TLS 1.3 server handshake is
mostly sequential in the chosen no-HRR/no-post-handshake scope, the normal budget
should remain very small.

---

## 5. Progress loop

The interpreter's progress function must be finite:

```text
for i in 0 .. maxProgressStepsPerCall:
  execute next pending output action
  feed result back into core
  stop on wouldBlock, emitted plaintext, terminal state, or no actions
return ProgressResult
```

It must not loop forever on a peer that alternates readiness hints and
would-block results. Readiness is only a hint.

---

## 6. DoS scenarios and controls

| Scenario | Control |
|---|---|
| Slow ClientHello | handshake timeout |
| Infinite fragmentation | handshake byte budget + timeout |
| Oversized vector length | parser bound before allocation |
| Many duplicate extensions | extension count cap + duplicate rejection |
| Large pending application writes | ciphertext queue cap + zero-consumption wouldBlock |
| Bad Finished CPU burn | bounded state machine + fail once |
| Repeated fatal alerts | terminal state; no repeated alert loop |
| Many idle TLS connections | idle timeout exposed to caller |
| Fuzzer-discovered parser deep path | parser complexity review + corpus regression |

---

## 7. Internal accounting

Each connection maintains approximate counters:

```lean
structure BudgetState where
  handshakeBytesSeen : Nat
  clientHelloBytesSeen : Nat
  extensionsSeen : Nat
  pendingCiphertextBytes : Nat
  pendingPlaintextRecords : Nat
  pendingCryptoOps : Nat
  progressStepsThisCall : Nat
```

Counters are updated before allocation when possible. On overflow of `Nat` is not
an issue in Lean semantics, but conversion to native sizes at FFI boundaries must
be checked.

---

## 8. Tests

1. Oversized record is rejected before AEAD call.
2. Oversized ClientHello is rejected before large allocation.
3. Duplicate extensions fail deterministically.
4. Pending ciphertext cap forces `wouldBlock` with zero additional plaintext
   consumption.
5. Progress loop terminates when fake iotakt repeatedly returns would-block.
6. Terminal failure releases pending queues.
7. Fuzz tests include budget-boundary values: limit-1, limit, limit+1.

---

## 9. Acceptance criteria

1. All public resource limits are represented in validated configuration.
2. All parser allocations are preceded by a budget check.
3. The interpreter has a finite progress-step limit.
4. Backpressure semantics are documented in the public `TlsConn` API.
5. CI includes negative tests for all budget failures.
