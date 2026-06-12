# RFC 018 — Data Classification and Lifecycle

**Project.** kroopt  
**Status.** Implemented (0.24.0-dev)  
**Type.** Implementation RFC  
**Target milestone.** M0–v0.2  
**Depends on.** RFC 002, RFC 004, RFC 005, RFC 008, RFC 009, RFC 010, RFC 012  
**Touches.** `docs/src/` data-classification notes; secret-bearing types across `Kroopt/`  
**Canonical source.** kroopt fixed requirements and external design.  

---

## 1. Summary

This RFC defines kroopt's data classes, ownership rules, lifecycle states, copy
permissions, logging permissions, and destruction responsibilities. TLS is not
only a state machine; it is also a disciplined flow of bytes, secrets, derived
keys, transcript material, authenticated plaintext, pending ciphertext, and
configuration snapshots. The goal is to make these flows explicit enough for
implementation, security review, and future proof obligations.

---

## 2. Data classes

| Class | Examples | May log? | May serialize? | Owner | Lifetime |
|---|---|---:|---:|---|---|
| Public config | protocol versions, ALPN names, size limits | yes, sanitized | yes | config snapshot | process/config epoch |
| Public peer input | raw record header, SNI string after validation | limited | limited | parser/core | connection |
| Attacker-controlled bytes | unparsed transport bytes, malformed extension data | no raw blob | no | input buffer | until parsed/rejected |
| Authenticated plaintext | HTTP bytes after successful AEAD open | no by kroopt | caller-owned after emission | kroopt then jemmet | record/caller |
| Pending ciphertext | encrypted records waiting for iotakt send | size only | no | interpreter | until flushed/failed |
| Transcript bytes/hash | handshake message bytes and digest state | no raw unless test-only | no | core | handshake |
| Traffic secret/key | read/write AEAD keys, IV bases | never | never | secret arena | epoch/connection |
| Private key | server signing key | never | never | secret arena/provider | config snapshot |
| Crypto op token | pending op id, expected phase/direction | yes id only | no | core/interpreter | until result consumed |
| Error classification | public error category, alert description | yes, redacted | yes | kroopt/jemmet | event |

---

## 3. Ownership model

### 3.1 Public configuration

A validated configuration is immutable. A running `TlsConn` holds a reference to
one configuration snapshot and does not observe later mutation. Config reloads
create a new snapshot; old connections continue with their old snapshot.

### 3.2 Transport input bytes

Transport bytes are owned by the interpreter until converted into an
`InputEvent.transportBytes`. After the core accepts them into parser state, they
are owned by the core state. No parser may create a slice pointing into mutable
transport memory unless the lifetime is statically confined to the parse call.

### 3.3 Plaintext

Inbound plaintext is not caller-visible until authenticated and state-legal.
After `emitPlaintext`, jemmet owns the returned `ByteArray`. kroopt may retain no
reference to caller-visible plaintext except within a bounded read result queue.

Outbound plaintext passed to `send` is consumed according to the public API:
`wrote n` means kroopt owns the first `n` plaintext bytes; `wouldBlock` means it
owns zero. After ownership transfer, jemmet must not resend consumed bytes.

### 3.4 Ciphertext queues

Ciphertext queues are interpreter-owned. They are bounded by config limits and
connection state. Partial writes advance a cursor; sent bytes are dropped or
compacted by policy.

### 3.5 Secrets

Long-lived secrets are referenced by opaque `SecretKeyHandle`. The Lean side does
not derive `Repr`, `ToString`, `BEq`, `Hashable`, or serialization instances for
secret-bearing types. Secret handles include kind, epoch, direction, and config
or connection scope.

---

## 4. Lifecycle diagrams

### 4.1 Inbound application data

```text
transport bytes
  → bounded record reassembly
  → TLSCiphertext parse
  → AEAD open request
  → cryptoResult authenticated plaintext
  → TLSInnerPlaintext validation
  → state check: connected only
  → emitPlaintext to jemmet
  → kroopt drops internal plaintext buffer
```

### 4.2 Outbound application data

```text
jemmet ByteArray
  → TlsConn.send
  → consume 0 or n plaintext bytes
  → split into record-sized chunks
  → seal request with write epoch + sequence
  → pending ciphertext queue
  → iotakt send partial/full
  → drop flushed ciphertext
```

### 4.3 Secret material

```text
config load/private key import
  → C-owned secret arena allocation
  → SecretKeyHandle stored in config snapshot
  → CertificateVerify signing operation references handle
  → old config snapshot retires after last connection
  → explicit provider free + best-effort zeroize
```

Traffic secrets:

```text
ECDHE result / HKDF output
  → traffic secret handle
  → derived key/iv handles by epoch+direction
  → record seal/open operations reference handles
  → close/fatal/config retirement
  → explicit zeroize/free
```

---

## 5. Data invariants

1. Unauthenticated bytes never become `AuthenticatedPlaintext`.
2. Secret handles are never embedded in public errors or logs.
3. Transcript updates use exact wire bytes, not reserialized ASTs.
4. A ciphertext record is associated with exactly one epoch and direction.
5. Pending crypto results must match a live operation id and expected state.
6. A connection owns at most the configured maximum pending plaintext and
   ciphertext bytes.
7. A config snapshot cannot be partially visible: it is validated before use.
8. Terminal connections release secret handles and pending queues.

---

## 6. Internal design types

Illustrative wrappers:

```lean
structure RedactedString where
  value : String

structure BoundedBytes (limit : Nat) where
  bytes : ByteArray
  proof_len : bytes.size <= limit

structure AuthenticatedPlaintext where
  bytes : ByteArray
  sourceEpoch : Epoch
  seq : UInt64

structure PendingCryptoOp where
  id : CryptoOpId
  expectedPhase : HandshakeState
  expectedDirection : Option Direction
  op : CryptoOp
```

The exact implementation may differ, but equivalent type-level or constructor
private enforcement is required.

---

## 7. Logging permissions

Allowed:

- connection id or internal trace id;
- alert description;
- public TLS version/cipher suite after validation;
- ALPN protocol after validation;
- SNI after normalization and escaping, subject to deployment policy;
- byte counts and duration buckets.

Forbidden:

- private key material;
- traffic secrets;
- raw ClientHello blob;
- raw certificate private key path if considered sensitive by deployment policy;
- plaintext application data;
- AEAD nonces combined with key identifiers in a way that aids correlation.

---

## 8. Acceptance criteria

1. `SecretKeyHandle` and secret-bearing records have no printable/serializable
   derived instances.
2. Config snapshots are immutable and reference-counted or otherwise safely held
   by active connections.
3. Inbound and outbound data lifecycle tests show bounded retention.
4. Terminal-state tests verify queue release and secret-handle release calls.
5. Logging tests assert forbidden data does not appear in representative events.
6. The external design's data model is synchronized with this RFC.
