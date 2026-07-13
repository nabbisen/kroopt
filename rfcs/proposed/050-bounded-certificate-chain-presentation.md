# RFC 050 — Bounded Certificate-Chain Presentation

**Project.** kroopt  
**Status.** Proposed  
**Type.** Blocking functional/wire-model fix  
**Target milestone.** AR2  
**Requires completion of.** [RFC 012](../done/012-server-certificate-key-presentation.md) (presentation), [RFC 032](../done/032-typed-flight-assembly-contract.md) (typed flight)  
**Coordinates with.** [RFC 026](026-compatibility-interop-and-negative-matrix.md) for the broader interop matrix  
**Touches.** config/cert types, Certificate serialization, limits, provisioning and interop tests  

## Review finding

Architecture review B8 found that a configured chain is one opaque DER `ByteArray` serialized as one TLS
`CertificateEntry`. A leaf and intermediates therefore cannot be represented as distinct ordered entries.

## Decision

A server certificate chain is a non-empty bounded ordered list of DER certificates. The first entry is the
leaf; following entries are intermediates in configured transmission order. Each entry has its own bounded
extension vector (empty in the initial implementation), and total chain bytes are validated before listener
construction.

Server mode still performs presentation/config lint only; it does not validate a peer chain or act as a CA.

## Work breakdown

1. Replace the single DER field with a bounded non-empty chain type.
2. Preserve leaf metadata/key compatibility checks against entry zero.
3. Serialize one TLS `CertificateEntry` per configured certificate with correct nested lengths.
4. Bind the transcript to the exact serialized Certificate message.
5. Add per-entry and total-chain resource limits and overflow-safe framing.
6. Update provisioning APIs and examples without making secret keys part of the chain value.
7. Add leaf-only, leaf+intermediate, oversize, empty, reordered, and malformed-DER lint tests.

## Acceptance criteria

1. A leaf plus intermediate is emitted as two ordered TLS Certificate entries.
2. OpenSSL/curl verifies the presented test chain against a supplied test trust anchor.
3. Empty/oversize chains fail at validation before a connection exists.
4. CertificateVerify uses the leaf-compatible configured key and the exact transcript.
5. Logs/traces expose ids/lengths only, never raw DER by default.
6. Requirements, external API docs, trust matrix, and canonical interop gate are updated.

## Non-goals

Peer path validation, hostname verification, revocation, trust-store policy, issuance, and ACME remain future
client/mTLS or operational work.
