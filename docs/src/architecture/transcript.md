# Transcript model

TLS 1.3 security depends on hashing the **exact ordered handshake bytes**. A
fatal class of bugs comes from parsing a message, reconstructing it later, and
assuming the reconstruction is transcript-equivalent — extension reordering,
padding, or DER differences then make the verification transcript diverge from
the peer's. RFC 007 forbids this: parsed values must be bound to the exact bytes
consumed, and generated messages enter the transcript from their framed bytes.

## Binding discipline

The transcript is modeled (RFC 007 §9.1, the proof-friendly option) as an ordered
log of committed events, each holding the **exact wire bytes** plus non-secret
metadata (kind, direction, length). The append functions take only a
`ByteArray`; a structured value alone is never sufficient. Parser output is
carried in a `WireBound`, whose `wireBytes` are the exact consumed slice — and
`appendParsed` commits those, never a re-serialization.

Proven facts:

- `appendFramed_binds_exact_bytes` / `appendParsed_uses_wire_bytes` — the
  committed bytes are exactly the framed / consumed bytes, verbatim;
- `appendFramed_preserves_order` / `appendFramed_increments_count` — events are
  appended in order, one message at a time;
- `snapshot_eventCount` / `snapshot_then_append_is_before` — a snapshot covers
  exactly the committed prefix, so a Finished or CertificateVerify input built
  from a snapshot taken *before* appending message M covers up to but not
  including M (RFC 007 §8).

## Snapshots and crypto correlation

A `TranscriptSnapshot` pins a transcript-bound crypto operation (Finished,
CertificateVerify) to the exact committed prefix it was computed over. The
snapshot counter advances monotonically, so a result produced for an older
snapshot is stale and rejected. The running hash itself is a provider action —
the proofs cover event order and exact-byte binding; the digest value is
provider-backed and checked by correspondence tests.
