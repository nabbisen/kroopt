# TLS accounting, sizing, and progress

RFC 055 defines the public resource contract used by a staged non-blocking
consumer such as jemmet. The values below are logical byte charges based on live
`ByteArray.size` values. They are neither allocated-capacity measurements nor
lifetime traffic counters.

## Inbound ownership

`TlsConn.inboundOwnership` reports four independently useful charges:

| Field | Retained data charged |
|---|---|
| `recordReassembly` | partial TLS record ciphertext |
| `handshakeReassembly` | partial/coalesced handshake-message bytes |
| `authenticatedPlaintext` | core and interpreter plaintext waiting for `recv` |
| `retainedHandshake` | read-direction transcript bytes, retained ClientHello-derived fields, and pending client Finished bytes |

`TlsConn.ownedInboundBytes` is their sum. Duplicate representations are charged
separately on purpose, making this a conservative logical resource charge.
Consumer-owned transport staging is excluded and must be added once by the
consumer.

When `recv` returns `.bytes b`, the returned `TlsConn` no longer owns that
authenticated-plaintext value. The consumer owns `b` and must charge any suffix
kept in its own carry buffer. Other handshake-derived retention can keep
`ownedInboundBytes` nonzero. Clean close, EOF, and fatal state do not falsify the
accessor: retained bytes remain charged until state cleanup or release.

## Protected-record sizing

`protectedRecordBytesForPlaintext suite n` returns the exact unpadded wire size
for one application record, `none` above `maxPlaintextFragment`, and `some 0` for
the zero-length no-record case. `maxPlaintextForProtectedBudget suite budget`
returns the largest one-record plaintext prefix that fits, or zero when no
nonempty record fits. Both include the five-byte header, inner content-type byte,
and suite AEAD tag.

`TlsConn.send` uses the same budget function. A connected zero-length send is a
state-preserving `.wrote 0`. Every `.wouldBlock` consumes zero; a consumer may
retry the same bytes. Kroopt may still accept a smaller prefix because its own
queue is authoritative.

## Egress reserves and progress

`ValidatedServerConfig.maxServerFlightCiphertextBytes` is a conservative bound
for the current one-record ServerHello plus four protected server-flight records.
It deliberately uses protocol record maxima. RFC 050 must revise the derivation
if certificate fragmentation adds records.

`ValidatedServerConfig.maxTerminalControlCiphertextBytes` is the largest current
one-record terminal-control output: 24 bytes. Terminal control is separate from
the application `maxPendingCiphertextBytes` cap, so the aggregate may temporarily
reach the application cap plus this reserve.

`TlsConn.needsTransportWrite` means kroopt owns ciphertext that `flush` can
transfer. A staged adapter keeps write readiness enabled exactly while
`TlsConn.ownedOutboundBytes + stagedOutboundBytes > 0`: drain staged bytes into
the real socket first, then call `flush` to refill staging. The internal
`RuntimeState.writeInterest` field is not this public contract, and a writable
`progress` event alone does not flush the queue.

Transfer from kroopt's outbound queue into consumer staging preserves aggregate
ownership and order. Partial acceptance retains the exact suffix; `wouldBlock`
transfers zero. Only real socket acceptance reduces the aggregate. Kroopt
terminalization retains its outbound queue. If an adapter discards its own staging
on teardown, it must account for that amount as an explicit adapter-owned discard.
