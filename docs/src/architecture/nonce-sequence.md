# Nonce, sequence, and key separation

AEAD nonce reuse is catastrophic — reusing a `(key, nonce)` pair breaks
confidentiality and integrity outright. RFC 005 therefore treats the sequence
and nonce logic as a first-class proof target, not a tested convention.

## Sequence numbers

Each direction (read / write) carries its own `SeqNo` (a `UInt64`), reset to zero
on epoch installation. Incrementing is overflow-checked by construction:

```lean
def SeqNo.next (s : SeqNo) : Option SeqNo :=
  let v := s.value + 1
  if v = 0 then none else some ⟨v⟩
```

Two facts are proved about it: a successful increment is exactly `+1`
(`next_some_succ`), and `next` returns `none` *only* at the ceiling
(`next_none_overflow`) — so a wrapped value is never produced. Over the record
path this lifts to:

- `seal_step_either_registers_and_advances_or_fails_closed` (with derived
  `successful_registered_seal_increments_write_seq` /
  `budget_failed_seal_does_not_advance_write_seq`) and
  `successful_open_increments_read_seq` — a *registered* record crypto operation
  reserves the current sequence number and advances that direction's sequence by
  exactly one; if crypto-op allocation fails (RFC 037 §4.1) no op is registered,
  no plaintext crosses the boundary, and the connection fails closed without
  advancing the sequence;
- `no_crypto_on_write_seq_overflow` — at the ceiling, a send requests *no* crypto
  and fails, so no seal is ever emitted with a wrapped sequence (**no silent
  wrap**).

## Nonces

The concrete TLS 1.3 per-record nonce is `iv_base XOR left_pad(seq)`
(`nonceBytes`). For a *fixed* IV base this map is a bijection in the sequence, so
distinct sequences give distinct nonces. The uniqueness theorem
(`nonce_unique_within_epoch`) is proved over `deriveNonce`, which models the
nonce as the public IV-base identity plus the sequence value — exactly the data
the security argument needs. RFC 005 §5 sanctions representing the IV base
abstractly; the concrete byte realization is exercised by known-answer tests at
M6.

## Key and epoch separation

A read operation must use only read keys and a write operation only write keys;
handshake records use handshake-epoch keys and application records
application-epoch keys. Structurally, the only seal request carries `writeMeta`
(write direction, application epoch) and the only open request carries `readMeta`
(read direction, application epoch):

- `aeadSeal_uses_write_keys` — every emitted seal op carries write-direction,
  application-epoch metadata;
- `aeadOpen_uses_read_keys` — every emitted open op carries read-direction,
  application-epoch metadata.

Handshake-epoch operations arrive with the handshake model (M4); KeyUpdate is a
non-goal, so application keys are never rotated in the initial release line.
