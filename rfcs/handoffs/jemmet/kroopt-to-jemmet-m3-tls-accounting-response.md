# kroopt → jemmet: M3 TLS accounting and sizing response

**Date.** 2026-07-14  
**Subject.** RFC 055 / AR-I TLS accounting, sizing, and progress contract  
**Candidate revision.** Pending  
**Target release.** `0.126.0`  
**Readiness scope.** Additive jemmet integration contract; no production/stable promotion  
**Overall status.** Pending release evidence

## 1. Accepted inbound ownership definition

```lean
structure InboundOwnership where
  recordReassembly       : Nat
  handshakeReassembly    : Nat
  authenticatedPlaintext : Nat
  retainedHandshake      : Nat

def TlsConn.inboundOwnership (c : TlsConn τ) : InboundOwnership
def TlsConn.ownedInboundBytes (c : TlsConn τ) : Nat
```

The scalar is the sum of the structure. Units are conservative logical retained-byte charges from live
`ByteArray.size` values, not allocated capacity or lifetime traffic. Duplicate retained representations are
charged separately. The charge covers partial records, handshake reassembly, core/interpreter authenticated
plaintext, read-direction transcript bytes, retained SNI/key-share/session-id/ALPN bytes, and pending client
Finished bytes. It excludes `τ` staging.

When `recv` returns `.bytes b`, the returned `TlsConn` has released that interpreter plaintext value; jemmet
then owns `b` and charges any `plainCarry`. Other retained handshake representations may keep the scalar
nonzero. Terminal state continues to report retained ownership truthfully until the value is cleaned up or
released.

## 2. Accepted record expansion and admission API

```lean
def protectedRecordBytesForPlaintext
  (suite : CipherSuite) (plaintextBytes : Nat) : Option Nat

def maxPlaintextForProtectedBudget
  (suite : CipherSuite) (ciphertextBudget : Nat) : Nat
```

The expansion includes header, inner content type, and the selected suite's tag. Zero plaintext is the
no-record case (`some 0`); above `maxPlaintextFragment` is `none`. `TlsConn.send` consumes the same budget
function. Connected empty input returns state-preserving `.wrote 0`. `.wouldBlock` consumes zero; jemmet may
retry unchanged. Kroopt remains authoritative and may accept only a fitting prefix.

## 3. Accepted server-flight and terminal-control bounds

```lean
def ValidatedServerConfig.maxServerFlightCiphertextBytes
  (cfg : ValidatedServerConfig) : Nat

def ValidatedServerConfig.maxTerminalControlCiphertextBytes
  (cfg : ValidatedServerConfig) : Nat
```

The current flight bound is one maximum plaintext ServerHello record plus four maximum protected records
(EncryptedExtensions, Certificate, CertificateVerify, Finished). It is conservative for all current validated
configurations. RFC 050 must revise the derivation if certificate fragmentation adds records.

The terminal bound is 24 bytes, covering protected fatal alert and `close_notify`; it dominates the seven-byte
plaintext fatal alert. Terminal control uses a separate one-record reserve and may temporarily take aggregate
egress above the application `maxPendingCiphertextBytes` cap by that reserve.

## 4. Writable progress and recommended jemmet mapping

```lean
def TlsConn.needsTransportWrite (c : TlsConn τ) : Bool :=
  c.ownedOutboundBytes > 0
```

Keep `ConnProgress.needsWrite == (ConnProgress.ownedOutBytes > 0)`, where owned output is kroopt-owned plus
jemmet-staged ciphertext. On writable readiness, drain jemmet staging through real `sendAck`, then call
`TlsConn.flush` to refill staging; disable native write interest only when the aggregate is zero.
`RuntimeState.writeInterest` is internal and not equivalent to pending output. A bare
`.transportWritable` progress event does not flush or create useful work while both tiers are empty.
Read/timer/immediate-work classification remains separate and can expand under RFC 047.

## 5. Outbound transfer and discard conservation

- Transfer from `rt.outbound` to `τ.outbound` is ownership transfer, not peer delivery.
- The aggregate is constant across full or partial staging transfer; the exact unsent suffix remains ordered.
- Transport `wouldBlock` transfers zero.
- Only real socket acceptance reduces aggregate owned ciphertext.
- Kroopt terminalization does not clear `rt.outbound`.
- Jemmet owns staging teardown. Any graceful/fatal/abortive close that drops it must record the exact dropped
  staging length as an explicit adapter-owned discard before releasing the slot.

## 6. Exact test and gate additions

`Tests/Conn.lean` covers all supported suites at zero, one byte, fragment maximum, and over maximum; public
sizing versus actual `send` ciphertext; connected empty-send neutrality; each inbound retention tier; `recv`
ownership transfer; terminal retention; kroopt write need; partial/would-block conservation; current flight
coverage; terminal reserve; and terminalization without silent discard.

`Tests/IotaktBinding.lean` freezes the common aggregate `needsWrite` mapping for kroopt-owned, staged, and
empty states and documents staged-first draining followed by `TlsConn.flush`. Existing close, record,
interpreter, and release gates remain applicable; RFC 055 adds no new canonical gate id.

## 7. Target release and verification evidence

Target release is `0.126.0`. Exact commit, source archive SHA-256 and byte count, sidecar SHA-256, GATE-RUN
SHA-256, and clean exact-revision CI evidence are Pending. Jemmet must not pin the working tree or treat this
handoff as released until this section is updated from the published release artifacts.

Migration from `0.124.1` is additive at the source API level. The one intentional behavior correction is that
connected zero-length `send` no longer queues an empty record or returns backpressure. These observational and
sizing APIs do not alter proved core protocol decisions or promote kroopt's trust/readiness claims.

## 8. Corrected jemmet assumptions

1. `ownedInboundBytes == 0` means no charged inbound-origin representation remains, not merely no currently
   deliverable/reassembly queue; retained transcript and parsed ClientHello fields are charged too.
2. Cumulative `handshakeBytesSeen` is not current ownership and must not feed the connection ingress sum.
3. The application cap alone is not the aggregate slot reserve; admit the server-flight reserve and retain a
   separate terminal-control reserve.
4. `transportWritable`/`RuntimeState.writeInterest` is not a command to generate output with empty ownership;
   staged-first drain plus `flush` is the useful progress sequence.
5. A `Transport.send` success transfers ownership into jemmet staging; it is not socket delivery.

## Acceptance ledger

| Item | Status | Candidate-specific evidence | Remaining work |
|---|---|---|---|
| Public API and behavior | Done | `Kroopt/Core/Config.lean`, `Kroopt/Conn/TlsConn.lean`; `lake build` observed green on dirty tree | Review and commit |
| Focused connection tests | Done | `lake exe kroopt-conn-test`: 41/41 passed on dirty tree | Clean exact-revision evidence pending |
| Iotakt translation tests | Done | `lake exe kroopt-iotaktbinding-test`: 30/30 passed on dirty tree | Clean exact-revision evidence pending |
| Documentation | Done | architecture/accounting, interpreter, resource-budget, roadmap, changelog pages; `mdbook build docs` passed | Clean exact-revision evidence pending |
| Canonical full-release gate | Pending | Dirty development tree passed 42/42; `gate-out/gate-ledger.json` and `gate-out/GATE-RUN.md`, timestamp `2026-07-14T01:22:38Z` | Rerun on clean exact revision and in CI |
| Published `0.126.0` provenance | Pending | No release artifacts yet | Commit, CI, release, and transcribe exact evidence |

## Commands observed

| Command | Result | Evidence location |
|---|---|---|
| `lake build` | Passed, dirty working tree | Current development thread |
| `lake exe kroopt-conn-test` | Passed 41/41, dirty working tree | Current development thread |
| `lake exe kroopt-iotaktbinding-test` | Passed 30/30, dirty working tree | Current development thread |
| `mdbook build docs` | Passed, dirty working tree | Current development thread; generated output removed |
| `PATH="$PWD/.git-exclude/venv-gate/bin:$PATH" bash scripts/gate.sh --profile full-release` | Passed 42/42, dirty working tree | `gate-out/gate-ledger.json`, `gate-out/GATE-RUN.md` |

## Risks and follow-up

- RFC 048 can harden validated construction without changing these method meanings.
- RFC 050 must update the flight-bound derivation and covering test when it introduces certificate
  fragmentation.
- RFC 047 owns future read/timer/immediate-work classification; it must preserve the aggregate write invariant.
