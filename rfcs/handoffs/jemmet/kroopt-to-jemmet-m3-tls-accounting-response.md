# kroopt → jemmet: M3 TLS accounting and sizing response

**Date.** 2026-07-14
**Subject.** RFC 055 / AR-I TLS accounting, sizing, and progress contract
**Candidate revision.** `cfda89310c040ef893e67c0c46e2889c140326eb`
**Target release.** `0.126.0`
**Release-candidate revision.** `877e54d1ce3a45ca88030052b7dedea99358ea56`
**Readiness scope.** Additive jemmet integration contract; no production/stable promotion
**Overall status.** Done — published as `0.126.0` with immutable provenance

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

Release `0.126.0` contains the implementation from exact commit
`cfda89310c040ef893e67c0c46e2889c140326eb`. GitHub Actions run
[`29298648079`](https://github.com/nabbisen/kroopt/actions/runs/29298648079) checked out that commit and passed
the canonical `full-release` profile 42/42, release-machinery regression tests, and dedicated GCC 12.5.0 and
GCC 16.1.0 ASan/UBSan jobs. The retained gate artifact is `8297742336`; GitHub reported artifact ZIP
SHA-256 `ae8938e7654df165f6b1b2d366329994c86657a59d860436e9dc5c8e9e1c377b`.

The annotated `0.126.0` tag peels to release commit
`877e54d1ce3a45ca88030052b7dedea99358ea56`. Tagged workflow run
[`29370919042`](https://github.com/nabbisen/kroopt/actions/runs/29370919042) checked out that exact commit,
passed the canonical `full-release` profile 42/42, all five release-machinery groups, and strict
`--require-release` verification, then published the non-draft, non-prerelease
[`0.126.0` release](https://github.com/nabbisen/kroopt/releases/tag/0.126.0) with exactly these assets:

| Asset | Bytes | SHA-256 |
|---|---:|---|
| `kroopt-0.126.0.tar.gz` | 824935 | `c311bf854f1bfc78426fbc47292fb5756cebe33c2f127b1d197487afef83c451` |
| `kroopt-0.126.0.release-verification.json` | 27739 | `ce621f26a828d0da97e6a834d38ee78f2f7d4b72b4b4a54d21b6e3889bf0e579` |
| `kroopt-0.126.0.GATE-RUN.md` | 2080 | `4f81a63b2bb89452b1362cfd584b8ad671f75d9aae7b45913e52549778a729e1` |

The retained release gate artifact is `8326067381`, with GitHub-reported ZIP SHA-256
`5ae9bbb2309fd71ef70b2f28e9de4189c14c65c9a68e5ef04de592b17a791b71`. Jemmet may now pin `0.126.0`
and the archive SHA-256 above.

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
| Public API and behavior | Done | Exact implementation commit `cfda89310c040ef893e67c0c46e2889c140326eb`; clean CI build/gate passed | None for implementation |
| Focused connection tests | Done | `suite:conn` passed inside the exact-revision canonical gate; local development run observed 41/41 | None for implementation |
| Iotakt translation tests | Done | `suite:iotaktbinding` passed inside the exact-revision canonical gate; local development run observed 30/30 | None for implementation |
| Documentation | Done | `docs`, `hygiene`, and `no-placeholder` passed in the exact-revision canonical gate | None for implementation |
| Canonical full-release gate | Done | Release run `29370919042`: exact `877e54d`, 42/42; artifact `8326067381` | Fresh evidence required only for later releases |
| GCC sanitizer matrix | Done | Lean 4.15.0 with GCC 12.5.0 and GCC 16.1.0: both dedicated ASan/UBSan harness jobs passed | None for implementation |
| Published `0.126.0` provenance | Done | Release run `29370919042`; exact commit and three immutable asset hashes recorded in §7 | Jemmet may pin the release/archive hash |

## Commands observed

| Command | Result | Evidence location |
|---|---|---|
| `lake build` | Passed, dirty working tree | Current development thread |
| `lake exe kroopt-conn-test` | Passed 41/41, dirty working tree | Current development thread |
| `lake exe kroopt-iotaktbinding-test` | Passed 30/30, dirty working tree | Current development thread |
| `mdbook build docs` | Passed, dirty working tree | Current development thread; generated output removed |
| `PATH="$PWD/.git-exclude/venv-gate/bin:$PATH" bash scripts/gate.sh --profile full-release` | Passed 42/42, dirty working tree | `gate-out/gate-ledger.json`, `gate-out/GATE-RUN.md` |
| CI `bash scripts/gate.sh --profile full-release` | Passed 42/42 on clean `cfda893` | Run `29298648079`, artifact `8297742336` |
| CI `bash scripts/sanitizer-check.sh` (GCC 12.5.0) | Passed under ASan/UBSan on clean `cfda893` | Run `29298648079` sanitizer job log |
| CI `bash scripts/sanitizer-check.sh` (GCC 16.1.0) | Passed under ASan/UBSan on clean `cfda893` | Run `29298648079` sanitizer job log |
| Tagged release workflow | Passed 42/42, five release-machinery groups, and strict real-release verification on exact `877e54d` | Run `29370919042`; retained artifact `8326067381`; published `0.126.0` assets |

## Risks and follow-up

- RFC 048 can harden validated construction without changing these method meanings.
- RFC 050 must update the flight-bound derivation and covering test when it introduces certificate
  fragmentation.
- RFC 047 owns future read/timer/immediate-work classification; it must preserve the aggregate write invariant.

## Release-preparation handoff

### Summary

RFC 055 and AR-I are complete and published in `0.126.0`. The annotated tag resolves to exact commit
`877e54d1ce3a45ca88030052b7dedea99358ea56`; clean implementation CI, sanitizer lanes, and the tagged
release workflow passed. This response is now a published jemmet pin.

### Scope followed

The work stayed within additive TLS accounting/sizing observability, one zero-length-send correction, tested
transport ownership semantics, and documentation. It added no iotakt dependency, TLS protocol decision,
listener-wide admission policy, or production/stable readiness claim.

### Files changed

- Public implementation and tests: `Kroopt/Core/Config.lean`, `Kroopt/Conn/TlsConn.lean`,
  `Tests/Conn.lean`, and `Tests/IotaktBinding.lean` in the implementation commit.
- Contract and evidence: RFC 055, this jemmet response, `ROADMAP.md`, `CHANGELOG.md`, `RELEASES.md`, the RFC
  index, and current-security documentation.
- Architecture guidance: the TLS accounting/sizing page plus interpreter and resource-budget updates.
- Release preparation: `scripts/check-provenance.sh` and `scripts/check-release-machinery.sh` correct and
  regression-test sidecar validation for the registered `no-placeholder` gate.

### Design decisions and assumptions

Inbound values are conservative live logical byte charges; consumer staging is excluded. Protected sizing is
suite-explicit. Terminal output has a separate 24-byte reserve. Native write readiness follows aggregate
owned ciphertext, with jemmet staging drained before `TlsConn.flush`. The published version is `0.126.0`.

### Tests and gates run

Local development evidence observed `lake build`, 41/41 connection checks, 30/30 iotakt-boundary checks,
mdBook, and a dirty-tree 42/42 full-release gate. Clean CI run `29298648079` then observed 42/42 at `cfda893`
plus passing GCC 12.5.0 and GCC 16.1.0 ASan/UBSan jobs.

The tagged release workflow additionally observed all five release-machinery groups, the canonical profile
42/42, and strict real-release provenance verification on exact release commit `877e54d`.

### Generated artifacts

Implementation CI retained gate artifact `8297742336`, with GitHub-reported artifact ZIP SHA-256
`ae8938e7654df165f6b1b2d366329994c86657a59d860436e9dc5c8e9e1c377b`. Release run `29370919042`
retained artifact `8326067381` (ZIP SHA-256
`5ae9bbb2309fd71ef70b2f28e9de4189c14c65c9a68e5ef04de592b17a791b71`) and published the three
immutable assets with the byte counts and hashes in §7. Those published hashes, not earlier local-dry-run
diagnostics, are the release evidence jemmet should pin.

### Known limitations

RFC 048, RFC 050, and RFC 047 retain the compatibility obligations stated above. Project production/stable
disposition remains NO-GO; publication of this additive integration contract does not close those findings.

### Recommended next step

Jemmet should pin `0.126.0` plus source-archive SHA-256
`c311bf854f1bfc78426fbc47292fb5756cebe33c2f127b1d197487afef83c451`, implement the documented
staging/accounting mapping, and retain the RFC 047/048/050 compatibility obligations in its adapter plan.
