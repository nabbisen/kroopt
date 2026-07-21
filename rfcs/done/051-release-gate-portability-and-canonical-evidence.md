# RFC 051 — Release-Gate Portability and Canonical Evidence

**Project.** kroopt  
**Status.** Implemented (AR0; shipped `0.125.0`; `2984db0`, CI run `79277038502`)
**Type.** Blocking release/operations fix  
**Target milestone.** AR0  
**Requires completion of.** [RFC 022](022-proof-gates-ci-and-lean-hygiene.md) (proof gates), [RFC 030](030-production-readiness-and-release-runbook.md) (release runbook), [RFC 043](043-hacl-evercrypt-vendoring-and-provenance.md) (provenance)  
**Consumed by.** AR2/AR3 candidate validation and [RFC 052](../proposed/052-jemmet-iotakt-production-path-acceptance.md)  
**Touches.** native harness, CI matrix, gate registry, dependency setup, release evidence  

## Review finding

Architecture review B7 observed `full-release` fail 35/37: the sanitizer harness used an undeclared Lean
runtime initializer under GCC 16, and record interop lacked its declared Python dependency. The review also
found release-critical checks and the iotakt binding reference outside the canonical gate.

## Decision

The canonical release gate is reproducible from a declared supported environment. Setup dependencies,
compiler/runtime compatibility, gate membership, and evidence retention are versioned policy. A release claim
refers only to candidate-specific observed output from that exact gate registry.

This RFC owns the AR0 portability repairs, registry mechanism, no-placeholder entry, and iotakt binding
contract entry. It transitions to Implemented when those mechanisms and the AR0 clean-environment ledger meet
the acceptance criteria below. AR2 and AR3 consume the implemented gate and retain new candidate ledgers as
milestone/release evidence; those recurring runs do not keep or reopen this RFC.
[RFC 052](../proposed/052-jemmet-iotakt-production-path-acceptance.md) owns downstream E2E
but only consumes the binding entry registered here.

## Work breakdown

1. Replace the undeclared runtime initializer with a supported Lean runtime API or supported harness setup.
2. Declare and provision compiler, OpenSSL/curl, Python, and `cryptography` versions/ranges.
3. Test at least the release compiler plus the newest supported compiler (including GCC 16 compatibility).
4. Register `check-no-placeholder.sh` if the no-placeholder claim remains release-critical.
5. Add a Lake executable/canonical gate entry for `Tests/IotaktBinding.lean` as a contract reference.
6. Define the registry-extension rule used as the [AR remediation RFCs](../README.md#proposed--architecture-review-remediation-schedule)
   land; prohibit unregistered release evidence.
7. Preserve per-gate logs/hashes and clean-tree provenance through packaging and release verification.

## Acceptance criteria

1. A clean documented environment can install prerequisites and run the gate without manual repair.
2. Sanitizer and record-interop gates pass on the supported release toolchain.
3. Gate self-tests prove nonzero exits, missing dependencies, missing gate ids, and stale registries fail.
4. All release-critical proof, parser, placeholder, native, interop, and binding checks are registered.
5. The AR0 candidate retains a 100%-passing ledger and human summary; the roadmap separately requires fresh
   ledgers when AR2 and AR3 consume the gate.
6. No handoff or release document reports a pass not observed for its exact revision.

## Non-goals

This RFC does not itself fix protocol behavior. Online HACL upstream re-verification remains an explicit
on-demand trust-tier operation, not a network-dependent every-PR gate.

## Implementation evidence

AR0 implementation commit `2984db0cc93b341fd0bf4b038d34fde68425ba82` produced a clean local
`kroopt-gate/v3` ledger with all 42 `full-release` gates passing on 2026-07-14 JST. GitHub Actions run
[`79277038502`](https://github.com/nabbisen/kroopt/actions/runs/79277038502) checked out that exact commit and
observed:

- the canonical `full-release` profile passing 42/42;
- release-machinery pass-detection, dependency, registry-drift, ledger, and provenance negative controls
  passing;
- the sanitizer harness compiling and passing cleanly under GCC 12.5.0 and GCC 16.1.0 with Lean 4.15.0.

AR2 and AR3 must retain fresh candidate ledgers when they consume this gate; those runs do not reopen this
RFC.
