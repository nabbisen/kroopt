# RFC 030 — Production Readiness and Release Runbook

**Project.** kroopt  
**Status.** Proposed  
**Type.** Implementation RFC  
**Target milestone.** v0.4 and every release after  
**Depends on.** RFC 020, RFC 022, RFC 026, RFC 028, RFC 029  
**Touches.** `docs/src/release-runbook.md`; release CI gates  
**Canonical source.** kroopt fixed requirements and external design.  

---

## 1. Summary

This RFC defines the release-readiness checklist for kroopt. A TLS layer can pass
unit tests yet still be unready for edge deployment if documentation, interop,
security review, proof inventory, fuzzing, and operational diagnostics are stale.
This runbook prevents that.

---

## 2. Release readiness checklist

A release candidate must have:

1. clean Lean build;
2. proof hygiene gate passing;
3. theorem inventory current;
4. proof/trust/test matrix current;
5. deterministic model tests passing;
6. parser and negative tests passing;
7. fuzz smoke tests passing;
8. native KATs passing if crypto provider is included;
9. sanitizer jobs passing for native shim;
10. OpenSSL/curl interop passing for network-enabled releases;
11. jemmet+iotakt E2E passing for integration releases;
12. documentation updated;
13. known limitations listed;
14. no release blockers from RFC 028.

---

## 3. Version-specific readiness

### 3.1 Core-only release

Requires proof/model/test readiness. Must clearly state that it is not a usable
TLS terminator.

### 3.2 Crypto-provider release

Requires KATs, sanitizer-clean shim, and secret-handle review.

### 3.3 Network interop release

Requires hostile-input negative matrix and resource-budget tests.

### 3.4 jemmet-facing release

Requires public API docs, progress-loop examples, ALPN/SNI docs, and E2E tests.

---

## 4. Release provenance and the stack manifest

This section is **design input only** until a provenance-bearing release is actually cut. It applies to the
future `jemmet-edge-runtime` stack manifest (the deployment closure where kroopt is a node), not to the
current `-dev` core/interop work. Captured from a jemmet note (against 0.114.0-dev) recording the henret
pattern and a concrete iotakt pitfall, so this lands right the first time.

**The pattern to follow (henret / henret RFC 096 is the model).** When the TLS path reaches a release that
needs verifiable provenance, publish, *as release-beside-tarball assets*:

- the canonical source archive, **files-at-root** (no parent directory) — kroopt's tarball recipe already
  produces this layout;
- the **henret RFC 096 sidecar** — `release-verification.json`, `manifest_schema 1` — carrying
  `source_archive` (name / sha256 / bytes), `lake_manifest_sha256`, `lean_toolchain_sha256`, the gate
  ledger, and a `dependencies` block. This exact schema is the target, not an example: jemmet's stack
  verifier is built around henret's RFC 096 sidecar (jemmet verified that chain end-to-end and marks henret
  `VERIFIED`). **Do not copy iotakt's `*.provenance.json` / `iotakt.provenance/v1` naming** — it diverges
  from henret's schema; follow henret, which is what the consumer actually reads;
- a human `GATE-RUN.md`, referenced from the sidecar by hash.

Each link must be a published, fetchable artifact so a consumer can run the chain end-to-end (sidecar hash →
archive hash → the archive's internal `lake-manifest.json` / `lean-toolchain` matching the sidecar's claims →
files-at-root layout).

**Confirmed field set (jemmet, round 6): mirror henret 0.34.4's actual `release-verification.json` as the
literal template.** jemmet will send henret 0.34.4's published sidecar (byte-verified copy, `21d6e9d0…`) to
mirror exactly; the top-level skeleton to author against is:

```
manifest_schema, generated_by, package, version, gate_registry, release_profile,
required_gates_passed, timestamp_utc, git_commit, git_dirty, git_dirty_paths,
tarball_sha256, source_archive{name,sha256,size_bytes}, lake_manifest_sha256,
lean_toolchain_sha256, os, runner, gate_policy{…script sha256s…},
gates[{id,name,command,status,duration_ms,stdout_log,stdout_sha256,stderr_log,
       stderr_sha256,criticality}…], validation_reports[], runtime_package{…},
human_summary{name,sha256}, dependencies[…]
```

kroopt's 27-suite gate + axiom audit + fuzz + sanitizers + interop maps directly onto `gates[]` (no new
verification work, only its publication). Keep the `verification` block too (theorem count,
`sorry`/`admit`/`project_axioms` = 0): jemmet reads the gate ledger as the per-package evidence tier and
`verification` as the corpus summary. **Dry-run loop (stub-first):** send jemmet a schema-shaped stub
(right keys/nesting, placeholder hashes) to settle structure through `verify_release_manifest.py` +
`verify_stack_release.py` fast; *then* wire the real gate ledger and re-run on the real-gate sidecar — two
cheap loops beat one expensive one.

**Loop-1 result (done, jemmet dry-run of `kroopt-0.0.0-stub`).** Structure is validated.
`verify_stack_release.py` is **green** — kroopt resolves as a single node with **zero edges**, and HACL\* is
correctly absent as a stack edge (the verifier only checks `dependency_edges` against `dependencies`, never
the reverse), confirming the corrected zero-edge model. `verify_release_manifest.py` passes **every**
structural check — `source_archive.sha256` == tarball, `tarball_sha256` == `source_archive.sha256`,
`size_bytes`, `lake_manifest_sha256`, `lean_toolchain_sha256`, `package`, `manifest_schema 1` (anchors
independently recomputed by jemmet, all hold) — and trips **only** on the gate-evidence tier: it requires
every required gate `status == "pass"` and correctly rejects the 34 self-marked `status: "stub"` gates. That
is the evidence tier doing its job, not a schema-shape problem, so it is **not** a blocker — loop-2 (real
`pass` gates) clears it. Two follow-ons: (1) a repeatable `--structure-only` dry-run mode that treats
self-marked stub gates as "structure-OK, evidence-pending" is a **henret** RFC 095 tooling item (the script
is shared stack tooling), which jemmet is raising upstream; it does not gate kroopt. (2) The canonical
`release-verification.json` basename is for the **real** release only; a `*-stub.provenance.json` basename is
correct for dry-runs (the verifiers take explicit paths and index by hash).

**The pitfall to avoid is a *publication* problem, not a layout problem (the iotakt lesson).** iotakt's
release asset *was* files-at-root; it still failed verification because the asset the manifest named was not
published as a downloadable attachment — only GitHub's auto-generated "Source code" tarball was fetchable,
and that one wraps everything in a `kroopt-X.Y.Z/` parent directory, carries different tar/gzip metadata, and
has historically had its checksums silently broken by GitHub. So a manifest that names a locally-built file
nobody can fetch is a phantom anchor. The asset the manifest names must be the asset that is published, from
the same run that produced the hash.

**Current gap (honest status).** Files-at-root layout is necessary but **not sufficient**, and kroopt is
*not* yet positioned to avoid the pitfall:

- kroopt's release tarballs are produced by a **manual** recipe, not by repo automation, so the canonical
  build is not reproducible from the repo and a human could hash one file and publish a differently-built
  one — exactly the iotakt failure mode, or worse;
- kroopt's only CI (`.github/workflows/ci.yml`) is a **gate** workflow (build, tests, fuzz, interop,
  hygiene/deps/axiom gates on push/PR). There is **no release-publish workflow**: nothing builds the
  files-at-root asset, generates the sidecar, or attaches assets to a GitHub release.

**Therefore RFC 030 must add, before the first provenance-bearing release** (concrete techniques below are
confirmed from iotakt's 0.14.4→0.14.5 release CI, which had to be re-fixed for label drift and archive
scope — worth not re-learning):

1. an **in-repo packaging script** (e.g. `scripts/package-release.sh "$VERSION" "$OUT"`) that:
   - derives the **canonical bare `X.Y.Z`** version from the tag, stripping a leading `v` (`VERSION="${RAW#v}"`);
   - produces a **byte-reproducible**, files-at-root archive — the determinism kroopt's manual recipe lacks
     today. The proven recipe: stage a clean tree, then
     `tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner -cf - -C "$tree" . | gzip -n > out.tar.gz`
     so the same commit yields the same bytes and the same `sha256` on any machine;
   - includes **source only** — exclude `.lake`/`.git`/`*.olean`/`*.o`/`*.a` **and** all cross-team
     correspondence (kroopt's reply/RFR/review notes live out-of-tree in `outputs/`, so they are already
     excluded; keep it that way). Reason beyond "not source": a correspondence note that ever cites the
     archive's own hash creates a self-reference the archive hash can never settle. Corollary: **no in-tree
     document (CHANGELOG, RFC) may quote the archive's own `sha256`** — the sidecar (a separate asset) is the
     only place that hash lives;
   - carries a **label-drift guard**: abort unless `VERSION` equals the latest `CHANGELOG.md` release heading,
     so the tag, the manifest `version`, and the changelog can never disagree (this is exactly the guard that
     would have caught iotakt's 0.14.4 drift, where the manifest said `0.14.4` but the docs said `0.14.4-dev`);
2. a **release-publish CI workflow** (separate from the gate `ci.yml`, triggered on a `vX.Y.Z` tag) that, in
   one run: runs the full gate, invokes the packaging script, **self-verifies the sidecar against the
   just-built archive before publishing**, and then `gh release upload --clobber`s the exact archive + sidecar
   as release assets (non-tag/dispatch runs upload them as workflow artifacts instead — a dry-run path). So
   the artifact the manifest names is, by construction, the artifact a consumer can fetch.

kroopt's sole dependency record (§below) follows the offline-rebind discipline, but kroopt's case is narrow:
its only link is HACL\*/EverCrypt, recorded as a vendored-source entry that **kroopt's own**
`check-provenance.sh` re-binds by hash — not a stack edge, and not an iotakt sidecar (kroopt has no iotakt
edge; see below).

**kroopt-specific manifest notes.**

- **The `dependencies` block declares only HACL\*/EverCrypt — and it is not a stack edge (settled, jemmet
  round 6).** kroopt's verified core is dependency-free (`lake-manifest.json` is `packages: []`, confirmed),
  and the only thing kroopt *links* is HACL\*/EverCrypt via FFI. kroopt does **not** link iotakt: kroopt's
  core defines the abstract `Transport` typeclass, and **jemmet's** `IotaktTransport` (jemmet RFC 009)
  supplies the iotakt-backed instance. So the iotakt edge in the deployment closure is **jemmet→iotakt**,
  owned by jemmet's binding node — **kroopt must not emit an iotakt edge** (it would be a phantom/duplicate).
  kroopt has no henret edge either. Net: **kroopt's stack node has zero outgoing stack edges.**
  - **HACL\*/EverCrypt is a vendored-source entry in kroopt's *own* sidecar, re-bound by kroopt's own
    `check-provenance.sh` — never by jemmet's stack verifier.** jemmet's `verify_stack_release.py` resolves
    every `dependency_edge` provider to a package entry with a resolvable `manifest_sha256` + `tarball_sha256`
    and cross-checks it against the consumer's `dependencies`; it has **no vendored-source / hash-only edge
    path**, so an upstream C project with no Lean-stack sidecar cannot be a stack edge. But the verifier only
    checks `dependency_edges` *against* `dependencies` — it does not require every `dependencies` entry to be
    an edge. So HACL\* lives in kroopt's `dependencies` as a structured vendored-source record (RFC 017
    structured-absence shape), bound by vendored bytes: the vendored C tree hashes to the recorded value at
    the recorded commit, status honestly "upstream-trusted, not sidecar-verified." **No jemmet verifier change
    is needed and the HACL\* record can never block a green stack run** — crypto provenance stays
    kroopt-internal, matching jemmet treating crypto as ASSUMED (RFC 011), not stack-proven.
  - **Field shape (kroopt's to choose — jemmet does not consume these keys):** `name`, `upstream_commit`,
    `upstream_version`, `source_tree_sha256`, `provenance_status` (e.g. `"external-upstream-vendored"`),
    `provenance_note` — parallel to RFC 017.
  - **Binding shape resolved by fact: kroopt *vendors* HACL\*/EverCrypt, so the bind is vendored-tree, not a
    system-link pin.** kroopt vendors the EverCrypt/HACL\* C sources in-tree at `Kroopt/Native/hacl` (167
    files; the shim + sanitizer/interop scripts compile and link them). So `check-provenance.sh` binds the
    edge by hashing that vendored tree into `source_tree_sha256` (jemmet confirmed either shape is fine since
    HACL\* is not a stack edge; the system-link "pin the upstream release tarball" shape does not apply because
    kroopt has the tree in-hand). **Loop-2 prerequisite / open gap:** the vendored tree currently records **no
    upstream provenance** — there is no `VERSION`/`README`/commit marker noting which EverCrypt/HACL\* upstream
    tag or commit it was vendored from, so `upstream_commit` / `upstream_version` cannot be derived from the
    tree alone and must be recorded (maintainer knowledge of the vendoring source), and a **canonical
    `source_tree_sha256` method** must be fixed (e.g. sorted per-file sha256 over `Kroopt/Native/hacl` then
    hash-of-hashes — a sample run yields `aaf8b179…` — or a deterministic-tar hash). Both are loop-2 work, not
    stub blockers; the stub carried placeholders for exactly these fields.
- **kroopt declares no iotakt or henret pin.** The single shared-stack pins — iotakt `0.14.5`
  (`8c1db19e…` / sidecar `8a125c2b…`) and the one henret `0.34.4` (`21d6e9d0…`) — live on jemmet's and
  iotakt's nodes, not kroopt's. The only shared-pin discipline touching kroopt is the unique-package-name rule
  and matching kroopt's *own* node hash. (kroopt has separately verified the published iotakt 0.14.5 assets —
  tarball `8c1db19e…`/315016 bytes, sidecar `8a125c2b…`, files-at-root — as diligence, but does not vendor
  them, having no iotakt edge.)
- **One version scheme: bare `X.Y.Z`** (no `-dev`). Mirrors iotakt, which dropped `-dev` after it caused
  exactly the 0.14.4 label drift. "Anchored release" is **not** a version-string property — it is the
  presence of a `vX.Y.Z` tag + a `release-verification.json` sidecar + a GitHub release. A plain
  `kroopt-X.Y.Z.tar.gz` build makes no such claim; the sidecar is the claim (and is the signal `-dev` was
  standing in for). kroopt's `0.` major already conveys pre-1.0 instability per SemVer. This is a deliberate
  divergence from iotakt/henret's *frozen-`-dev`* pin: kroopt pins a bare `X.Y.Z` (worth telling jemmet, who
  assumed a `-dev` pin). Existing `…-dev` history stays as the record; bare from the next increment onward.
- **One small guard, at release time only:** `package-release.sh` aborts unless the release version equals
  the top `CHANGELOG.md` heading and that heading is bare `X.Y.Z`, so tag, manifest `version`, and changelog
  cannot disagree.
- Declare canonical `X.Y.Z` releases **immutable once published** in a `RELEASES.md` (as iotakt and henret do
  for their pinned artifacts) — a published `X.Y.Z` archive + sidecar are never re-cut under the same version.

The gate ledger in the sidecar maps directly onto kroopt's existing full gate (27 suites, axiom audit,
dependency and hygiene gates, fuzz, sanitizers, interop), so no new verification work is implied — only its
publication in a fetchable, hash-linked form.

### 4.x Implementation staging status

The provenance generator is staged A → B → C:

- **Stage A — canonical gate + CI consolidation — SHIPPED (0.119.0).** One `scripts/gate.sh` shared by CI
  and (future) release, emitting `gate-out/gate-ledger.json` + `GATE-RUN.md`; CI rewired to it.
- **Stage B — release machinery + real local sidecar — SHIPPED (0.121.0; release-readiness hardening
  0.121.1).** `scripts/package-release.sh` (reproducible, files-at-root source tarball; `--release` enforces
  the version equals the bare `X.Y.Z` top CHANGELOG heading; sidecar is a sibling, never inside),
  `scripts/gen-sidecar.sh` (assembles `release-verification.json` / `manifest_schema 1` from the ledger + HACL
  provenance manifest; HACL\* as a vendored-source `dependencies` entry, not a stack edge; run-context sourced
  from the ledger and labeled honestly — a real-release profile requires a real git commit, a clean tree, and
  a **canonical full-release ledger** validated against `scripts/gate-registry.json` (registry + profile +
  exact gate set + every gate pass/required), else a `local-dry-run` sidecar marked `must_not_publish`), and
  `scripts/check-provenance.sh` (self-verifies every hash against on-disk artifacts, re-runs the HACL gate,
  enforces profile-metadata consistency always, and with `--require-release` re-checks the canonical gate set,
  attestation status, and archive name). `gate.sh` pass-detection now **requires exit code 0** for every gate
  kind (a nonzero gate can never be recorded `pass`) and self-checks its emitted set against the registry;
  guarded by `gate.sh --selftest-passdetect` and `scripts/check-release-machinery.sh` (CI steps). The HACL\*
  anchor it consumes landed in 0.120.0–0.120.2 (RFC 043). Demonstrated locally end-to-end against a
  `local-dry-run` sidecar; publish is not exercisable outside CI/git.
- **Stage C — `release.yml` + `RELEASES.md` — AUTHORED (0.122.0).** `.github/workflows/release.yml`: on a
  `vX.Y.Z` tag it checks tag == `vX.Y.Z` == top CHANGELOG heading, runs `gate.sh --profile full-release` + the
  release-machinery regression tests, packages with `package-release.sh --release`, generates the sidecar with
  `--profile real-release`, self-verifies with `check-provenance.sh --require-release`, and publishes exactly
  `kroopt-X.Y.Z.tar.gz` + `…release-verification.json` + `…GATE-RUN.md`. Releases are **immutable**: the
  workflow refuses to publish if the tag's release already exists and never uses `--clobber`; a wrong
  published asset requires a new version (`RELEASES.md`). Non-tag (`workflow_dispatch`) runs exercise the same
  path but emit only a `local-dry-run` sidecar as CI artifacts. `ci.yml` also runs the regression tests on
  every push/PR. The publish step itself is not exercisable outside a real tagged CI run; it is authored to
  spec and the dry-run path is the locally/CI-reviewable one.

---

## 5. Release notes structure

Each release note includes:

- milestone and scope;
- public API changes;
- security-relevant changes;
- proof status changes;
- interop matrix changes;
- known limitations;
- upgrade notes for jemmet/iotakt consumers.

---

## 6. Rollback considerations

Because kroopt is used at the edge, releases should be easy to disable or roll
back in jemmet deployment. The runbook should document:

1. how to switch a listener back to plaintext for local testing only;
2. how to revert to previous kroopt config snapshot;
3. how to identify handshake failure spikes;
4. how to collect redacted diagnostics.

This RFC does not recommend deploying plaintext publicly; rollback guidance is
for operational control and local staging.

---

## 7. Acceptance criteria

1. `docs/src/release-runbook.md` exists before v0.4.
2. Release checklist is executed for every archive/tag.
3. Release notes include proof/test/assumption deltas.
4. Security blockers have explicit signoff.
5. The release never claims cryptographic properties beyond the established
   trust boundary.
