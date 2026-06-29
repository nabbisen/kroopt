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

The dependency edges (§below) follow the same offline-rebind pattern iotakt uses: kroopt **vendors** each
dependency's sidecar (iotakt's, HACL\*'s) and the provenance check re-binds each declared edge against the
vendored sidecar by name + hash + pin, rather than trusting an unanchored pin.

**kroopt-specific manifest notes.**

- The `dependencies` block must carry both the **iotakt** and **HACL\*/EverCrypt** pins (package name +
  hash), even though kroopt's verified core is dependency-free (`lake-manifest.json` is `packages: []`,
  confirmed). The deployment tiers consume iotakt (the `Conn` interpreter) and HACL\*/EverCrypt (crypto); the
  stack verifier cross-checks edges by package name + hash, so those pins are what let kroopt slot into
  `jemmet-edge-runtime.stack-release.json` as a node with verifiable edges.
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
