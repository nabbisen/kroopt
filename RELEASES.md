# Releases

kroopt releases are cut by [`.github/workflows/release.yml`](.github/workflows/release.yml) (RFC 030
Stage C) from a `vX.Y.Z` tag. Each release carries verifiable provenance.

## Assets per release

A published `vX.Y.Z` release attaches exactly three assets:

- `kroopt-X.Y.Z.tar.gz` — the reproducible, files-at-root source archive.
- `kroopt-X.Y.Z.release-verification.json` — the provenance sidecar (henret `manifest_schema 1`): the gate
  ledger transcription, the source-archive hash/size, lake-manifest/lean-toolchain hashes, and the
  HACL\*/EverCrypt vendored-source dependency (anchored to upstream `ocaml-v0.4.5`; see RFC 043).
- `kroopt-X.Y.Z.GATE-RUN.md` — the human-readable gate summary, so the gate-log hash chain in the sidecar is
  externally checkable.

## Immutability

**A published `X.Y.Z` release is immutable.** Once the tarball and sidecar are published under a version,
they are never re-cut or replaced:

- The release workflow refuses to publish if a release for the tag already exists (no `--clobber` against
  published assets).
- If a published asset is later found to be wrong, **publish a new version** (`X.Y.(Z+1)` or higher) with the
  fix. Do not replace the tarball or sidecar of an already-published version — external references pin the
  published hashes, and replacing them silently invalidates every such reference.

This mirrors the immutability discipline of the upstream provenance ecosystem (iotakt / henret pinned
artifacts).

## How a release is produced

On a `vX.Y.Z` tag, the workflow:

1. checks the tag is `vX.Y.Z` and equals the top `CHANGELOG.md` heading `[X.Y.Z]`;
2. runs the canonical gate, `scripts/gate.sh --profile full-release`, and the release-machinery regression
   tests;
3. packages the exact source tarball, `scripts/package-release.sh --release X.Y.Z`;
4. generates the sidecar, `scripts/gen-sidecar.sh --profile real-release X.Y.Z` — which refuses unless the
   ledger is a clean-tree, real-commit, canonical full-release run;
5. self-verifies, `scripts/check-provenance.sh --require-release X.Y.Z`;
6. publishes the three assets.

Non-tag (`workflow_dispatch`) runs exercise the same path but emit only a **local-dry-run** sidecar
(`must_not_publish: true`) uploaded as CI artifacts — never as release assets.

## Verifying a downloaded release

With all three assets in a `dist/` directory beside a checkout of the matching tag:

```sh
OUT_DIR=dist bash scripts/check-provenance.sh --require-release X.Y.Z
```

This recomputes the tarball / lake-manifest / lean-toolchain / gate-log / GATE-RUN.md hashes against the
sidecar, re-runs the HACL\* provenance gate, and enforces the canonical full-release gate set and release
attestation posture. Or verify the headline hashes by hand:

```sh
sha256sum dist/kroopt-X.Y.Z.tar.gz   # must equal source_archive.sha256 in the sidecar
```

## Versioning

Versions are bare `X.Y.Z` (RFC 030; SemVer-style, `0.` major conveying pre-1.0 instability). The tag is
`vX.Y.Z`; the sidecar `version`, the tag, and the top CHANGELOG heading must all agree, enforced at release
time.
