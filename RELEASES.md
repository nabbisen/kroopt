# Releases

kroopt releases are cut by [`.github/workflows/release.yml`](.github/workflows/release.yml) (RFC 030
Stage C) from a `X.Y.Z` tag. Each release carries verifiable provenance.

## Assets per release

A published `X.Y.Z` release attaches exactly three assets:

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

On a `X.Y.Z` tag, the workflow:

1. checks the tag is `X.Y.Z` and equals the top `CHANGELOG.md` heading `[X.Y.Z]`;
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

## Operational status

The repository records `0.124.0` as the first real published-release workflow exercise and `0.124.1` as its
follow-up provenance fix. Earlier tags are development/history tags; this page does not retroactively assert
that they carried the three release assets. For a particular release, the immutable assets attached to that
tag are the publication evidence—neither a local tag nor a CHANGELOG gate count substitutes for them.

The current published release is pre-production `0.126.0`, exact commit
`877e54d1ce3a45ca88030052b7dedea99358ea56`. Tagged workflow run `29370919042` passed the canonical
`full-release` profile 42/42 and the release-machinery checks, then published the three immutable assets:

- source archive: 824935 bytes, SHA-256
  `c311bf854f1bfc78426fbc47292fb5756cebe33c2f127b1d197487afef83c451`;
- release-verification sidecar: 27739 bytes, SHA-256
  `ce621f26a828d0da97e6a834d38ee78f2f7d4b72b4b4a54d21b6e3889bf0e579`;
- GATE-RUN summary: 2080 bytes, SHA-256
  `4f81a63b2bb89452b1362cfd584b8ad671f75d9aae7b45913e52549778a729e1`.

The retained release gate artifact is `8326067381` (GitHub-reported ZIP SHA-256
`5ae9bbb2309fd71ef70b2f28e9de4189c14c65c9a68e5ef04de592b17a791b71`). Publication does not change
the production/stable NO-GO disposition. RFC 046 / B2 is implemented and `0.127.0` release-candidate
metadata is under review, but `0.126.0` remains the current published release until a successful tagged
workflow publishes the next immutable asset set. AR1 remains open through B1, B4, and B5.

## Versioning

Versions are bare `X.Y.Z` (RFC 030; SemVer-style, `0.` major conveying pre-1.0 instability). The tag is
`X.Y.Z`; the sidecar `version`, the tag, and the top CHANGELOG heading must all agree, enforced at release
time.
