# HACL*/EverCrypt vendoring & provenance

This directory (`Kroopt/Native/hacl-provenance/`) holds kroopt-authored provenance metadata for the
vendored HACL\*/EverCrypt sources under `Kroopt/Native/hacl/`. It lives **outside** the hash-covered
source tree on purpose: the vendored tree stays pure upstream bytes, and this metadata is never counted
as an upstream algorithm file.

## What is anchored

The vendored C/H/assembly under `Kroopt/Native/hacl/` is a flattened, deliberate **subset** of a single
named, checksum-verified upstream artifact:

- **Upstream:** `https://github.com/hacl-star/hacl-star`, release tag **`ocaml-v0.4.5`**
- **Artifact:** `hacl-star.0.4.5.tar.gz`
- **Artifact sha256:** `47bf253f804ec369b2fbc76c892ba89275fde17d7444d291d5eb5c179a05e174`
  (independently corroborated by the checksum recorded for `hacl-star.0.4.5` in `ocaml/opam-repository`)
- **Vendored upstream files:** 166, **all byte-identical** to the artifact; `local_modifications: []`
- **`source_tree_sha256`** (`sorted-file-sha256-v1`): `ff82d9a7360cf04d677300a0a107d105245b454befd2c4e6b51e9ebe05daf1cd`

The machine-readable record is `HACL-PROVENANCE.json` (per-file `vendored_path → upstream_path → sha256`,
plus the path mapping and the artifact anchor). It is the single source the release sidecar reads for the
HACL\* dependency fields.

## What the anchor does and does not establish

- **Established (by kroopt):** the vendored bytes are byte-identical to the named upstream `ocaml-v0.4.5`
  artifact subset.
- **Inherited / ASSUMED:** upstream Project Everest's verification and KaRaMeL extraction claims about that
  artifact. kroopt does not re-run them.
- **Not proven by kroopt:** cryptographic correctness, secrecy, or constant-time behavior.

The anchor restores the legitimacy of *inheriting* the upstream claim; it does not convert that inherited
claim into a kroopt proof. See [trust matrix](../../../docs/src/verification/trust-matrix.md).

## How it is verified

- **Offline, every build (CI gate):** `scripts/check-hacl-provenance.sh` re-checks **tree == manifest**
  byte-for-byte — every listed file present and hash-matching, no unlisted/undocumented files, excluded
  metadata exactly as declared, `local_modifications` empty, and `source_tree_sha256` recomputed. No
  network. Wired into `scripts/gate.sh` (both `full-release` and `pr` profiles).
- **Online, on demand:** `scripts/verify-hacl-upstream.sh` re-establishes **manifest == upstream** — it
  downloads the pinned artifact, confirms its sha256 against the manifest, and byte-compares every
  manifest file against its recorded `upstream_path`. Network-dependent, so it is deliberately **not** a
  CI gate.

## `source_tree_sha256` method (`sorted-file-sha256-v1`)

Pinned precisely (a path-sorted variant computes a different digest, so the definition is exact):

1. For each upstream-matched vendored file, build one line:
   `<lowercase sha256><two spaces><relative path from Kroopt/Native/hacl><LF>`.
2. Sort the complete lines lexicographically **by byte value** (`LC_ALL=C` / Unicode code point; the lines
   are ASCII).
3. Concatenate them.
4. SHA-256 the concatenated UTF-8 bytes.

Excluded metadata files (below) are not included.

## Excluded metadata

- `Kroopt/Native/hacl/LICENSE` — a kroopt-authored aggregation of the vendored sources' MIT/Apache-2.0
  license texts. It is **not** an upstream dist file; it is excluded from the upstream set and from
  `source_tree_sha256`, and is recorded in the manifest's `excluded_metadata_files`. (A future cleanup may
  relocate it; excluding-and-documenting it is sufficient today.)

## Upstream bumps are trust-tier events

Changing the pinned upstream is **not** a casual dependency refresh — it is a deliberate trust-tier change.
The procedure (re-fetch the chosen artifact, confirm its checksum, re-extract the subset with zero
modifications to algorithm sources, regenerate `HACL-PROVENANCE.json`, re-run both checks, update the trust
matrix and CHANGELOG, and review) is governed by the dedicated HACL\*/EverCrypt vendoring & provenance RFC.
