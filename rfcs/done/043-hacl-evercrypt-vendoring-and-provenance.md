# RFC 043 — HACL\*/EverCrypt Vendoring and Provenance Discipline

**Project.** kroopt  
**Status.** Implemented (0.120.0 anchor mechanism; RFC 0.120.1; ratified after review cleanup 0.120.2)  
**Type.** Cross-cutting policy RFC (external-dependency trust discipline)  
**Depends on.** RFC 008 (crypto-provider capability and FFI contract), RFC 009 (HACL\* shim/KAT/sanitizer)  
**Relates to.** RFC 030 (release runbook / provenance sidecar), RFC 034 (provider-capability honesty)  
**Touches.** `Kroopt/Native/hacl/` (vendored tree), `Kroopt/Native/hacl-provenance/` (manifest + VENDOR.md), `scripts/check-hacl-provenance.sh`, `scripts/verify-hacl-upstream.sh`, `scripts/gate.sh`, `docs/src/verification/trust-matrix.md`, `docs/src/crypto/third-party.md`, `docs/src/verification/proof-assumptions.md`  
**Canonical source.** kroopt fixed requirements and external design; the HACL\* trust-anchoring review.

---

## 1. Summary

kroopt borrows its cryptography from HACL\*/EverCrypt (Project Everest) and places it in the
ASSUMED-inherited-verified trust tier. That inheritance is legitimate only if the vendored bytes under
`Kroopt/Native/hacl/` provably **are** a named upstream verified artifact. This RFC defines the discipline
that establishes and maintains that binding: a recorded per-file provenance manifest, an offline gate that
re-checks it every build, an on-demand online re-verification against upstream, a zero-modification rule for
vendored algorithm sources, and a bump procedure that treats any upstream change as a deliberate trust-tier
event. It ratifies the anchor landed in 0.120.0 and governs all future vendoring.

## 2. Motivation

Functional gates (KATs, interop) prove the borrowed primitives *behave* correctly; they do **not** establish
that the vendored bytes are the verified upstream artifact — a functionally-correct but unverified
reimplementation would pass the same vectors. Before 0.120.0 the vendored tree had no recorded upstream
commit/release, no per-file manifest, and no gate tying it to upstream, so the central
"inherited-verified crypto" claim rested on bytes of unrecorded origin. Filling a guessed `upstream_commit`
into a release sidecar would have *manufactured* provenance — worse than none. The fix is to anchor the
bytes to a named, checksum-verified upstream artifact and keep that binding under a recurring check.

## 3. Principle — an outer project is managed strictly, not flexibly

HACL\*/EverCrypt is outside kroopt's authorship; kroopt inherits upstream's verification rather than
re-proving it. An inherited claim is only as strong as the binding to the thing it inherits from, so the
binding must be **provable, recorded, and continuously re-checked**, with **zero unaccounted modifications**.
Flexible/best-effort provenance (an unverified version string, "looks like HACL\*", KAT success as identity)
is explicitly insufficient.

## 4. Scope

Covers the vendored HACL\*/EverCrypt C/header/assembly subset under `Kroopt/Native/hacl/`. Out of scope:
kroopt's own FFI shim (`Kroopt/Native/kroopt_ffi.c`, `kroopt.h`), which is kroopt-authored code under
kroopt's normal proof/test discipline (RFC 008/009), not vendored upstream, and is deliberately kept
*outside* the vendored tree.

## 5. The current anchor

| Field | Value |
|---|---|
| Upstream repo | `https://github.com/hacl-star/hacl-star` |
| Pinned release | `ocaml-v0.4.5` |
| Artifact | `hacl-star.0.4.5.tar.gz` |
| Artifact sha256 | `47bf253f804ec369b2fbc76c892ba89275fde17d7444d291d5eb5c179a05e174` (corroborated by `ocaml/opam-repository`) |
| Vendored upstream files | 166, all byte-identical; `local_modifications: []` |
| `source_tree_sha256` | `ff82d9a7360cf04d677300a0a107d105245b454befd2c4e6b51e9ebe05daf1cd` (`sorted-file-sha256-v1`) |
| Excluded metadata | `LICENSE` (kroopt-authored license aggregation) |

The vendored tree is a flattened, deliberate **subset** of the artifact; the path mapping is recorded in the
manifest.

## 6. Provenance manifest

The machine-readable record is `Kroopt/Native/hacl-provenance/HACL-PROVENANCE.json`, with a human companion
`VENDOR.md`. Both live **outside** the hash-covered source tree so the vendored tree stays pure upstream
bytes and metadata is never counted as an upstream algorithm file.

Required fields: `schema_version`, `provenance_status` (`external-upstream-vendored`), `upstream_repo_url`,
`upstream_release_tag`, `upstream_artifact_name`, `upstream_artifact_url`, `upstream_artifact_sha256`,
`source_tree_hash_method`, `source_tree_sha256`, `vendored_upstream_file_count`, `excluded_metadata_files`,
`local_modifications` (must be `[]` for a clean inherited claim), `path_mapping`, and `files[]` with
`{vendored_path, upstream_path, sha256}` for every upstream file. Excluded metadata files (e.g. `LICENSE`)
must **not** appear in `files[]`.

## 7. `source_tree_sha256` method (`sorted-file-sha256-v1`)

Pinned precisely — a path-sorted variant computes a different digest, so the definition is exact:

1. For each upstream-matched vendored file, build one line: `<lowercase sha256><two spaces><relative path from
   `Kroopt/Native/hacl`><LF>`.
2. Sort the complete lines lexicographically **by byte value** (`LC_ALL=C` / Unicode code point; lines are
   ASCII).
3. Concatenate them.
4. SHA-256 the concatenated UTF-8 bytes.

Excluded metadata files are not included.

## 8. Zero-modification rule

Vendored algorithm/header/assembly files are **byte-identical** to the pinned upstream artifact. kroopt makes
no edits to them; any kroopt glue lives outside the vendored tree. A modification — should one ever be
unavoidable — must be enumerated in `local_modifications`, justified in this RFC (or a successor), covered by
explicit tests, and **downgraded out of inherited-verified status** for that file in the trust matrix. The
default and current state is zero modifications; the offline gate fails if `local_modifications` is non-empty
while the trust matrix claims a clean inherited posture.

## 9. Verification

- **Offline, every build (CI gate):** `scripts/check-hacl-provenance.sh` re-checks **tree == manifest**:
  every listed file present and hash-matching, no unlisted/undocumented file under the tree, excluded
  metadata exactly as declared (no drift), `local_modifications` empty, `source_tree_sha256` recomputed by
  the pinned method, and no stub/placeholder sentinels. It performs **no network access** and is wired into
  `gate.sh` (both `full-release` and `pr` profiles), with its hash recorded in the gate ledger's
  `gate_policy`.
- **Online, on demand (not a CI gate):** `scripts/verify-hacl-upstream.sh` re-establishes **manifest ==
  upstream**: it downloads the pinned artifact, confirms its sha256 against the manifest, and byte-compares
  every manifest file against its recorded `upstream_path`. It is deliberately excluded from CI so ordinary
  builds stay offline and deterministic.

The two together form the chain: *tree == manifest* (offline, every build) ← *manifest == upstream artifact*
(online, on demand; established once at vendoring) ← *artifact is the verified upstream* (inherited).

## 10. Upstream bump procedure (a trust-tier event)

Changing the pinned upstream is **not** a casual dependency refresh. The procedure:

1. Choose the new upstream artifact per the pin policy (§11) and record the decision in this RFC + CHANGELOG.
2. Download it; confirm its checksum against an independent source (e.g. opam-repository, upstream release
   notes).
3. Re-extract the needed subset with **zero modifications** to algorithm sources; glue stays outside the
   tree.
4. Regenerate `HACL-PROVENANCE.json` (new artifact anchor, per-file hashes, `source_tree_sha256`).
5. Run `check-hacl-provenance.sh` (offline) and `verify-hacl-upstream.sh` (online) — both must pass.
6. Update the trust matrix and `third-party.md` to the new anchor; keep the anchored wording only while the
   gate is active.
7. Review as a deliberate trust-tier change.

## 11. Pin policy

If the vendored tree byte-matches a specific upstream artifact (the identify-and-verify path), pin that
artifact. If it does not match, the maintainer chooses the upstream release to re-vendor from; the design
team does not invent a pin for convenience. A chosen fallback should provide the required primitives, have a
clear published artifact, be compatible with kroopt's FFI boundary, and vendor with zero algorithm-source
modifications.

## 12. Trust-matrix coupling

The HACL\* rows may carry the anchored-inherited wording **only while** the offline gate is active. The
matrix states the precise three-way split: *proven by kroopt* — vendored bytes are byte-identical to the
named upstream artifact subset; *inherited / ASSUMED* — upstream Project Everest verification and KaRaMeL
extraction claims about that artifact; *not proven by kroopt* — cryptographic correctness, secrecy, or
constant-time behavior. The anchor restores the legitimacy of inheriting the upstream claim; it does not
convert it into a kroopt proof.

## 13. Release-sidecar coupling (RFC 030)

The real release sidecar (RFC 030 Stage B) sources its HACL\* dependency fields **from the manifest**, never
from free-form release-script flags or maintainer memory: `upstream_release_tag`, `upstream_artifact_sha256`,
`source_tree_sha256`, `vendored_file_count`, `local_modifications`. The sidecar generator must fail if the
manifest is missing, carries stub/placeholder values, or disagrees with the recomputed `source_tree_sha256`.

## 14. What this does and does not establish

- **Established by kroopt:** the vendored bytes are byte-identical to the named upstream `ocaml-v0.4.5`
  artifact subset.
- **Inherited / ASSUMED:** upstream's verification and KaRaMeL extraction claims about that artifact.
- **Not proven by kroopt:** cryptographic correctness, secrecy, or constant-time behavior.

## 15. Implementation status

The anchor mechanism shipped in **0.120.0**: `HACL-PROVENANCE.json` + `VENDOR.md`, the offline
`check-hacl-provenance.sh` gate wired into `gate.sh` (both profiles; 37 gates in `full-release`), the online
`verify-hacl-upstream.sh` re-verification, and the trust-matrix/`third-party.md`/`proof-assumptions.md`
restoration to anchored wording. The RFC document shipped in 0.120.1; review-cleanup (anchor-metadata schema
checks in the offline gate, doc-link fixes) shipped in 0.120.2. This RFC is therefore Implemented: the policy
is adopted and enforced. The first future upstream bump will *exercise* the §10 procedure and may produce
follow-up amendments, but is **not** a prerequisite for ratifying the policy — it is future validation
evidence, not a done-gate.

## 16. Open questions

1. Whether to relocate the kroopt-authored `LICENSE` out of `Kroopt/Native/hacl/` (to
   `Kroopt/Native/hacl-provenance/` or `THIRD-PARTY-NOTICES.md`) for full source-tree purity. Excluding and
   documenting it is sufficient today; relocation is a cosmetic follow-up.
2. Whether a future EverCrypt bump should track the main `hacl-star` repo `dist/` rather than the OCaml
   package release (the current anchor uses the OCaml package artifact, which the embedded provenance comment
   named).
3. Whether any portion of the manifest generation should itself be a committed script (`vendor-hacl.sh`) for
   reproducible re-vendoring, versus a documented procedure run at bump time.
