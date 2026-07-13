# RFC 054 — Maintainability Split and History Archival

**Project.** kroopt  
**Status.** Proposed  
**Type.** Non-blocking maintainability theme  
**Target milestone.** AR-M, completed before stable/v1  
**Requires completion of.** Project Lean/file-size instructions; [RFC 022](../done/022-proof-gates-ci-and-lean-hygiene.md) hygiene  
**Touches.** oversized core/proof modules, ROADMAP/CHANGELOG historical structure, docs navigation  

## Review finding

The review identified concentrated maintenance risk: `Proofs/Handshake.lean` (1,216 lines),
`Proofs/RecordPath.lean` (630), and `Core/Handshake.lean` (534) exceed the project's strong split threshold.
ROADMAP and CHANGELOG also mix current operating truth with long historical narrative.

## Decision

Split by stable logical boundaries in small behavior-preserving changes. Do not combine mechanical moves with
security behavior changes. Preserve public theorem/API names where practical; otherwise provide explicit
compatibility re-exports and a migration map.

Current schedule/status stays concise and reviewable. Historical milestone narratives remain durable but move
to a versioned archive or generated history rather than obscuring current decisions.

## Work breakdown

1. Inventory imports, theorem dependencies, declarations, and effective lines for modules over 300 ELOC.
2. Split handshake proofs by negotiation, transition legality, transcript, and completion authorization.
3. Split record-path proofs by framing, open/seal, plaintext authorization, and alert/terminal behavior.
4. Split core handshake helpers only at dependency-stable boundaries revealed by AR1 changes.
5. Keep facade imports so downstream module paths remain stable where possible.
6. Extract historical roadmap status bands to an archive and keep a short live roadmap.
7. Preserve changelog releases, but add generated navigation/indexing instead of duplicating status prose.

## Acceptance criteria

1. No behavior/proof statement changes in a split-only patch.
2. Build, axiom, dependency, hygiene, and full test gates remain green after every slice.
3. Public theorem/API name changes have a documented migration map and compatibility decision.
4. Strict-zone dependencies do not gain imports from impure/native layers.
5. Current roadmap/status can be reviewed without traversing historical milestone logs.
6. The durable history remains linkable and is not deleted.

## Non-goals

No proof weakening, mass rename, speculative abstraction, RFC renumbering, or history deletion is permitted.
