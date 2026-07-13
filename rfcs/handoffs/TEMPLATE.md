# RFC / release handoff template

**Subject.** RFC, milestone, or release candidate  
**Candidate revision.** Exact 40-hex commit, or `Pending`  
**Readiness scope.** Property/milestone being assessed; never infer whole-project production readiness  
**Overall status.** `Done`, `Pending`, or `N/A`  

## Acceptance ledger

| Item | Status (`Done` / `Pending` / `N/A`) | Candidate-specific evidence | Remaining work / reason for N/A |
|---|---|---|---|
| Requirement or acceptance criterion | Pending | Command, theorem, test, retained artifact, or review pointer | Owner and next action |

Rules:

- `Done` requires evidence observed for the candidate revision.
- `Pending` remains open and cannot be summarized as passed elsewhere.
- `N/A` requires a scope reason; it is not a pass.
- A canonical gate claim includes profile, registry id, result, revision, clean/dirty state, and the retained
  `gate-ledger.json` plus `GATE-RUN.md` location.
- Historical evidence may establish regression context but cannot attest the current candidate.
- Production/stable wording must match the current security state and ROADMAP release-decision gate.

## Commands observed

| Command | Result | Evidence location |
|---|---|---|
| `command --exact-arguments` | Pending | Pending |

## Risks and follow-up

- Pending blockers, assumptions, delegated ownership, and the next authorized milestone.

