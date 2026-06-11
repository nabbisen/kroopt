#!/usr/bin/env bash
# check-axioms.sh — RFC 022 proof gate.
#
# Asserts that every PUBLIC theorem in Kroopt/Proofs depends only on the
# whitelisted foundational axioms (propext, Quot.sound, Classical.choice) and in
# particular NEVER on `sorryAx`. A `sorry` anywhere in a proof's transitive
# dependencies surfaces here as a `sorryAx` axiom dependency, even if the source
# grep in check-hygiene.sh missed it (e.g. via a dependency). This is the
# semantic complement to the syntactic hygiene gate.
set -euo pipefail
cd "$(dirname "$0")/.."

AUDIT=$(mktemp /tmp/kroopt-axiom-audit-XXXX.lean)
trap 'rm -f "$AUDIT"' EXIT

{
  echo 'import Kroopt.Proofs'
  echo 'open Kroopt.Core.Proofs Kroopt.Core Kroopt.Parse Kroopt.Parse.Proofs Proofs'
  # Public theorems only (exclude `private theorem`).
  grep -rhoE '^theorem [A-Za-z0-9_]+' Kroopt/Proofs/*.lean | awk '{print "#print axioms " $2}'
} > "$AUDIT"

N=$(grep -c '#print axioms' "$AUDIT")
OUT=$(lake env lean "$AUDIT" 2>&1)

if echo "$OUT" | grep -q 'sorryAx'; then
  echo "FAIL: a proof depends on sorryAx (a 'sorry' leaked in):"
  echo "$OUT" | grep -B0 'sorryAx'
  exit 1
fi

# Flag any axiom outside the whitelist.
if echo "$OUT" | grep -oE "axioms: \[[^]]*\]" \
   | grep -vE 'propext|Quot\.sound|Classical\.choice' \
   | grep -qE '[A-Za-z]'; then
  echo "FAIL: a proof depends on a non-whitelisted axiom:"
  echo "$OUT" | grep "axioms:" | grep -vE 'propext|Quot\.sound|Classical\.choice' || true
  exit 1
fi

echo "OK: $N public theorem(s) audited; no sorryAx; axioms within {propext, Quot.sound, Classical.choice}."
