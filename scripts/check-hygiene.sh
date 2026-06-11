#!/usr/bin/env bash
# scripts/check-hygiene.sh — RFC 022 §4/§5 proof-hygiene gate.
#
# Fails if any project-local `sorry`, `axiom`, `unsafe`, `native_decide`, or
# `admit` appears as *code* (not in comments) in the verified-core or proof
# zones. These zones must remain fully verified (RFC 022 §3 strict zones).
#
# Comments and doc-strings are stripped before scanning, so prose like
# "no `sorry` here" does not trip the gate.

set -euo pipefail
cd "$(dirname "$0")/.."

STRICT_PATHS=(Kroopt/Core Kroopt/Parse Kroopt/Proofs Kroopt/Error.lean Kroopt/Core.lean Kroopt/Parse.lean Kroopt/Proofs.lean)
FORBIDDEN='sorry|axiom|unsafe|native_decide|admit'

fail=0

strip_comments() {
  # Remove /- ... -/ block comments (including /-! -/) then -- line comments.
  perl -0777 -pe 's{/-.*?-/}{}gs; s{--.*}{}g' "$1"
}

for path in "${STRICT_PATHS[@]}"; do
  [ -e "$path" ] || continue
  while IFS= read -r f; do
    if strip_comments "$f" | grep -nEw "$FORBIDDEN" >/dev/null 2>&1; then
      echo "HYGIENE VIOLATION in $f:"
      strip_comments "$f" | grep -nEw "$FORBIDDEN" | sed 's/^/    /'
      fail=1
    fi
  done < <(find "$path" -name '*.lean' 2>/dev/null; [ -f "$path" ] && echo "$path")
done

if [ "$fail" -eq 0 ]; then
  echo "OK: no sorry/axiom/unsafe/native_decide/admit in strict zones."
else
  echo "FAIL: forbidden constructs found in strict zones (RFC 022 §4)."
  exit 1
fi
