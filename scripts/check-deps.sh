#!/usr/bin/env bash
# scripts/check-deps.sh — RFC 022 §5 / RFC 001 §9 module-dependency gate.
#
# The verified core (Kroopt/Core, Kroopt/Proofs, Kroopt/Parse) must never import
# the runtime interpreter, native FFI, crypto provider implementation, or the
# iotakt transport. If it did, the proofs would no longer constrain the code that
# actually runs (proof/runtime correspondence, RFC 002 §5).
#
# At M0 there are no runtime/native modules yet, so this gate is trivially
# satisfied — but it must exist and run from M0 so the boundary can never be
# crossed silently later (RFC 022 active from M0).

set -euo pipefail
cd "$(dirname "$0")/.."

# Pure zones that must stay free of runtime/native/transport imports.
PURE_PATHS=(Kroopt/Core Kroopt/Proofs Kroopt/Parse Kroopt/Error.lean)

# Imports forbidden inside the pure zones.
#   Kroopt.Conn.*    — runtime interpreter / iotakt integration (M7)
#   Kroopt.Crypto.*  — provider implementation + FFI wrappers (M6)
#   Kroopt.Native.*  — anything wrapping the C shim
#   Iotakt / Henret  — transport / reactor dependencies
FORBIDDEN_IMPORT='^[[:space:]]*import[[:space:]]+(Kroopt\.Conn|Kroopt\.Crypto|Kroopt\.Native|Iotakt|Henret)\b'

fail=0
scanned=0

for path in "${PURE_PATHS[@]}"; do
  [ -e "$path" ] || continue
  while IFS= read -r f; do
    scanned=$((scanned+1))
    if grep -nE "$FORBIDDEN_IMPORT" "$f" >/dev/null 2>&1; then
      echo "DEPENDENCY VIOLATION in $f (pure zone importing a runtime/native/transport layer):"
      grep -nE "$FORBIDDEN_IMPORT" "$f" | sed 's/^/    /'
      fail=1
    fi
  done < <(find "$path" -name '*.lean' 2>/dev/null; [ -f "$path" ] && echo "$path")
done

if [ "$fail" -eq 0 ]; then
  echo "OK: $scanned pure-zone file(s) clean; no forbidden runtime/native/transport imports."
else
  echo "FAIL: verified core imports a forbidden layer (RFC 001 §9, RFC 022 §5)."
  exit 1
fi
