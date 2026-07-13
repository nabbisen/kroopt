#!/usr/bin/env bash
# Prove the emitted gate ids and the versioned registry are exact matches before running expensive gates.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REGISTRY="$ROOT/scripts/gate-registry.json"
SELFTEST=0
while [ $# -gt 0 ]; do
  case "$1" in
    --registry) REGISTRY="${2:-}"; shift 2 ;;
    --selftest) SELFTEST=1; shift ;;
    -h|--help) echo "usage: check-gate-registry.sh [--selftest]"; exit 0 ;;
    *) echo "check-gate-registry: unknown arg '$1'" >&2; exit 2 ;;
  esac
done

check_registry() {
  local registry="$1" profile actual
  for profile in full-release pr; do
    actual="$(bash "$ROOT/scripts/gate.sh" --profile "$profile" --list-gate-ids)"
    python3 - "$registry" "$profile" "$actual" <<'PY' || return 1
import json, sys
path, profile, actual_text = sys.argv[1:]
with open(path, encoding="utf-8") as f:
    registry = json.load(f)
if registry.get("gate_registry") != "kroopt-gate/v3":
    raise SystemExit(f"stale gate_registry: {registry.get('gate_registry')!r}, expected 'kroopt-gate/v3'")
expected = registry.get("profiles", {}).get(profile, {}).get("required_gate_ids")
if not isinstance(expected, list):
    raise SystemExit(f"missing registry profile: {profile}")
actual = [line for line in actual_text.splitlines() if line]
missing = sorted(set(actual) - set(expected))
extra = sorted(set(expected) - set(actual))
duplicates = sorted({item for item in expected if expected.count(item) > 1})
if expected != actual or missing or extra or duplicates:
    raise SystemExit(
        f"gate registry mismatch for {profile}: missing={missing} extra={extra} "
        f"duplicates={duplicates} order_match={expected == actual}")
PY
  done
}

if [ "$SELFTEST" = 1 ]; then
  tmp_root="${TMPDIR:-$ROOT/.git-exclude/tmp}"
  mkdir -p "$tmp_root"
  tmp="$(mktemp -d "$tmp_root/gate-registry-selftest.XXXXXX")"
  trap 'rm -rf "$tmp"' EXIT
  python3 - "$REGISTRY" "$tmp" <<'PY'
import copy, json, os, sys
source, out = sys.argv[1:]
with open(source, encoding="utf-8") as f:
    good = json.load(f)
missing = copy.deepcopy(good)
missing["profiles"]["full-release"]["required_gate_ids"].remove("build")
with open(os.path.join(out, "missing.json"), "w", encoding="utf-8") as f:
    json.dump(missing, f)
stale = copy.deepcopy(good)
stale["gate_registry"] = "kroopt-gate/v2"
with open(os.path.join(out, "stale.json"), "w", encoding="utf-8") as f:
    json.dump(stale, f)
PY
  if check_registry "$tmp/missing.json" >/dev/null 2>&1; then
    echo "selftest FAIL: registry missing a required gate id was accepted"; exit 1
  fi
  if check_registry "$tmp/stale.json" >/dev/null 2>&1; then
    echo "selftest FAIL: stale registry id was accepted"; exit 1
  fi
  check_registry "$REGISTRY"
  echo "OK: gate registry self-test passed (missing ids and stale registry fail)"
  exit 0
fi

check_registry "$REGISTRY"
echo "OK: gate registry exactly matches emitted full-release and pr gate ids"
