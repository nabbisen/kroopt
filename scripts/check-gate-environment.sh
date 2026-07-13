#!/usr/bin/env bash
# Validate the declared RFC 051 host contract before expensive canonical gates run.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROFILE="full-release"
SELFTEST=0
while [ $# -gt 0 ]; do
  case "$1" in
    --profile) PROFILE="${2:-}"; shift 2 ;;
    --profile=*) PROFILE="${1#*=}"; shift ;;
    --selftest) SELFTEST=1; shift ;;
    -h|--help) echo "usage: check-gate-environment.sh [--profile full-release|pr] [--selftest]"; exit 0 ;;
    *) echo "check-gate-environment: unknown arg '$1'" >&2; exit 2 ;;
  esac
done
case "$PROFILE" in full-release|pr) ;; *) echo "unknown profile '$PROFILE'" >&2; exit 2 ;; esac

need_cmd() {
  local cmd="$1"
  if [ "${KROOPT_GATE_SELFTEST:-0}" = 1 ] && [ "${KROOPT_GATE_TEST_MISSING:-}" = "$cmd" ]; then
    echo "missing required command: $cmd" >&2
    return 1
  fi
  command -v "$cmd" >/dev/null 2>&1 || { echo "missing required command: $cmd" >&2; return 1; }
}

check_environment() {
  local cmd crypto_version openssl_version curl_version mdbook_version
  for cmd in lean lake leanc gcc python3 mdbook; do need_cmd "$cmd" || return 1; done

  local pinned lean_major gcc_major py_major py_minor
  pinned="$(sed -n 's#.*:v\([0-9][0-9.]*\).*#\1#p' "$ROOT/lean-toolchain")"
  lean_major="$(lean --version | sed -n 's/Lean (version \([0-9][0-9.]*\).*/\1/p')"
  [ -n "$pinned" ] && [ "$lean_major" = "$pinned" ] || {
    echo "Lean version mismatch: pinned=${pinned:-unparsed}, active=${lean_major:-unparsed}" >&2
    return 1
  }

  gcc_major="$(gcc -dumpversion | cut -d. -f1)"
  case "$gcc_major" in 12|13|14|15|16) ;; *)
    echo "unsupported GCC major $gcc_major (supported: 12 through 16)" >&2; return 1 ;;
  esac

  read -r py_major py_minor <<EOF
$(python3 -c 'import sys; print(sys.version_info.major, sys.version_info.minor)')
EOF
  [ "$py_major" -eq 3 ] && [ "$py_minor" -ge 10 ] && [ "$py_minor" -le 14 ] || {
    echo "unsupported Python $py_major.$py_minor (supported: 3.10 through 3.14)" >&2
    return 1
  }
  mdbook_version="$(mdbook --version | awk '{print $2}' | sed 's/^v//')"
  case "$mdbook_version" in 0.5.*) ;; *)
    echo "unsupported mdBook $mdbook_version (required: 0.5.x)" >&2; return 1 ;;
  esac

  if [ "$PROFILE" = full-release ]; then
    for cmd in openssl curl; do need_cmd "$cmd" || return 1; done
    openssl version | grep -qE '^OpenSSL 3\.' || {
      echo "unsupported OpenSSL (required: 3.x)" >&2; return 1;
    }
    curl --version | head -1 | grep -qE '^curl 8\.' || {
      echo "unsupported curl (required: 8.x)" >&2; return 1;
    }
    if [ "${KROOPT_GATE_SELFTEST:-0}" = 1 ] && [ "${KROOPT_GATE_TEST_MISSING:-}" = cryptography ]; then
      echo "missing required Python module: cryptography" >&2
      return 1
    fi
    crypto_version="$(python3 - <<'PY'
import sys
try:
    import cryptography
except ImportError:
    print("missing required Python module: cryptography", file=sys.stderr)
    raise SystemExit(1)
major = int(cryptography.__version__.split(".", 1)[0])
if major not in (46, 47):
    print(f"unsupported cryptography {cryptography.__version__} (required: >=46,<48)", file=sys.stderr)
    raise SystemExit(1)
print(cryptography.__version__)
PY
    )"
    openssl_version="$(openssl version | awk '{print $2}')"
    curl_version="$(curl --version | head -1 | awk '{print $2}')"
  fi

  if [ "$PROFILE" = full-release ]; then
    printf 'OK: gate environment supported (Lean %s, GCC %s, Python %s.%s, mdBook %s, OpenSSL %s, curl %s, cryptography %s, profile=%s)\n' \
      "$lean_major" "$gcc_major" "$py_major" "$py_minor" "$mdbook_version" "$openssl_version" "$curl_version" \
      "$crypto_version" "$PROFILE"
  else
    printf 'OK: gate environment supported (Lean %s, GCC %s, Python %s.%s, mdBook %s, profile=%s)\n' \
      "$lean_major" "$gcc_major" "$py_major" "$py_minor" "$mdbook_version" "$PROFILE"
  fi
}

if [ "$SELFTEST" = 1 ]; then
  tmp_root="${TMPDIR:-$ROOT/.git-exclude/tmp}"
  mkdir -p "$tmp_root"
  log="$(mktemp "$tmp_root/gate-env-selftest.XXXXXX")"
  trap 'rm -f "$log"' EXIT
  if KROOPT_GATE_SELFTEST=1 KROOPT_GATE_TEST_MISSING=python3 \
      "$0" --profile pr >"$log" 2>&1; then
    echo "selftest FAIL: missing command was accepted"; exit 1
  fi
  grep -q 'missing required command: python3' "$log" || {
    echo "selftest FAIL: missing-command failure reason not observed"; exit 1;
  }
  if KROOPT_GATE_SELFTEST=1 KROOPT_GATE_TEST_MISSING=cryptography \
      "$0" --profile full-release >"$log" 2>&1; then
    echo "selftest FAIL: missing Python dependency was accepted"; exit 1
  fi
  grep -q 'missing required Python module: cryptography' "$log" || {
    echo "selftest FAIL: missing-module failure reason not observed"; exit 1;
  }
  echo "OK: gate environment self-test passed (missing dependencies fail)"
  exit 0
fi

check_environment
