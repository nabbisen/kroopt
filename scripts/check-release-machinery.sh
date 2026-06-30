#!/bin/sh
# check-release-machinery.sh — regression tests for the RFC 030 Stage B release machinery.
#
# Covers the two release-readiness blockers and the profile-consistency hardening:
#   - gate pass-detection requires exit code 0 (gate.sh --selftest-passdetect);
#   - gen-sidecar --profile real-release requires a canonical full-release ledger
#     (rejects pr profile, missing required gate, mismatched registry, a non-pass gate;
#      accepts a well-formed full-release ledger);
#   - check-provenance rejects contradictory profile metadata even without --require-release.
#
# Synthetic ledgers carry a fake-but-well-formed git context so the real-release path is reachable
# in environments without git; no real ledger/sidecar/tarball is touched.
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
FAILS=0
pass() { echo "  ok   - $1"; }
bad()  { echo "  FAIL - $1"; FAILS=$((FAILS+1)); }
# expect a command to exit nonzero
expect_fail() { if "$@" >/tmp/rm.out 2>&1; then return 1; else return 0; fi; }
expect_ok()   { if "$@" >/tmp/rm.out 2>&1; then return 0; else return 1; fi; }

echo "[1] gate pass-detection requires exit code 0"
if expect_ok bash scripts/gate.sh --selftest-passdetect; then pass "selftest passed"; else bad "selftest failed"; fi

echo "[2] gen-sidecar --profile real-release ledger validation"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
V="9.9.9"
: > "$TMP/kroopt-$V.tar.gz"   # dummy tarball so the existence check passes; we fail earlier on ledger

# Build a well-formed full-release ledger from the registry, with a fake clean git context.
python3 - "$ROOT" "$TMP" <<'PY'
import sys, os, json
root, tmp = sys.argv[1], sys.argv[2]
reg = json.load(open(os.path.join(root,"scripts","gate-registry.json")))
ids = reg["profiles"]["full-release"]["required_gate_ids"]
def gate(i): return {"id":i,"name":i,"command":i,"status":"pass","exit_code":0,"duration_ms":1,
                     "timestamp_utc":"2026-01-01T00:00:00Z","criticality":"required",
                     "stdout_log":"logs/x","stdout_sha256":"0"*64,"stderr_log":"logs/y","stderr_sha256":"0"*64}
def led(**kw):
    d={"gate_registry":"kroopt-gate/v1","release_profile":"full-release","required_gates_passed":True,
       "registry_consistent":True,"git_commit":"a"*40,"git_ref":"refs/tags/v9.9.9","git_dirty":False,
       "generation_context":"git","github_run_id":"1","runner_os":"Linux","runner_arch":"x86_64",
       "gate_count":len(ids),"gate_policy":{},"gates":[gate(i) for i in ids]}
    d.update(kw); return d
json.dump(led(), open(os.path.join(tmp,"led-good.json"),"w"))
json.dump(led(release_profile="pr"), open(os.path.join(tmp,"led-pr.json"),"w"))
# missing sanitizers gate
g=led(); g["gates"]=[x for x in g["gates"] if x["id"]!="sanitizers"]; g["gate_count"]=len(g["gates"])
json.dump(g, open(os.path.join(tmp,"led-missing-san.json"),"w"))
# mismatched registry
json.dump(led(gate_registry="kroopt-gate/v0"), open(os.path.join(tmp,"led-badreg.json"),"w"))
# a required gate not pass
g=led(); g["gates"][5]["status"]="fail"
json.dump(g, open(os.path.join(tmp,"led-notpass.json"),"w"))
PY

run_gen() { OUT_DIR="$TMP" bash scripts/gen-sidecar.sh --profile real-release --ledger "$1" "$V"; }
if expect_ok   run_gen "$TMP/led-good.json";        then pass "accepts well-formed full-release ledger"; else bad "rejected a valid full-release ledger"; fi
if expect_fail run_gen "$TMP/led-pr.json";          then pass "rejects pr-profile ledger"; else bad "accepted pr-profile ledger"; fi
if expect_fail run_gen "$TMP/led-missing-san.json"; then pass "rejects ledger missing sanitizers"; else bad "accepted ledger missing sanitizers"; fi
if expect_fail run_gen "$TMP/led-badreg.json";      then pass "rejects mismatched gate_registry"; else bad "accepted mismatched gate_registry"; fi
if expect_fail run_gen "$TMP/led-notpass.json";     then pass "rejects ledger with a non-pass gate"; else bad "accepted ledger with a non-pass gate"; fi

echo "[3] check-provenance rejects contradictory profile metadata (no --require-release)"
# craft a local-dry-run sidecar that lies about must_not_publish; must fail at profile-consistency
: > "$TMP/kroopt-$V.tar.gz"
python3 - "$TMP" "$V" <<'PY'
import sys, os, json
tmp, v = sys.argv[1], sys.argv[2]
sc = {"manifest_schema":1,"version":v,"release_profile":"local-dry-run",
      "must_not_publish":False,"attestation_status":"local-dry-run-not-an-attestation",
      "source_archive":{"name":"kroopt-%s.tar.gz"%v,"sha256":"0"*64,"size_bytes":0}}
json.dump(sc, open(os.path.join(tmp,"kroopt-%s.release-verification.json"%v),"w"))
PY
if expect_fail env OUT_DIR="$TMP" bash scripts/check-provenance.sh "$V"; then
  grep -q "must_not_publish" /tmp/rm.out && pass "rejects local-dry-run with must_not_publish=false" || bad "failed but not on profile-consistency"
else
  bad "accepted contradictory profile metadata"
fi

echo ""
if [ "$FAILS" -eq 0 ]; then echo "OK: release-machinery regression tests passed"; exit 0
else echo "FAIL: $FAILS release-machinery test(s) failed"; exit 1; fi
