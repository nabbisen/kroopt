#!/usr/bin/env bash
# scripts/gate.sh — the canonical kroopt ship gate (RFC 030).
#
# ONE gate runner shared by ci.yml and release.yml, so CI and the release gate can
# never diverge. Runs the gate set for a profile, captures per-gate stdout/stderr +
# timings + pass/fail, and writes a machine-readable ledger (gate-out/gate-ledger.json)
# plus a human summary (gate-out/GATE-RUN.md). The release sidecar's gates[] is a direct
# transcription of this ledger — never a hand-authored reconstruction.
#
# Profiles:
#   full-release  (default) — every gate, incl. sanitizers + all interop. Required for release.
#   pr                       — full-release minus the expensive native/live gates
#                              (sanitizers + interop); for fast PR feedback. Explicit, recorded
#                              in the ledger; NEVER a silent ad-hoc subset.
#
# Exit 0 iff every required gate in the profile passed. The ledger is written even on failure
# (with the failed gate marked) so CI retains diagnosable evidence.
#
# Requires lake/lean on PATH (the workflow sets up the toolchain before calling this) and,
# for the interop/sanitizer gates, gcc/openssl/python3(+cryptography). Run from anywhere.
set -u

PROFILE="full-release"
while [ $# -gt 0 ]; do
  case "$1" in
    --profile) PROFILE="${2:-}"; shift 2 ;;
    --profile=*) PROFILE="${1#*=}"; shift ;;
    -h|--help) echo "usage: gate.sh [--profile full-release|pr]"; exit 0 ;;
    *) echo "gate.sh: unknown arg '$1'" >&2; exit 2 ;;
  esac
done
case "$PROFILE" in full-release|pr) ;; *) echo "gate.sh: unknown profile '$PROFILE'" >&2; exit 2 ;; esac

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
GATE_REGISTRY="kroopt-gate/v1"
OUT="$ROOT/gate-out"
LOGS="$OUT/logs"
rm -rf "$OUT"; mkdir -p "$LOGS"
RESULTS="$OUT/results.tsv"
: > "$RESULTS"

# --- gate table: "id<TAB>kind<TAB>name<TAB>command" -------------------------------------
# kind drives pass detection (exit code alone is insufficient: test suites can exit 0 while
# reporting failures, so suites also scan for FAILED/FAIL).
SUITES="capabilities close config conn correspondence crypto e2e flight hacl handshake \
hardening https keyschedule model nativesecret nonce parse provision realprovider record \
record13 replay scheduledriver socket socketdriver trace wire"

GATELIST="$OUT/gates.txt"; : > "$GATELIST"
emit() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$GATELIST"; }

emit build build "lake build" "lake build"
for s in $SUITES; do emit "suite:$s" suite "$s test suite" "lake exe kroopt-$s-test"; done
emit axioms   ok    "axiom audit"                 "bash scripts/check-axioms.sh"
emit deps     ok    "dependency purity"           "bash scripts/check-deps.sh"
emit hygiene  ok    "hygiene"                      "bash scripts/check-hygiene.sh"
emit provenance ok  "HACL* vendored-byte provenance" "bash scripts/check-hacl-provenance.sh"
emit fuzz     fuzz  "parser fuzz (20000)"          "lake exe kroopt-parse-fuzz 20000"
if [ "$PROFILE" = "full-release" ]; then
  emit sanitizers     san     "ASan/UBSan sanitizer harness"            "bash scripts/sanitizer-check.sh"
  emit interop:tls    interop "live TLS 1.3 interop (OpenSSL/Python/curl)" "bash scripts/tls-interop.sh"
  emit interop:ed25519 interop "Ed25519 CertificateVerify interop (HACL* vs OpenSSL)" "bash scripts/ed25519-interop.sh"
  emit interop:record interop "record-layer interop (Record13 vs Python cryptography)" "bash scripts/record-interop.sh"
fi

# --- pass detection ---------------------------------------------------------------------
passed() { # kind exit_code logfile
  k="$1"; ec="$2"; log="$3"
  case "$k" in
    build)   [ "$ec" -eq 0 ] ;;
    suite)   [ "$ec" -eq 0 ] && ! grep -qE 'FAILED|FAIL ' "$log" ;;
    ok)      grep -qE '^OK:' "$log" ;;
    fuzz)    grep -q 'no invariant violations' "$log" ;;
    san)     grep -qiE 'ALL sanitizer.*passed|sanitizer.*clean' "$log" ;;
    interop) grep -qiE 'ALL .*passed' "$log" ;;
    *)       [ "$ec" -eq 0 ] ;;
  esac
}

# --- run gates (no pipe into the loop, so state persists) -------------------------------
ALLPASS=true
N=0
while IFS="$(printf '\t')" read -r gid kind gname gcmd; do
  N=$((N+1))
  sout="$LOGS/$(printf '%s' "$gid" | tr '/:' '__').stdout"
  serr="$LOGS/$(printf '%s' "$gid" | tr '/:' '__').stderr"
  started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  t0=$(date +%s%N)
  sh -c "$gcmd" >"$sout" 2>"$serr"; ec=$?
  t1=$(date +%s%N)
  dur=$(( (t1 - t0) / 1000000 ))
  if passed "$kind" "$ec" "$sout"; then status=pass; else status=fail; ALLPASS=false; fi
  oh="$(sha256sum "$sout" | cut -d' ' -f1)"
  eh="$(sha256sum "$serr" | cut -d' ' -f1)"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$gid" "$kind" "$gname" "$gcmd" "$status" "$ec" "$dur" "$started" \
    "logs/$(basename "$sout")" "$oh" "logs/$(basename "$serr")" "$eh" "required" >> "$RESULTS"
  printf '  [%-4s] %-46s %5sms\n' "$status" "$gid" "$dur"
done < "$GATELIST"

# --- assemble ledger + human summary (python: robust JSON; available in CI + locally) ---
KROOPT_PROFILE="$PROFILE" KROOPT_REGISTRY="$GATE_REGISTRY" KROOPT_ALLPASS="$ALLPASS" \
KROOPT_OUT="$OUT" KROOPT_ROOT="$ROOT" python3 - "$RESULTS" <<'PY'
import json, os, subprocess, sys, datetime
results, out, root = sys.argv[1], os.environ["KROOPT_OUT"], os.environ["KROOPT_ROOT"]

def sh(p):
    try:
        import hashlib
        return hashlib.sha256(open(p,"rb").read()).hexdigest()
    except OSError:
        return None

def git(args):
    try:
        return subprocess.run(["git","-C",root]+args, capture_output=True, text=True).stdout.strip()
    except Exception:
        return ""

has_git = os.path.isdir(os.path.join(root, ".git")) and bool(git(["rev-parse","--git-dir"]))
if has_git:
    commit = git(["rev-parse","HEAD"]) or "unavailable"
    ref = git(["rev-parse","--abbrev-ref","HEAD"]) or "unavailable"
    dirty = bool(git(["status","--porcelain"]))
    gen_ctx = "git"
else:
    commit, ref, dirty, gen_ctx = "unavailable-local", "unavailable-local", "unknown-local", "local-dry-run"

gates, allpass = [], True
with open(results) as f:
    for ln in f:
        p = ln.rstrip("\n").split("\t")
        if len(p) != 13: continue
        gid,kind,name,cmd,status,ec,dur,started,olog,osha,elog,esha,crit = p
        if status != "pass": allpass = False
        gates.append({
            "id": gid, "name": name, "command": cmd, "kind": kind,
            "status": status, "exit_code": int(ec), "duration_ms": int(dur),
            "timestamp_utc": started, "criticality": crit,
            "stdout_log": olog, "stdout_sha256": osha,
            "stderr_log": elog, "stderr_sha256": esha,
        })

policy_scripts = ["scripts/gate.sh","scripts/check-axioms.sh","scripts/check-deps.sh",
                  "scripts/check-hygiene.sh","scripts/check-hacl-provenance.sh",
                  "scripts/sanitizer-check.sh","scripts/tls-interop.sh",
                  "scripts/ed25519-interop.sh","scripts/record-interop.sh"]
gate_policy = {os.path.basename(s).replace("-","_").replace(".sh","")+"_sha256": sh(os.path.join(root,s))
               for s in policy_scripts if sh(os.path.join(root,s))}

ledger = {
    "gate_registry": os.environ["KROOPT_REGISTRY"],
    "release_profile": os.environ["KROOPT_PROFILE"],
    "required_gates_passed": allpass,
    "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "generation_context": gen_ctx,
    "git_commit": commit, "git_ref": ref, "git_dirty": dirty,
    "github_run_id": os.environ.get("GITHUB_RUN_ID","local"),
    "github_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT","local"),
    "github_workflow": os.environ.get("GITHUB_WORKFLOW","local"),
    "github_job": os.environ.get("GITHUB_JOB","local"),
    "runner_os": os.environ.get("RUNNER_OS", os.uname().sysname),
    "runner_arch": os.environ.get("RUNNER_ARCH", os.uname().machine),
    "gate_count": len(gates),
    "gate_policy": gate_policy,
    "gates": gates,
}
with open(os.path.join(out,"gate-ledger.json"),"w") as f:
    json.dump(ledger, f, indent=2); f.write("\n")

npass = sum(1 for g in gates if g["status"]=="pass")
lines = [
    "# kroopt gate run","",
    f"- **profile**: `{ledger['release_profile']}`  ",
    f"- **result**: {'PASS' if allpass else 'FAIL'} ({npass}/{len(gates)} gates)  ",
    f"- **timestamp_utc**: {ledger['timestamp_utc']}  ",
    f"- **git**: `{commit}` ({ref}, dirty={str(dirty).lower()}) — context `{gen_ctx}`  ",
    f"- **runner**: {ledger['runner_os']}/{ledger['runner_arch']}  ",
    f"- **gate_registry**: `{ledger['gate_registry']}`","",
    "| gate | status | ms |","|---|---|---|",
]
for g in gates:
    lines.append(f"| `{g['id']}` | {g['status']} | {g['duration_ms']} |")
lines += ["","Per-gate stdout/stderr hashes are recorded in `gate-ledger.json`. Raw logs are retained",
          "as CI build artifacts per repository retention policy; this file is the durable",
          "human-readable summary. This is the development/release gate ledger, not a release",
          "attestation — the sidecar generator (RFC 030 loop-2) transcribes these into",
          "`release-verification.json` only on a real tagged release.",""]
open(os.path.join(out,"GATE-RUN.md"),"w").write("\n".join(lines))
print(f"\ngate-ledger.json + GATE-RUN.md written to {out}/ ({npass}/{len(gates)} pass, profile={ledger['release_profile']})")
PY

if [ "$ALLPASS" = "true" ]; then
  echo "GATE: PASS ($N gates, profile=$PROFILE)"; exit 0
else
  echo "GATE: FAIL (profile=$PROFILE) — see $OUT/gate-ledger.json"; exit 1
fi
