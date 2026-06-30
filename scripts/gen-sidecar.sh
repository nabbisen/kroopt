#!/bin/sh
# gen-sidecar.sh — assemble the release-verification sidecar (henret manifest_schema 1) for a
# kroopt source tarball (RFC 030 Stage B).
#
# Reads (never invents): the gate ledger (gate-out/gate-ledger.json), the HACL provenance manifest
# (Kroopt/Native/hacl-provenance/HACL-PROVENANCE.json), the source tarball, lake-manifest.json,
# lean-toolchain, and the human GATE-RUN.md. HACL* is declared as a vendored-source `dependencies`
# entry (not a stack edge). Run-context is sourced from the ledger and labeled honestly: a
# real-release profile REQUIRES a real git commit and a clean tree, otherwise the sidecar is a
# local-dry-run that must not be published.
#
# Usage: bash scripts/gen-sidecar.sh [--profile local-dry-run|real-release] [VERSION]
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PROFILE="local-dry-run"
VERSION=""
while [ $# -gt 0 ]; do
  case "$1" in
    --profile) PROFILE="$2"; shift 2 ;;
    *) VERSION="$1"; shift ;;
  esac
done
[ -n "$VERSION" ] || VERSION=$(grep -m1 -oE '^## \[[0-9]+\.[0-9]+\.[0-9]+\]' CHANGELOG.md | tr -d '#[] ')

TARBALL="${OUT_DIR:-$ROOT/dist}/kroopt-$VERSION.tar.gz"
OUT="${OUT_DIR:-$ROOT/dist}/kroopt-$VERSION.release-verification.json"

exec python3 - "$ROOT" "$VERSION" "$PROFILE" "$TARBALL" "$OUT" <<'PY'
import sys, os, json, hashlib, datetime

root, version, profile, tarball, out = sys.argv[1:6]
def fail(m): print("FAIL: " + m); sys.exit(1)
def sha(p):
    h=hashlib.sha256()
    with open(p,"rb") as f:
        for c in iter(lambda:f.read(65536), b""): h.update(c)
    return h.hexdigest()

led_path = os.path.join(root, "gate-out", "gate-ledger.json")
man_path = os.path.join(root, "Kroopt", "Native", "hacl-provenance", "HACL-PROVENANCE.json")
gaterun  = os.path.join(root, "gate-out", "GATE-RUN.md")
lakem    = os.path.join(root, "lake-manifest.json")
toolch   = os.path.join(root, "lean-toolchain")

for p in (led_path, man_path, gaterun, lakem, toolch):
    if not os.path.isfile(p): fail("required input missing: %s" % os.path.relpath(p, root))
if not os.path.isfile(tarball): fail("source tarball missing: %s (run package-release.sh first)" % tarball)

led = json.load(open(led_path, encoding="utf-8"))
man = json.load(open(man_path, encoding="utf-8"))

# --- run-context honesty + profile guard -------------------------------------------------
git_commit = led.get("git_commit", "unavailable-local")
git_dirty  = led.get("git_dirty", "unknown-local")
gen_ctx    = led.get("generation_context", "local-dry-run")
HEX = set("0123456789abcdef")
real_git = isinstance(git_commit, str) and len(git_commit) == 40 and all(c in HEX for c in git_commit)

if profile == "real-release":
    if not real_git:
        fail("real-release requires a real git commit; ledger git_commit=%r (refusing to fabricate)" % git_commit)
    if git_dirty not in (False, "false"):
        fail("real-release requires a clean tree; ledger git_dirty=%r" % git_dirty)
    if not led.get("required_gates_passed"):
        fail("real-release requires required_gates_passed=true in the ledger")
    attestation_status = "release-attestation"
    must_not_publish = False
elif profile == "local-dry-run":
    attestation_status = "local-dry-run-not-an-attestation"
    must_not_publish = True
else:
    fail("unknown --profile %r (use local-dry-run|real-release)" % profile)

# --- gates: reshape from the ledger (do not re-run) ---------------------------------------
gates = []
for g in led.get("gates", []):
    gates.append({
        "id": g.get("id"), "name": g.get("name"), "command": g.get("command"),
        "status": g.get("status"), "duration_ms": g.get("duration_ms"),
        "criticality": g.get("criticality", "required"),
        "stdout_log": g.get("stdout_log"), "stdout_sha256": g.get("stdout_sha256"),
        "stderr_log": g.get("stderr_log"), "stderr_sha256": g.get("stderr_sha256"),
    })

# --- HACL* vendored-source dependency (NOT a stack edge) ----------------------------------
hacl_dep = {
    "name": "hacl-star-evercrypt",
    "kind": "vendored-source",
    "upstream_repo_url": man["upstream_repo_url"],
    "upstream_release_tag": man["upstream_release_tag"],
    "upstream_version": "0.4.5",
    "upstream_artifact_name": man["upstream_artifact_name"],
    "upstream_artifact_sha256": man["upstream_artifact_sha256"],
    "source_tree_hash_method": man["source_tree_hash_method"],
    "source_tree_sha256": man["source_tree_sha256"],
    "vendored_file_count": man["vendored_upstream_file_count"],
    "local_modifications": man["local_modifications"],
    "provenance_status": man["provenance_status"],
    "provenance_manifest": "Kroopt/Native/hacl-provenance/HACL-PROVENANCE.json",
    "provenance_note": "Byte-identical vendored subset of the named upstream artifact; rechecked every "
                       "build by scripts/check-hacl-provenance.sh. Anchored by artifact sha256 + release "
                       "tag (no bare upstream commit is claimed). See RFC 043.",
}

sidecar = {
    "manifest_schema": 1,
    "generated_by": "kroopt/gen-sidecar v1",
    "package": "kroopt",
    "version": version,
    "release_profile": profile,
    "attestation_status": attestation_status,
    "must_not_publish": must_not_publish,
    "gate_registry": led.get("gate_registry"),
    "required_gates_passed": led.get("required_gates_passed"),
    "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "generation_context": gen_ctx,
    "git_commit": git_commit,
    "git_ref": led.get("git_ref"),
    "git_dirty": git_dirty,
    "ci_run": {
        "github_run_id": led.get("github_run_id"),
        "github_run_attempt": led.get("github_run_attempt"),
        "github_workflow": led.get("github_workflow"),
        "github_job": led.get("github_job"),
    },
    "log_retention_note": "Raw per-gate stdout/stderr logs are CI artifacts (gate-out/logs/); they are "
                          "hashed here for integrity but may be subject to CI retention limits. The "
                          "human-readable GATE-RUN.md is the durable summary.",
    "source_archive": {
        "name": os.path.basename(tarball),
        "sha256": sha(tarball),
        "size_bytes": os.path.getsize(tarball),
    },
    "tarball_sha256": sha(tarball),
    "lake_manifest_sha256": sha(lakem),
    "lean_toolchain_sha256": sha(toolch),
    "os": led.get("runner_os"),
    "runner": led.get("runner_arch"),
    "gate_policy": led.get("gate_policy", {}),
    "gates": gates,
    "human_summary": {"name": "GATE-RUN.md", "sha256": sha(gaterun)},
    "validation_reports": [],
    "runtime_package": {},
    "dependencies": [hacl_dep],
}

with open(out, "w", encoding="utf-8") as f:
    json.dump(sidecar, f, indent=2, ensure_ascii=False)
    f.write("\n")

print("OK: sidecar written: %s" % os.path.relpath(out, root))
print("  profile=%s  attestation_status=%s  must_not_publish=%s" % (profile, attestation_status, must_not_publish))
print("  source_archive.sha256=%s  size=%d" % (sidecar["source_archive"]["sha256"], sidecar["source_archive"]["size_bytes"]))
print("  HACL source_tree_sha256=%s (tag %s)" % (hacl_dep["source_tree_sha256"], hacl_dep["upstream_release_tag"]))
PY
