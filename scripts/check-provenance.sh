#!/bin/sh
# check-provenance.sh — self-verify a kroopt release sidecar against on-disk artifacts (RFC 030 Stage B).
#
# Recomputes and compares every hash the sidecar claims: source tarball (name/size/sha256),
# lake-manifest, lean-toolchain, each gate's stdout/stderr log, the gate-policy script hashes, the
# human GATE-RUN.md, and the HACL* vendored-source tree (by re-running check-hacl-provenance.sh and
# matching the dependency's source_tree_sha256 to the manifest). Rejects stub/placeholder sentinels,
# non-hex hashes, and forbidden paths inside the tarball.
#
# Default mode verifies internal consistency and reports the profile. With --require-release it also
# enforces a real, publishable release: release_profile=real-release, must_not_publish=false, a real
# git commit, and a clean tree.
#
# Usage: bash scripts/check-provenance.sh [--require-release] [VERSION]
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

REQUIRE_RELEASE=0; VERSION=""
while [ $# -gt 0 ]; do
  case "$1" in
    --require-release) REQUIRE_RELEASE=1; shift ;;
    *) VERSION="$1"; shift ;;
  esac
done
[ -n "$VERSION" ] || VERSION=$(grep -m1 -oE '^## \[[0-9]+\.[0-9]+\.[0-9]+\]' CHANGELOG.md | tr -d '#[] ')

# Re-run the offline HACL provenance gate first (tree == manifest); fail fast if it fails.
if ! bash scripts/check-hacl-provenance.sh >/dev/null 2>&1; then
  echo "FAIL: check-hacl-provenance.sh failed (HACL tree != manifest)"; exit 1
fi

SIDECAR="${OUT_DIR:-$ROOT/dist}/kroopt-$VERSION.release-verification.json"
TARBALL="${OUT_DIR:-$ROOT/dist}/kroopt-$VERSION.tar.gz"

exec python3 - "$ROOT" "$VERSION" "$REQUIRE_RELEASE" "$SIDECAR" "$TARBALL" <<'PY'
import sys, os, json, hashlib
root, version, require_release, sidecar_path, tarball = sys.argv[1], sys.argv[2], sys.argv[3]=="1", sys.argv[4], sys.argv[5]
def fail(m): print("FAIL: " + m); sys.exit(1)
def sha(p):
    h=hashlib.sha256()
    with open(p,"rb") as f:
        for c in iter(lambda:f.read(65536), b""): h.update(c)
    return h.hexdigest()
HEX=set("0123456789abcdef")
def hex64(s): return isinstance(s,str) and len(s)==64 and all(c in HEX for c in s)

if not os.path.isfile(sidecar_path): fail("sidecar missing: %s" % sidecar_path)
if not os.path.isfile(tarball): fail("tarball missing: %s" % tarball)
raw = open(sidecar_path, encoding="utf-8").read()
for bad in ("STUB","PLACEHOLDER","NOT-COMPUTED","NOT_COMPUTED","TODO","FIXME"):
    if bad in raw.upper(): fail("stub/placeholder sentinel in sidecar: %s" % bad)
s = json.loads(raw)

# 1) schema + version
if s.get("manifest_schema") != 1: fail("manifest_schema != 1")
if s.get("version") != version: fail("version mismatch: sidecar %r != %r" % (s.get("version"), version))

# 1b) profile consistency — reject contradictory profile metadata even without --require-release
prof = s.get("release_profile")
mnp = s.get("must_not_publish")
ast = s.get("attestation_status")
if prof == "local-dry-run":
    if mnp is not True: fail("local-dry-run must imply must_not_publish=true (got %r)" % mnp)
    if ast != "local-dry-run-not-an-attestation":
        fail("local-dry-run must imply attestation_status=local-dry-run-not-an-attestation (got %r)" % ast)
elif prof == "real-release":
    if mnp is not False: fail("real-release must imply must_not_publish=false (got %r)" % mnp)
    if ast != "release-attestation":
        fail("real-release must imply attestation_status=release-attestation (got %r)" % ast)
else:
    fail("unknown release_profile: %r" % prof)

# 1c) source_archive name must be canonical kroopt-<version>.tar.gz
if s.get("source_archive", {}).get("name") != ("kroopt-%s.tar.gz" % version):
    fail("source_archive.name not canonical kroopt-%s.tar.gz" % version)

# 2) source archive: name / size / sha256
sa = s.get("source_archive", {})
if sa.get("name") != os.path.basename(tarball): fail("source_archive.name mismatch")
if sa.get("size_bytes") != os.path.getsize(tarball): fail("source_archive.size_bytes mismatch")
t_sha = sha(tarball)
if not hex64(sa.get("sha256")) or sa.get("sha256") != t_sha:
    fail("source_archive.sha256 mismatch (sidecar %s, disk %s)" % (sa.get("sha256"), t_sha))
if s.get("tarball_sha256") != t_sha: fail("tarball_sha256 mismatch")

# 3) lake-manifest + lean-toolchain
if s.get("lake_manifest_sha256") != sha(os.path.join(root,"lake-manifest.json")): fail("lake_manifest_sha256 mismatch")
if s.get("lean_toolchain_sha256") != sha(os.path.join(root,"lean-toolchain")): fail("lean_toolchain_sha256 mismatch")

# 4) human summary
hs = s.get("human_summary", {})
if hs.get("name") != "GATE-RUN.md" or hs.get("sha256") != sha(os.path.join(root,"gate-out","GATE-RUN.md")):
    fail("human_summary (GATE-RUN.md) hash mismatch")

# 5) gate log hashes (recompute each referenced log) + gate-policy script hashes
go = os.path.join(root,"gate-out")
for g in s.get("gates", []):
    for logkey, shakey in (("stdout_log","stdout_sha256"),("stderr_log","stderr_sha256")):
        lp = g.get(logkey)
        if not lp: continue
        ap = os.path.join(go, lp)
        if not os.path.isfile(ap): fail("gate log missing: %s (%s)" % (lp, g.get("id")))
        if not hex64(g.get(shakey)) or g.get(shakey) != sha(ap):
            fail("gate log hash mismatch for %s/%s" % (g.get("id"), logkey))
gp = s.get("gate_policy", {})
name2script = {
    "gate_sha256":"scripts/gate.sh","check_axioms_sha256":"scripts/check-axioms.sh",
    "check_deps_sha256":"scripts/check-deps.sh","check_hygiene_sha256":"scripts/check-hygiene.sh",
    "check_hacl_provenance_sha256":"scripts/check-hacl-provenance.sh",
    "sanitizer_check_sha256":"scripts/sanitizer-check.sh","tls_interop_sha256":"scripts/tls-interop.sh",
    "ed25519_interop_sha256":"scripts/ed25519-interop.sh","record_interop_sha256":"scripts/record-interop.sh",
}
for k,v in gp.items():
    sp = name2script.get(k)
    if sp and os.path.isfile(os.path.join(root,sp)):
        if not hex64(v) or v != sha(os.path.join(root,sp)):
            fail("gate_policy hash mismatch for %s" % k)

# 6) HACL dependency must match the manifest (which the gate already validated)
man = json.load(open(os.path.join(root,"Kroopt","Native","hacl-provenance","HACL-PROVENANCE.json"), encoding="utf-8"))
deps = [d for d in s.get("dependencies", []) if d.get("name")=="hacl-star-evercrypt"]
if len(deps) != 1: fail("expected exactly one hacl-star-evercrypt dependency")
hd = deps[0]
if hd.get("kind") != "vendored-source": fail("HACL dependency must be kind=vendored-source")
if hd.get("source_tree_sha256") != man["source_tree_sha256"]: fail("HACL source_tree_sha256 != manifest")
if hd.get("upstream_artifact_sha256") != man["upstream_artifact_sha256"]: fail("HACL upstream_artifact_sha256 != manifest")
if hd.get("upstream_release_tag") != man["upstream_release_tag"]: fail("HACL upstream_release_tag != manifest")
if hd.get("local_modifications") != []: fail("HACL local_modifications must be [] for inherited claim")

# 7) all top-level *_sha256 fields are real hex (no placeholder hashes)
for k,v in s.items():
    if k.endswith("_sha256") and not hex64(v): fail("non-hex top-level hash: %s=%r" % (k,v))

# 8) forbidden paths inside the tarball
import tarfile
with tarfile.open(tarball, "r:gz") as tf:
    for nm in tf.getnames():
        if any(x in nm for x in (".lake","/dist/","gate-out","/probe","Tests/Probe")) or nm.endswith(".olean") or "/.git/" in nm:
            fail("forbidden path in tarball: %s" % nm)

# 9) profile gating
profile = s.get("release_profile")
if require_release:
    if profile != "real-release": fail("--require-release: release_profile=%r (not real-release)" % profile)
    if s.get("must_not_publish") is not False: fail("--require-release: must_not_publish must be false")
    if s.get("attestation_status") != "release-attestation":
        fail("--require-release: attestation_status must be release-attestation")
    if s.get("required_gates_passed") is not True:
        fail("--require-release: required_gates_passed must be true")
    gc = s.get("git_commit")
    if not (isinstance(gc,str) and len(gc)==40 and all(c in HEX for c in gc)):
        fail("--require-release: git_commit not a real 40-hex commit (%r)" % gc)
    if s.get("git_dirty") not in (False,"false"): fail("--require-release: git_dirty not clean")
    # the sidecar's gates must be exactly the canonical full-release set, all pass, all required
    try:
        reg = json.load(open(os.path.join(root,"scripts","gate-registry.json"), encoding="utf-8"))
    except Exception as e:
        fail("--require-release: cannot read gate-registry.json: %s" % e)
    if s.get("gate_registry") != reg.get("gate_registry"):
        fail("--require-release: gate_registry %r != %r" % (s.get("gate_registry"), reg.get("gate_registry")))
    sgates = s.get("gates", [])
    if s.get("gate_count") not in (None, len(sgates)):
        fail("--require-release: gate_count %r != len(gates) %d" % (s.get("gate_count"), len(sgates)))
    expected = set(reg["profiles"]["full-release"]["required_gate_ids"])
    got = set(g.get("id") for g in sgates)
    if expected != got:
        fail("--require-release: gate set != registry full-release: missing=%s extra=%s"
             % (sorted(expected-got), sorted(got-expected)))
    for g in sgates:
        if g.get("status") != "pass": fail("--require-release: gate %s status=%r" % (g.get("id"), g.get("status")))
        if g.get("criticality") != "required": fail("--require-release: gate %s criticality=%r" % (g.get("id"), g.get("criticality")))
    print("OK: sidecar verified AND publishable (real-release; %d canonical gates, all pass)." % len(sgates))
else:
    note = "" if profile=="real-release" else "  [%s — not publishable]" % profile
    print("OK: sidecar internally consistent (all hashes match, HACL anchored, profile consistent, no stubs/forbidden paths).%s" % note)
PY
