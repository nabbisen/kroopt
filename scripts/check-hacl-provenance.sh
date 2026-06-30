#!/bin/sh
# check-hacl-provenance.sh — OFFLINE HACL*/EverCrypt vendored-byte provenance gate.
#
# Verifies that Kroopt/Native/hacl/ matches the recorded provenance manifest
# (Kroopt/Native/hacl-provenance/HACL-PROVENANCE.json) byte-for-byte, deterministically
# and WITHOUT network access. This re-checks, every build, the "tree == manifest" link of
# the anchor chain (tree == manifest  <-  manifest == upstream ocaml-v0.4.5 artifact, the
# latter established once at vendoring and re-checkable online via verify-hacl-upstream.sh).
#
# Prints "OK: ..." and exits 0 on success; "FAIL: ..." and exits 1 otherwise.
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
exec python3 - "$ROOT" <<'PY'
import sys, os, json, hashlib

root = sys.argv[1]
hacl = os.path.join(root, "Kroopt", "Native", "hacl")
mani = os.path.join(root, "Kroopt", "Native", "hacl-provenance", "HACL-PROVENANCE.json")

def fail(msg):
    print("FAIL: " + msg); sys.exit(1)

if not os.path.isfile(mani):
    fail("HACL-PROVENANCE.json missing at Kroopt/Native/hacl-provenance/")

raw = open(mani, encoding="utf-8").read()
# stub/placeholder sentinels must never appear in a real manifest
for bad in ("STUB", "PLACEHOLDER", "NOT-COMPUTED", "NOT_COMPUTED", "TODO", "FIXME"):
    if bad in raw.upper():
        fail("placeholder/stub sentinel present in manifest: %s" % bad)

try:
    m = json.loads(raw)
except Exception as e:
    fail("manifest not valid JSON: %s" % e)

if m.get("source_tree_hash_method") != "sorted-file-sha256-v1":
    fail("unknown source_tree_hash_method: %r" % m.get("source_tree_hash_method"))

lm = m.get("local_modifications")
if lm is None:
    fail("manifest missing local_modifications")
if len(lm) != 0:
    fail("local_modifications non-empty (%d) — the clean inherited-verified claim requires zero" % len(lm))

files = m.get("files") or []
if not files:
    fail("manifest 'files' array empty")
excluded_set = set(m.get("excluded_metadata_files", []))

HEX = set("0123456789abcdef")
def is_hex64(s): return isinstance(s, str) and len(s) == 64 and all(c in HEX for c in s)
def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(65536), b""): h.update(c)
    return h.hexdigest()

# 1) every manifest-listed file: well-formed, present, hash matches
listed = {}
lines = []
for e in files:
    vp = e.get("vendored_path"); sh = e.get("sha256")
    if not vp or not is_hex64(sh):
        fail("malformed manifest file entry: %r" % e)
    if vp in listed:
        fail("duplicate vendored_path in manifest: %s" % vp)
    listed[vp] = sh
    ap = os.path.join(hacl, vp)
    if not os.path.isfile(ap):
        fail("manifest-listed file missing on disk: %s" % vp)
    actual = sha256_file(ap)
    if actual != sh:
        fail("hash differs for %s (manifest %s, disk %s)" % (vp, sh, actual))
    lines.append("%s  %s" % (actual, vp))

# 2) recompute source_tree_sha256 (sorted-file-sha256-v1: byte-value line sort, LF-joined)
blob = "".join(s + "\n" for s in sorted(lines)).encode("utf-8")
recomputed = hashlib.sha256(blob).hexdigest()
if recomputed != m.get("source_tree_sha256"):
    fail("source_tree_sha256 recomputation differs (manifest %s, recomputed %s)"
         % (m.get("source_tree_sha256"), recomputed))

# 3) declared count matches
if m.get("vendored_upstream_file_count") != len(listed):
    fail("vendored_upstream_file_count (%r) != listed (%d)" % (m.get("vendored_upstream_file_count"), len(listed)))

# 4) on-disk reconciliation: every file under the tree is either listed (upstream) or excluded
on_disk = set()
for dp, _, fns in os.walk(hacl):
    for fn in fns:
        on_disk.add(os.path.relpath(os.path.join(dp, fn), hacl))
for rel in on_disk:
    if rel not in listed and rel not in excluded_set:
        fail("unlisted file under Kroopt/Native/hacl absent from manifest and not excluded: %s" % rel)

# 5) excluded metadata exactly as documented: present, never also listed, no drift
for ex in excluded_set:
    if ex in listed:
        fail("file both excluded and listed: %s" % ex)
    if not os.path.isfile(os.path.join(hacl, ex)):
        fail("excluded metadata file documented but missing: %s" % ex)
disk_nonupstream = set(r for r in on_disk if r not in listed)
if disk_nonupstream != excluded_set:
    fail("excluded-metadata drift: on-disk non-upstream %s != documented %s"
         % (sorted(disk_nonupstream), sorted(excluded_set)))

print("OK: HACL* provenance anchored — %d upstream files byte-match manifest "
      "(artifact %s sha256 %s..., tree_sha %s..., local_modifications=0, excluded=%s)"
      % (len(listed), m.get("upstream_release_tag"),
         (m.get("upstream_artifact_sha256") or "")[:12], recomputed[:12], sorted(excluded_set)))
PY
