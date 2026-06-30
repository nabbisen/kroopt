#!/bin/sh
# verify-hacl-upstream.sh — ONLINE, on-demand re-verification of the HACL*/EverCrypt anchor.
#
# This is NOT a CI gate (it needs network). It re-establishes the "manifest == upstream" link:
# it downloads the pinned upstream artifact, confirms its sha256 against the manifest, extracts
# it, and byte-compares every manifest-listed file against its recorded upstream_path. The
# per-build offline check (check-hacl-provenance.sh) verifies "tree == manifest"; this command
# re-verifies the other half of the chain on demand.
#
# Usage: bash scripts/verify-hacl-upstream.sh
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MANI="$ROOT/Kroopt/Native/hacl-provenance/HACL-PROVENANCE.json"
[ -f "$MANI" ] || { echo "FAIL: manifest missing: $MANI"; exit 1; }

URL=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["upstream_artifact_url"])' "$MANI")
WANT=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["upstream_artifact_sha256"])' "$MANI")
NAME=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["upstream_artifact_name"])' "$MANI")

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
echo "Fetching pinned upstream artifact: $NAME"
echo "  $URL"
curl -sSL -o "$TMP/$NAME" "$URL" || { echo "FAIL: download failed"; exit 1; }

GOT=$(sha256sum "$TMP/$NAME" | cut -d' ' -f1)
echo "artifact sha256: $GOT"
if [ "$GOT" != "$WANT" ]; then
  echo "FAIL: artifact sha256 mismatch (manifest $WANT, downloaded $GOT)"; exit 1
fi
echo "  matches manifest upstream_artifact_sha256."

mkdir -p "$TMP/x"; tar xzf "$TMP/$NAME" -C "$TMP/x"
# the artifact extracts to a single top dir (or directly); locate the artifact root
AROOT="$TMP/x"
if [ "$(find "$TMP/x" -maxdepth 1 -mindepth 1 -type d | wc -l)" = "1" ] && [ "$(find "$TMP/x" -maxdepth 1 -type f | wc -l)" = "0" ]; then
  AROOT=$(find "$TMP/x" -maxdepth 1 -mindepth 1 -type d)
fi
# the ocaml package extracts with raw/ and kremlin/ at its root already; detect
if [ ! -d "$AROOT/raw" ]; then
  cand=$(find "$TMP/x" -type d -name raw | head -1)
  [ -n "$cand" ] && AROOT=$(dirname "$cand")
fi

python3 - "$ROOT" "$MANI" "$AROOT" <<'PY'
import sys, os, json, hashlib
root, mani_path, aroot = sys.argv[1], sys.argv[2], sys.argv[3]
hacl = os.path.join(root, "Kroopt", "Native", "hacl")
m = json.load(open(mani_path, encoding="utf-8"))
def sha(p):
    h=hashlib.sha256()
    with open(p,"rb") as f:
        for c in iter(lambda:f.read(65536), b""): h.update(c)
    return h.hexdigest()
ok=0; bad=0; miss=0
for e in m["files"]:
    up = os.path.join(aroot, e["upstream_path"])
    vp = os.path.join(hacl, e["vendored_path"])
    if not os.path.isfile(up):
        print("MISSING upstream:", e["upstream_path"]); miss+=1; continue
    if sha(up) == sha(vp) == e["sha256"]:
        ok+=1
    else:
        print("MISMATCH:", e["vendored_path"]); bad+=1
print("re-verify: matched=%d mismatch=%d missing=%d" % (ok,bad,miss))
sys.exit(0 if (bad==0 and miss==0 and ok==m["vendored_upstream_file_count"]) else 1)
PY
rc=$?
[ "$rc" = "0" ] && echo "OK: upstream re-verification passed — manifest == upstream ocaml-v0.4.5 artifact." || echo "FAIL: upstream re-verification failed."
exit $rc
