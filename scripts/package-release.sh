#!/bin/sh
# package-release.sh — produce a REPRODUCIBLE, files-at-root source tarball (RFC 030 Stage B).
#
# Determinism: same working tree -> byte-identical tarball -> identical sha256. Achieved with a
# name-sorted tar, normalized mtime/owner/group, and gzip -n (no embedded timestamp/name).
# The release sidecar is a SIBLING artifact produced by gen-sidecar.sh; it is NEVER placed inside
# this tarball (dist/ is excluded).
#
# Usage: bash scripts/package-release.sh [VERSION]   (VERSION defaults to latest CHANGELOG heading)
#        OUT_DIR=<dir> to override output dir (default: dist/)
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
  VERSION=$(grep -m1 -oE '^## \[[0-9]+\.[0-9]+\.[0-9]+\]' CHANGELOG.md | tr -d '#[] ')
fi
[ -n "$VERSION" ] || { echo "FAIL: could not determine version"; exit 1; }

OUT="${OUT_DIR:-$ROOT/dist}"
mkdir -p "$OUT"
TARBALL="$OUT/kroopt-$VERSION.tar.gz"

# Reproducible tar: name-sorted, normalized metadata, deterministic gzip.
# Exclusions: build (.lake/*.olean), vcs (.git), gate output, release output (dist), scratch.
LC_ALL=C tar \
  --format=gnu --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner \
  --exclude='./.lake' --exclude='./.git' --exclude='*.olean' \
  --exclude='./gate-out' --exclude='./dist' --exclude='./probe*' --exclude='./Tests/Probe' \
  -cf - -C "$ROOT" . | gzip -n > "$TARBALL"

SHA=$(sha256sum "$TARBALL" | cut -d' ' -f1)
SZ=$(wc -c < "$TARBALL")
FIRST=$(tar tzf "$TARBALL" | head -1)
FORBIDDEN=$(tar tzf "$TARBALL" | grep -cE '\.lake|\.olean|\.git/|/dist/|gate-out|/probe|Tests/Probe' || true)

echo "tarball:        $TARBALL"
echo "sha256:         $SHA"
echo "size_bytes:     $SZ"
echo "first_entry:    $FIRST"
echo "forbidden_paths:$FORBIDDEN"
[ "$FORBIDDEN" -eq 0 ] || { echo "FAIL: forbidden paths in tarball"; exit 1; }
echo "OK: reproducible source tarball written."
