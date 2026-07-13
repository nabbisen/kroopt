#!/usr/bin/env bash
# Canonical RFC 053 documentation, relative-link, lifecycle, and changelog consistency gate.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP_ROOT="${TMPDIR:-$ROOT/.git-exclude/tmp}"
mkdir -p "$TMP_ROOT"
BOOK_OUT="$(mktemp -d "$TMP_ROOT/mdbook.XXXXXX")"
trap 'rm -rf "$BOOK_OUT"' EXIT

python3 - "$ROOT" <<'PY'
from collections import Counter
from pathlib import Path
from urllib.parse import unquote
import re, sys

root = Path(sys.argv[1]).resolve()
excluded = {".git", ".git-exclude", ".lake", "book", "gate-out"}
markdown = []
for path in root.rglob("*.md"):
    rel = path.relative_to(root)
    if any(part in excluded for part in rel.parts):
        continue
    markdown.append(path)

link_re = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
errors = []
for source in markdown:
    text = source.read_text(encoding="utf-8")
    text = re.sub(r"```.*?```", "", text, flags=re.S)
    for raw in link_re.findall(text):
        target = raw.strip()
        if target.startswith("<") and target.endswith(">"):
            target = target[1:-1]
        if not target or target.startswith(("#", "http://", "https://", "mailto:")):
            continue
        # Repository links do not use Markdown's optional quoted title syntax.
        target = unquote(target.split("#", 1)[0].split("?", 1)[0])
        if not target:
            continue
        resolved = (source.parent / target).resolve()
        try:
            resolved.relative_to(root)
        except ValueError:
            errors.append(f"{source.relative_to(root)}: link escapes repository: {raw}")
            continue
        if not resolved.exists():
            errors.append(f"{source.relative_to(root)}: missing link target: {raw}")

rfc_files = []
status_rules = {
    "proposed": re.compile(r"^\*\*Status\.\*\* Proposed"),
    "done": re.compile(r"^\*\*Status\.\*\* Implemented"),
    "archive": re.compile(r"^\*\*Status\.\*\* (?:Withdrawn|Superseded)"),
}
index = (root / "rfcs" / "README.md").read_text(encoding="utf-8")
for folder, status_re in status_rules.items():
    for path in sorted((root / "rfcs" / folder).glob("[0-9][0-9][0-9]-*.md")):
        rfc_files.append(path)
        text = path.read_text(encoding="utf-8")
        status = re.search(r"^\*\*Status\.\*\*.*$", text, re.M)
        if status is None or not status_re.match(status.group(0)):
            errors.append(f"{path.relative_to(root)}: status does not match {folder}/ lifecycle folder")
        link = f"{folder}/{path.name}"
        row_re = re.compile(rf"^\|\s*{path.name[:3]}\s*\|[^\n]*\({re.escape(link)}\)", re.M)
        memberships = len(row_re.findall(index))
        if memberships != 1:
            errors.append(f"rfcs/README.md: expected exactly one lifecycle-table row for {link}, found {memberships}")

numbers = Counter(path.name[:3] for path in rfc_files)
for number, count in sorted(numbers.items()):
    if count != 1:
        errors.append(f"RFC {number}: number appears in {count} lifecycle files")

headings = re.findall(r"^## \[([^]]+)\]", (root / "CHANGELOG.md").read_text(encoding="utf-8"), re.M)
for heading, count in Counter(headings).items():
    if heading != "Unreleased" and count != 1:
        errors.append(f"CHANGELOG.md: duplicate release heading [{heading}] ({count} occurrences)")

if errors:
    print("Documentation consistency failures:", file=sys.stderr)
    for error in errors:
        print(f"- {error}", file=sys.stderr)
    raise SystemExit(1)
print(f"relative links resolved across {len(markdown)} Markdown files; {len(rfc_files)} RFC lifecycle files indexed")
PY

mdbook build "$ROOT/docs" --dest-dir "$BOOK_OUT" >/dev/null
echo "OK: documentation links, RFC lifecycle/index, changelog uniqueness, and mdBook build passed."
