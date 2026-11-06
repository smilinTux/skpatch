#!/usr/bin/env python3
"""Docs gate: no em/en dashes anywhere, and every fenced code block closes.

Stdlib only, no network, hermetic - this runs on every push and PR via
.github/workflows/validate-docs.yml. Checks every tracked `*.md` file (the
caller passes the file list; default is everything under the repo root
save the usual noise directories).

Two checks:

1. **No em dash (U+2014) or en dash (U+2013) anywhere.** Per this repo's
   writing-style rule: use a comma, a period, a colon, or a plain hyphen
   instead. A mermaid diagram's arrow labels are not exempt.
2. **Every fenced code block is closed**, with special attention to
   ```` ```mermaid ```` blocks (SOP.md's Architecture section requires at
   least one that actually renders; an unclosed fence breaks every renderer
   silently).

Exits 1 and prints every violation (not just the first) on failure.
"""

from __future__ import annotations

import pathlib
import sys

EM_DASH = chr(0x2014)  # the character this gate forbids everywhere else in the repo
EN_DASH = chr(0x2013)  # same; defined via chr() so this file itself stays free of the literal

_DEFAULT_EXCLUDE_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    "build",
    "dist",
}


def _iter_markdown_files(root: pathlib.Path) -> list[pathlib.Path]:
    out = []
    for path in root.rglob("*.md"):
        if any(part in _DEFAULT_EXCLUDE_DIRS for part in path.parts):
            continue
        out.append(path)
    return out


def check_no_em_en_dashes(path: pathlib.Path) -> list[str]:
    errors = []
    text = path.read_text(encoding="utf-8", errors="replace")
    for lineno, line in enumerate(text.splitlines(), start=1):
        if EM_DASH in line:
            errors.append(f"{path}:{lineno}: contains an em dash (U+2014)")
        if EN_DASH in line:
            errors.append(f"{path}:{lineno}: contains an en dash (U+2013)")
    return errors


def check_fences_balanced(path: pathlib.Path) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    fence_count = 0
    mermaid_open = False
    errors = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("```"):
            fence_count += 1
            if stripped.startswith("```mermaid"):
                mermaid_open = True
            elif fence_count % 2 == 0:
                mermaid_open = False
    if fence_count % 2 != 0:
        errors.append(f"{path}: unclosed fenced code block (odd number of ``` lines)")
    if mermaid_open:
        errors.append(f"{path}: a ```mermaid block appears unclosed")
    return errors


def main(argv: list[str]) -> int:
    root = pathlib.Path(argv[1]) if len(argv) > 1 else pathlib.Path(".")
    files = _iter_markdown_files(root)
    all_errors: list[str] = []
    for path in files:
        all_errors += check_no_em_en_dashes(path)
        all_errors += check_fences_balanced(path)

    if all_errors:
        for err in all_errors:
            print(err, file=sys.stderr)
        print(f"\nFAIL: {len(all_errors)} issue(s) across {len(files)} markdown file(s)", file=sys.stderr)
        return 1

    print(f"PASS: {len(files)} markdown file(s) checked, no em/en dashes, all fences balanced")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
