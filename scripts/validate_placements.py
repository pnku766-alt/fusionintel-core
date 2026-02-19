#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path


WORKFLOW_RULE = (
    "Workflow files must be placed in .github/workflows/*.yml",
    re.compile(r"^\.github/workflows/[^/]+\.yml$"),
)
SCHEMA_RULE = (
    "JSON policy/schema files must be placed in schemas/*.json or policies/*.json",
    re.compile(r"^(schemas|policies)/[^/]+\.json$"),
)
DOC_RULE = ("Docs files must be placed in docs/*.md or README.md", re.compile(r"^(docs/[^/]+\.md|README\.md)$"))
SCRIPT_RULE = ("Scripts must be placed in scripts/*", re.compile(r"^scripts/.+"))

LEGACY_PYTHON_PREFIXES = (
    "contracts/",
    "sovereignty_compliance/",
    "delivery_action/",
    "audit_log/",
    "orchestrator/",
    "api/",
)

ALLOWED_PYTHON = re.compile(r"^(fusionintel_core/.+\.py|scripts/[^/]+\.py|tests/.+\.py)$")
FILETYPE_GUARDS = {
    ".yml": WORKFLOW_RULE,
    ".yaml": WORKFLOW_RULE,
    ".json": SCHEMA_RULE,
    ".md": DOC_RULE,
    ".ps1": SCRIPT_RULE,
    ".sh": SCRIPT_RULE,
}

# Block “paste YAML into PowerShell” style content showing up inside docs/scripts
PASTE_PATTERNS = [
    re.compile(r"^\s*on:\s*$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*jobs:\s*$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"```(?:yaml|yml|toml|json|markdown)\b", re.IGNORECASE),
    re.compile(r"Here'?s what to paste", re.IGNORECASE),
]


def _check_path(path: Path) -> list[str]:
    errors: list[str] = []
    posix = path.as_posix()
    suffix = path.suffix.lower()

    if suffix in FILETYPE_GUARDS:
        msg, pattern = FILETYPE_GUARDS[suffix]
        if not pattern.match(posix):
            errors.append(f"{posix}: {msg}")

    if suffix == ".py" and not ALLOWED_PYTHON.match(posix):
        if not posix.startswith(LEGACY_PYTHON_PREFIXES):
            errors.append(f"{posix}: Python must be under fusionintel_core/** or scripts/*.py (or legacy layer packages)")

    return errors


def _check_content(path: Path) -> list[str]:
    errors: list[str] = []
    suffix = path.suffix.lower()
    # only scan “human-edited / paste-prone” files
    if suffix not in {".ps1", ".md"}:
        return errors

    try:
        content = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        # don't block on encoding weirdness; keep fail-closed elsewhere
        return errors

    for pat in PASTE_PATTERNS:
        if pat.search(content):
            errors.append(f"{path.as_posix()}: contains blocked paste pattern '{pat.pattern}'")
    return errors


def main(argv: list[str]) -> int:
    errors: list[str] = []
    for arg in argv:
        p = Path(arg)
        if not p.exists() or p.is_dir():
            continue
        errors.extend(_check_path(p))
        errors.extend(_check_content(p))

    if errors:
        print("validate_placements failed:")
        for err in errors:
            print(f" - {err}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
