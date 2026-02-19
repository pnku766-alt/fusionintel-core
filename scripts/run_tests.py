#!/usr/bin/env python3
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


def run(command: list[str], *, cwd: Path) -> int:
    completed = subprocess.run(command, cwd=str(cwd), check=False)
    if command[:3] == [sys.executable, "-m", "pytest"] and completed.returncode == 5:
        return 0
    return completed.returncode


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]

    existing = os.environ.get("PYTHONPATH", "")
    os.environ["PYTHONPATH"] = str(repo_root) + (os.pathsep + existing if existing else "")

    if shutil.which("pytest"):
        print("Running tests with pytest...")
        return run([sys.executable, "-m", "pytest", str(repo_root)], cwd=repo_root)

    print("pytest not found; falling back to unittest discovery...")
    return run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py", "-t", ".", "-v"],
        cwd=repo_root,
    )


if __name__ == "__main__":
    raise SystemExit(main())
