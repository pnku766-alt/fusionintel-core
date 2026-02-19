from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from scripts.validate_placements import main


class TestValidatePlacements(unittest.TestCase):
    def test_allows_precommit_config_at_repo_root(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            old = os.getcwd()
            try:
                os.chdir(td)
                p = Path(".pre-commit-config.yaml")
                p.write_text("repos: []\n", encoding="utf-8")

                # Simulate how pre-commit calls hooks: relative path from repo root
                self.assertEqual(0, main([p.as_posix()]))
            finally:
                os.chdir(old)

    def test_blocks_yaml_outside_workflows(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "random.yml"
            p.write_text("name: nope\n", encoding="utf-8")
            self.assertEqual(1, main([str(p)]))

    def test_blocks_json_in_wrong_path(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "oops.json"
            p.write_text("{}", encoding="utf-8")
            self.assertEqual(1, main([str(p)]))


if __name__ == "__main__":
    unittest.main()
