"""Exercise the local check command in a source-only copy."""

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


REPOSITORY = Path(__file__).resolve().parents[1]


class PackagingTests(unittest.TestCase):
    def test_bundled_examples_have_documented_cli_status(self):
        expected = {
            "clean-lf.txt": (0, {"cr": 0, "crlf": 0, "lf": 2}, []),
            "mixed.txt": (
                1,
                {"cr": 1, "crlf": 1, "lf": 1},
                ["mixed", "missing_final_newline"],
            ),
        }
        for name, (status, counts, findings) in expected.items():
            with self.subTest(example=name):
                path = REPOSITORY / "examples" / name
                self.assertTrue(path.is_file(), f"example is missing: {name}")
                original = path.read_bytes()
                completed = subprocess.run(
                    [sys.executable, "newline-audit", "--json", str(path)],
                    cwd=REPOSITORY,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(completed.returncode, status, completed.stderr)
                report = json.loads(completed.stdout)["files"][0]
                self.assertEqual(report["newline_counts"], counts)
                self.assertEqual(report["findings"], findings)
                self.assertEqual(path.read_bytes(), original)

    def test_check_script_runs_in_source_only_copy(self):
        check_script = REPOSITORY / "scripts" / "check.py"
        self.assertTrue(check_script.is_file(), "local check script is missing")
        with tempfile.TemporaryDirectory() as directory:
            snapshot = Path(directory)
            (snapshot / "tests").mkdir()
            (snapshot / "scripts").mkdir()
            for name in ("newline-audit", "newline_audit.py"):
                shutil.copy2(REPOSITORY / name, snapshot / name)
            shutil.copy2(
                REPOSITORY / "tests" / "test_newline_audit.py",
                snapshot / "tests" / "test_newline_audit.py",
            )
            shutil.copy2(check_script, snapshot / "scripts" / "check.py")
            completed = subprocess.run(
                [sys.executable, str(snapshot / "scripts" / "check.py")],
                cwd=snapshot / "scripts",
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn("Ran ", completed.stderr)
            self.assertIn("OK", completed.stderr)
            self.assertIn("SKIP git diff --check", completed.stdout)


if __name__ == "__main__":
    unittest.main()
