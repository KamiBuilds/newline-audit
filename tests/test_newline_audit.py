import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import newline_audit


class AuditBytesTests(unittest.TestCase):
    def test_empty_file_has_no_findings(self):
        result = newline_audit.audit_bytes(b"")
        self.assertEqual(result["bytes"], 0)
        self.assertEqual((result["lf"], result["crlf"], result["cr"]), (0, 0, 0))
        self.assertFalse(result["mixed"])
        self.assertFalse(result["nul"])
        self.assertFalse(result["missing_final_newline"])

    def test_clean_lf_file_is_counted_without_findings(self):
        result = newline_audit.audit_bytes(b"one\ntwo\n")

        self.assertEqual(
            result,
            {
                "bytes": 8,
                "lf": 2,
                "crlf": 0,
                "cr": 0,
                "mixed": False,
                "nul": False,
                "missing_final_newline": False,
            },
        )

    def test_crlf_is_not_double_counted_as_lf(self):
        result = newline_audit.audit_bytes(b"one\r\ntwo\r\n")

        self.assertEqual(result["lf"], 0)
        self.assertEqual(result["crlf"], 2)
        self.assertEqual(result["cr"], 0)
        self.assertFalse(result["mixed"])
        self.assertFalse(result["missing_final_newline"])

    def test_lone_cr_is_counted_as_a_newline(self):
        result = newline_audit.audit_bytes(b"one\rtwo\r")

        self.assertEqual(result["lf"], 0)
        self.assertEqual(result["crlf"], 0)
        self.assertEqual(result["cr"], 2)
        self.assertFalse(result["missing_final_newline"])

    def test_multiple_newline_styles_are_mixed(self):
        result = newline_audit.audit_bytes(b"lf\ncrlf\r\ncr\r")

        self.assertEqual((result["lf"], result["crlf"], result["cr"]), (1, 1, 1))
        self.assertTrue(result["mixed"])

    def test_nul_byte_is_a_finding(self):
        result = newline_audit.audit_bytes(b"safe\x00looking\n")

        self.assertTrue(result["nul"])

    def test_nonempty_file_without_final_newline_is_a_finding(self):
        result = newline_audit.audit_bytes(b"unfinished")

        self.assertTrue(result["missing_final_newline"])


class AuditPathTests(unittest.TestCase):
    def test_regular_file_is_read_without_modification(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "clean.txt")
            original = b"one\ntwo\n"
            path.write_bytes(original)

            result = newline_audit.audit_path(path)

            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(result["path"], str(path))
            self.assertEqual(result["findings"], [])
            self.assertEqual(result["newline_counts"], {"lf": 2, "crlf": 0, "cr": 0})

    @unittest.skipIf(os.name == "nt", "requires POSIX symlink creation")
    def test_symbolic_link_is_rejected_without_following_it(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory, "target.txt")
            target.write_bytes(b"secret\n")
            link = Path(directory, "link.txt")
            link.symlink_to(target)

            with self.assertRaisesRegex(Exception, "unsafe"):
                newline_audit.audit_path(link)

    @unittest.skipIf(os.name == "nt", "requires POSIX symlink creation")
    def test_symlink_swap_without_nofollow_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "input.txt")
            path.write_bytes(b"ok\n")
            target = Path(directory, "target.txt")
            target.write_bytes(b"do-not-read\n")
            original_open = os.open

            def swap_then_open(name, flags):
                path.unlink()
                path.symlink_to(target)
                return original_open(name, flags)

            # Force the race deterministically, using real filesystem operations.
            with mock.patch.object(os, "O_NOFOLLOW", 0, create=True):
                with mock.patch.object(os, "open", side_effect=swap_then_open):
                    with self.assertRaisesRegex(newline_audit.AuditInputError, "changed"):
                        newline_audit.audit_path(path)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO files require POSIX")
    def test_special_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            fifo = Path(directory, "input.fifo")
            os.mkfifo(fifo)

            with self.assertRaisesRegex(Exception, "regular file"):
                newline_audit.audit_path(fifo)

    def test_failed_descriptor_stat_does_not_leak_descriptor(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "input.txt")
            path.write_bytes(b"ok\n")
            original_open = os.open
            descriptors = []

            def record_open(name, flags):
                descriptor = original_open(name, flags)
                descriptors.append(descriptor)
                return descriptor

            with mock.patch.object(os, "open", side_effect=record_open):
                with mock.patch.object(os, "fstat", side_effect=OSError("stat failed")):
                    with self.assertRaises(OSError):
                        newline_audit.audit_path(path)
            try:
                with self.assertRaises(OSError):
                    os.fstat(descriptors[0])
            finally:
                try:
                    os.close(descriptors[0])
                except OSError:
                    pass

    def test_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(newline_audit.AuditInputError, "regular file"):
                newline_audit.audit_path(directory)

    def test_file_at_exact_size_limit_is_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "at-limit.txt")
            path.write_bytes(b"a" * (newline_audit.MAX_FILE_BYTES - 1) + b"\n")
            result = newline_audit.audit_path(path)
            self.assertEqual(result["bytes"], newline_audit.MAX_FILE_BYTES)
            self.assertEqual(result["findings"], [])

    def test_file_growing_after_stat_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "growing.txt")
            path.write_bytes(b"ok\n")
            original_fstat = os.fstat

            def grow_after_stat(descriptor):
                before_growth = original_fstat(descriptor)
                path.write_bytes(b"x" * 9)
                return before_growth

            with mock.patch.object(newline_audit, "MAX_FILE_BYTES", 8):
                with mock.patch.object(os, "fstat", side_effect=grow_after_stat):
                    with self.assertRaisesRegex(newline_audit.AuditInputError, "10 MiB"):
                        newline_audit.audit_path(path)

    def test_file_larger_than_ten_mib_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "too-large.bin")
            with path.open("wb") as handle:
                handle.truncate(10 * 1024 * 1024 + 1)

            with self.assertRaisesRegex(Exception, "10 MiB"):
                newline_audit.audit_path(path)


class CliTests(unittest.TestCase):
    def test_clean_file_has_human_report_and_exit_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "clean.txt")
            path.write_bytes(b"one\ntwo\n")
            stdout = io.StringIO()
            stderr = io.StringIO()

            code = newline_audit.main([str(path)], stdout=stdout, stderr=stderr)

            self.assertEqual(code, 0)
            self.assertEqual(stderr.getvalue(), "")
            self.assertEqual(
                stdout.getvalue(),
                f"CLEAN {path} bytes=8 LF=2 CRLF=0 CR=0 findings=none\n",
            )

    def test_finding_has_human_report_and_exit_one_without_contents(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "mixed.txt")
            path.write_bytes(b"DO_NOT_ECHO\r\nsecret\n")
            stdout = io.StringIO()

            code = newline_audit.main([str(path)], stdout=stdout, stderr=io.StringIO())

            self.assertEqual(code, 1)
            self.assertIn("LF=1 CRLF=1 CR=0 findings=mixed", stdout.getvalue())
            self.assertNotIn("DO_NOT_ECHO", stdout.getvalue())
            self.assertNotIn("secret", stdout.getvalue())

    def test_unreadable_input_returns_two(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "missing.txt")
            stdout = io.StringIO()
            stderr = io.StringIO()

            code = newline_audit.main([str(path)], stdout=stdout, stderr=stderr)

            self.assertEqual(code, 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("ERROR", stderr.getvalue())
            self.assertIn(str(path), stderr.getvalue())

    def test_json_report_is_compact_and_deterministic(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "mixed.txt")
            path.write_bytes(b"a\r\nb\n")
            stdout = io.StringIO()

            code = newline_audit.main(
                ["--json", str(path)], stdout=stdout, stderr=io.StringIO()
            )

            expected = {
                "files": [
                    {
                        "bytes": 5,
                        "findings": ["mixed"],
                        "newline_counts": {"cr": 0, "crlf": 1, "lf": 1},
                        "path": str(path),
                    }
                ],
                "status": "findings",
            }
            self.assertEqual(code, 1)
            self.assertEqual(
                stdout.getvalue(),
                json.dumps(expected, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
                + "\n",
            )

    @unittest.skipIf(os.name == "nt", "Windows filenames cannot contain these controls")
    def test_human_report_escapes_terminal_controls_in_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "bad\n\x1b\u202e.txt")
            path.write_bytes(b"ok\n")
            stdout = io.StringIO()

            code = newline_audit.main([str(path)], stdout=stdout, stderr=io.StringIO())

            report = stdout.getvalue()
            self.assertEqual(code, 0)
            self.assertNotIn("\x1b", report)
            self.assertNotIn("\u202e", report)
            self.assertNotIn("\n", report[:-1])
            self.assertIn("\\x0a\\x1b\\u202e", report)

    def test_malformed_cli_fails_closed_with_fixed_program_name(self):
        stdout = io.StringIO()
        stderr = io.StringIO()

        code = newline_audit.main([], stdout=stdout, stderr=stderr)

        self.assertEqual(code, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(
            stderr.getvalue(),
            "ERROR malformed command line; run 'newline-audit --help'\n",
        )

    def test_json_failure_does_not_emit_partial_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            clean = Path(directory, "clean.txt")
            clean.write_bytes(b"ok\n")
            stdout = io.StringIO()
            stderr = io.StringIO()
            code = newline_audit.main(
                ["--json", str(clean), str(Path(directory, "missing.txt"))],
                stdout=stdout,
                stderr=stderr,
            )
            self.assertEqual(code, 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("ERROR cannot audit", stderr.getvalue())

    def test_json_includes_nul_and_missing_final_newline_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "nul.txt")
            path.write_bytes(b"private\x00")
            stdout = io.StringIO()
            code = newline_audit.main(
                ["--json", str(path)], stdout=stdout, stderr=io.StringIO()
            )
            self.assertEqual(code, 1)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["status"], "findings")
            self.assertEqual(
                payload["files"][0]["findings"], ["nul", "missing_final_newline"]
            )
            self.assertNotIn("private", stdout.getvalue())

    def test_invalid_option_does_not_echo_terminal_controls(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        code = newline_audit.main(
            ["--bad\x1b\n"], stdout=stdout, stderr=stderr
        )
        self.assertEqual(code, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertNotIn("\x1b", stderr.getvalue())
        self.assertEqual(stderr.getvalue().count("\n"), 1)

    def test_file_count_is_capped(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "clean.txt")
            path.write_bytes(b"ok\n")
            stdout = io.StringIO()
            stderr = io.StringIO()

            code = newline_audit.main(
                [str(path)] * 129, stdout=stdout, stderr=stderr
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(stderr.getvalue(), "ERROR at most 128 files are allowed\n")

    def test_report_size_is_capped_before_output(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = []
            for index in range(80):
                path = Path(directory, f"{index:03d}-" + "x" * 196 + ".txt")
                path.write_bytes(b"ok\n")
                paths.append(str(path))
            stdout = io.StringIO()
            stderr = io.StringIO()

            code = newline_audit.main(paths, stdout=stdout, stderr=stderr)

            self.assertEqual(code, 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(stderr.getvalue(), "ERROR report exceeds 16 KiB limit\n")

    @unittest.skipIf(os.name == "nt", "direct shebang execution requires POSIX")
    def test_executable_entrypoint_runs_cli(self):
        repository = Path(__file__).resolve().parents[1]
        executable = repository / "newline-audit"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "clean.txt")
            path.write_bytes(b"ok\n")

            completed = subprocess.run(
                [str(executable), str(path)],
                cwd=repository,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0)
            self.assertTrue(os.access(executable, os.X_OK))
            self.assertIn("CLEAN", completed.stdout)
            self.assertEqual(completed.stderr, "")


if __name__ == "__main__":
    unittest.main()
