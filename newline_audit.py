"""Audit newline bytes without decoding file contents."""

import argparse
import json
import os
from pathlib import Path
import stat
import sys
from typing import NoReturn, TextIO, TypedDict


def escape_terminal(text: str) -> str:
    """Escape non-printing Unicode characters for terminal-safe output."""
    escaped = []
    for character in text:
        value = ord(character)
        if character.isprintable():
            escaped.append(character)
        elif value <= 0xFF:
            escaped.append(f"\\x{value:02x}")
        elif value <= 0xFFFF:
            escaped.append(f"\\u{value:04x}")
        else:
            escaped.append(f"\\U{value:08x}")
    return "".join(escaped)


class AuditInputError(Exception):
    """Raised when an input cannot be audited safely."""


class CliUsageError(Exception):
    """Raised for malformed command-line arguments."""


class SafeArgumentParser(argparse.ArgumentParser):
    """Argument parser that does not echo attacker-controlled arguments."""

    def error(self, message: str) -> NoReturn:
        raise CliUsageError(message)


class ByteAudit(TypedDict):
    bytes: int
    lf: int
    crlf: int
    cr: int
    mixed: bool
    nul: bool
    missing_final_newline: bool


class NewlineCounts(TypedDict):
    lf: int
    crlf: int
    cr: int


class FileReport(TypedDict):
    path: str
    bytes: int
    newline_counts: NewlineCounts
    findings: list[str]


MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_FILES = 128
MAX_REPORT_BYTES = 16 * 1024


def audit_bytes(data: bytes) -> dict[str, int | bool]:
    """Return newline and safety findings for an in-memory byte string."""
    crlf = data.count(b"\r\n")
    lf = data.count(b"\n") - crlf
    cr = data.count(b"\r") - crlf
    return {
        "bytes": len(data),
        "lf": lf,
        "crlf": crlf,
        "cr": cr,
        "mixed": sum(bool(count) for count in (lf, crlf, cr)) > 1,
        "nul": b"\x00" in data,
        "missing_final_newline": bool(data) and not data.endswith((b"\n", b"\r")),
    }


def audit_path(path: str | Path) -> dict[str, object]:
    """Read and audit one file path."""
    path_text = str(path)
    initial_stat = os.lstat(path)
    mode = initial_stat.st_mode
    if stat.S_ISLNK(mode):
        raise AuditInputError(f"unsafe input: {path_text}")
    if not stat.S_ISREG(mode):
        raise AuditInputError(f"input is not a regular file: {path_text}")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as handle:
        opened_stat = os.fstat(handle.fileno())
        if not stat.S_ISREG(opened_stat.st_mode):
            raise AuditInputError(f"input is not a regular file: {path_text}")
        if not os.path.samestat(initial_stat, opened_stat):
            raise AuditInputError(f"input changed while opening: {path_text}")
        if opened_stat.st_size > MAX_FILE_BYTES:
            raise AuditInputError(f"input exceeds 10 MiB: {path_text}")
        data = handle.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise AuditInputError(f"input exceeds 10 MiB: {path_text}")
    metrics = audit_bytes(data)
    findings = [
        name
        for name in ("mixed", "nul", "missing_final_newline")
        if metrics[name]
    ]
    return {
        "path": path_text,
        "bytes": metrics["bytes"],
        "newline_counts": {
            "lf": metrics["lf"],
            "crlf": metrics["crlf"],
            "cr": metrics["cr"],
        },
        "findings": findings,
    }


def main(
    argv: list[str] | None = None,
    *,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    """Run the command-line interface and return its process status."""
    parser = SafeArgumentParser(
        prog="newline-audit",
        allow_abbrev=False,
        description="Audit raw file bytes for newline and safety findings.",
    )
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument("paths", nargs="+")
    try:
        arguments = parser.parse_args(argv)
    except CliUsageError:
        stderr.write("ERROR malformed command line; run 'newline-audit --help'\n")
        return 2
    if len(arguments.paths) > MAX_FILES:
        stderr.write("ERROR at most 128 files are allowed\n")
        return 2

    reports = []
    for path in arguments.paths:
        try:
            reports.append(audit_path(path))
        except (AuditInputError, OSError):
            stderr.write(f"ERROR cannot audit {escape_terminal(path)}\n")
            return 2
    has_findings = any(report["findings"] for report in reports)
    if arguments.as_json:
        payload = {"files": reports, "status": "findings" if has_findings else "clean"}
        output = (
            json.dumps(
                payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
            )
            + "\n"
        )
    else:
        lines = []
        for report in reports:
            counts = report["newline_counts"]
            findings = report["findings"]
            status = "FINDINGS" if findings else "CLEAN"
            finding_text = ",".join(findings) if findings else "none"
            lines.append(
                f"{status} {escape_terminal(report['path'])} bytes={report['bytes']} "
                f"LF={counts['lf']} CRLF={counts['crlf']} CR={counts['cr']} "
                f"findings={finding_text}\n"
            )
        output = "".join(lines)

    if len(output.encode("utf-8")) > MAX_REPORT_BYTES:
        stderr.write("ERROR report exceeds 16 KiB limit\n")
        return 2
    stdout.write(output)
    return 1 if has_findings else 0
