# newline-audit

A dependency-free, read-only Python CLI that checks **raw bytes**, not text
encodings, for mixed newline styles, NUL bytes, and missing final newlines.
It reports LF, CRLF, and lone-CR counts without double-counting CRLF. There is
no fix mode, recursive traversal, network access, or content output.

## Requirements and platform evidence

- Python **3.11 or newer**; standard library only. No pip, packages, or admin
  permissions are needed. The examples assume Git is installed for clone/update.
- Read permission on the files you audit. Do not run as administrator/root just
  to bypass a permission error.

| Platform | Status | Evidence / limitations |
| --- | --- | --- |
| Linux x86-64 | Live-tested | Python 3.11.16; unit/CLI tests, source-copy setup/run/test/cleanup, FIFO and symlink rejection, local syntax checks |
| macOS | Designed, unverified | Use the POSIX commands below; no macOS execution performed |
| Windows | Designed, unverified | Use the PowerShell commands below; no Windows execution performed; POSIX-only tests are skipped |
| Other Python versions / CPU architectures | Unverified | No separate execution evidence |

## Clone and setup

Clone the repository:

```sh
git clone https://github.com/KamiBuilds/newline-audit.git
cd newline-audit
```

No wheel or global installation is required. An isolated environment without
pip is sufficient:

### Linux / macOS (POSIX shell)

```sh
python3 -m venv --without-pip .venv
. .venv/bin/activate
python --version
python newline-audit --help
python newline-audit examples/clean-lf.txt
```

The clean example prints:

```text
CLEAN examples/clean-lf.txt bytes=8 LF=2 CRLF=0 CR=0 findings=none
```

### Windows (PowerShell; unverified)

Use a Python 3.11+ interpreter selected by the Python launcher. No activation
or PowerShell execution-policy change is needed:

```powershell
py -3 -m venv --without-pip .venv
.\.venv\Scripts\python.exe --version
.\.venv\Scripts\python.exe newline-audit --help
.\.venv\Scripts\python.exe newline-audit examples/clean-lf.txt
```

All later `python` commands can be run with `.\.venv\Scripts\python.exe`.
On POSIX, `./newline-audit` is also an executable entry point, using the
`python3` selected by your PATH. Invoking `python newline-audit` is portable.

## Run

```sh
python newline-audit path/to/file.txt path/to/another.txt
python newline-audit --json examples/mixed.txt
python newline-audit -- --filename-starting-with-a-dash.txt
```

Pass literal file paths; shell glob expansion is your shell's responsibility.
The example `mixed.txt` intentionally exits **1** and reports one of each
newline style plus `missing_final_newline`. See [examples](examples/README.md).

| Exit | Meaning |
| --- | --- |
| `0` | All inputs clean; `--help` also exits 0 |
| `1` | At least one file has findings |
| `2` | Malformed arguments, unsafe/unreadable/missing input, or a resource limit |

A uniform LF, CRLF, **or lone-CR** file is clean if it contains no NUL and has a
final newline. A zero-byte file is clean. A nonempty file ending in either CR or
LF has a final newline. Files are assessed independently: separate LF and CRLF
files do not constitute a mixed file. NUL detection is not a complete binary-file
detector; arbitrary non-NUL bytes are accepted without decoding them.

JSON is one compact, deterministically key-sorted object terminated by LF:

```json
{"files":[{"bytes":8,"findings":[],"newline_counts":{"cr":0,"crlf":0,"lf":2},"path":"examples/clean-lf.txt"}],"status":"clean"}
```

`findings` contains zero or more of `mixed`, `nul`, `missing_final_newline`, in
that order. A findings report has `status: "findings"`. On exit 2, errors go to
stderr and stdout is empty (there is no partial report, including in JSON mode).
Errors intentionally do not echo OS exception details. JSON escapes non-ASCII
and control characters. Human reports escape nonprinting characters in paths;
file contents are never emitted.

For shell automation, accept exits 0/1 separately rather than treating any
nonzero status as a crashed program. Do not pipe JSON from an exit-2 invocation
into a parser and expect a JSON error object.

## Safety and bounds

- At most **128** explicit paths per invocation, **10 MiB** per file, and
  **16 KiB** of UTF-8 report output. The final report is checked before printing.
- Only regular files are read. Directories, FIFOs, devices, sockets, and final
  symbolic-link inputs are rejected. On POSIX, nonblocking/no-follow open flags
  are used when available; the opened file type and identity are checked too.
- Files growing past the size limit are rejected after a bounded read. Opened
  handles are closed on validation/stat/read failures.
- Input **contents are never modified**. Normal OS reads may update access time.
- This is not a security sandbox or an atomic snapshot: trusted parent
  directories are assumed (parent-directory symlinks are not forbidden),
  hard links are accepted, and concurrent writes can change bytes during a read.
  Use stable, local regular files; exotic/network filesystems can still stall
  reads. Windows reparse-point behavior has not been live-tested.

## Test and local checks

From the repository root with your chosen Python interpreter:

```sh
python -m unittest discover -s tests -v
python -m compileall -q newline_audit.py tests scripts
python -m py_compile newline-audit
git diff --check
python scripts/check.py
```

The check script runs the preceding checks, stops on the first failure, and can
be launched from any working directory. For a source archive without `.git`,
it explicitly skips only the Git diff check. `git diff --check` does not check
untracked files; review `git status --short` before committing.

Tests use temporary synthetic files and never touch your production files.
POSIX FIFO tests require `mkfifo`; symlink and direct-executable tests, and
filenames containing ASCII controls, are skipped on Windows. No claim of
Windows/macOS test success or hosted CI success is made. Verification is local;
no GitHub Actions workflow is included. Git checkout preservation of the mixed
fixture and executable launcher was also verified with `core.autocrlf=true`.

## Update

In a clean clone (save any local work before updating):

```sh
git status --short
git pull --ff-only
python scripts/check.py
```

There are no dependency updates or global installs. Rerun the clean example
after pulling. Clone/pull require Git and access to GitHub.

## Cleanup / uninstall

There is nothing globally installed to uninstall. From the project root on
Linux/macOS, deactivate if you activated the environment, then remove only the
local environment and generated caches:

```sh
deactivate
rm -rf -- .venv __pycache__ tests/__pycache__ scripts/__pycache__
```

If you did not activate an environment, omit `deactivate`. In PowerShell:

```powershell
Remove-Item -Recurse -Force .venv, __pycache__, tests/__pycache__, scripts/__pycache__ -ErrorAction SilentlyContinue
```

To remove the project entirely, delete only its clone/source directory after
saving your own files. Audited files elsewhere are unaffected.

## License

[MIT](LICENSE), copyright 2026 KamiBuilds.
