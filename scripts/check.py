"""Run dependency-free local checks from any working directory."""

from pathlib import Path
import subprocess
import sys


if __name__ == "__main__":
    repository = Path(__file__).resolve().parents[1]
    commands = [
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
        [sys.executable, "-m", "compileall", "-q", "newline_audit.py", "tests", "scripts"],
        [sys.executable, "-m", "py_compile", "newline-audit"],
    ]
    if (repository / ".git").exists():
        commands.append(["git", "diff", "--check"])
    else:
        print("SKIP git diff --check: source copy has no .git metadata", flush=True)
    for command in commands:
        print("RUN " + " ".join(command), flush=True)
        completed = subprocess.run(command, cwd=repository, check=False)
        if completed.returncode:
            raise SystemExit(completed.returncode)
    print("PASS local checks", flush=True)
