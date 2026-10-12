# Examples

Run from the repository root:

```sh
python newline-audit examples/clean-lf.txt
python newline-audit --json examples/mixed.txt
```

- `clean-lf.txt`: 8 bytes, two LF endings, no findings; exit **0**.
- `mixed.txt`: 25 bytes, one LF, one CRLF, one lone CR, and an unfinished final
  line; findings `mixed,missing_final_newline`; exit **1** (expected).

The mixed fixture is intentionally not terminated by a newline. Its Git
attribute is `-text` so checkout does not convert its CRLF/CR bytes.

NUL detection is covered by tests using temporary byte fixtures; the auditor
never prints file contents, decodes text, or rewrites any input.
