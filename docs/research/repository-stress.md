# Public repository stress tests

Measured on 2026-11-03, Darwin arm64. Shallow checkouts, no repository code executed.
Scans cover current UTF-8 text files within the documented policy, not Git history.

| Repository | Text files | MiB text | Seconds | Candidates | Policy traversal complete |
|---|---:|---:|---:|---:|---|
| microsoft/vscode | 20,392 | 257.0 | 57.42 | 36 | True |
| fastapi/fastapi | 3,045 | 23.9 | 9.20 | 0 | True |
| fastapi/fastapi + local synthetic Groq probe | 3,046 | 23.9 | 4.45 | 1 | True |

Raw JSON contains pinned commit IDs, exclusions, skip counts, and masked candidate
locations. No key was submitted to a provider for validity checking. These public
repositories have no independent secret labels, so candidate counts are not
confirmed leaks and do not establish precision/recall or a false-positive rate.
The VS Code results include many testing/configuration locations requiring manual
review; they must not be described as compromised production credentials.

The FastAPI seeded run adds one local synthetic Groq-format value (not a real
credential) to the same checkout and finds exactly that probe. This is a narrow
regression check, not real-world recall. The original unmodified FastAPI run
predates the final literal-prefilter optimization, so these times are observations,
not a controlled before/after speedup claim.

The stress work exposed unnecessary regex work on unrelated source. Necessary
literal prefilters now bypass that work, and service-account email matching has
bounded lengths and a token boundary. A long-token regression test passes. Binary,
non-UTF-8, symlink and oversized-file skips are reported explicitly. No source code
or credential values are included in these reports.

Reproduce with shallow checkouts at the recorded commits:

```sh
PYTHONPATH=backend .venv/bin/python -m research.repository_stress /path/to/vscode --out data/stress-vscode.json
PYTHONPATH=backend .venv/bin/python -m research.repository_stress /path/to/fastapi --out data/stress-fastapi.json
```
