# Scanner and setup logic review

Verified on 2026-11-03. The review covered detection, diff provenance, repository
scan limits, simulation error handling, and the existing database migration path.

## Fixes

- Diff scanning now uses added/unchanged post-commit source. Deleted lines cannot
  supply provider context, secret-pair evidence, or literal fragments. Removing
  a comment no longer breaks reconstruction of literals that become adjacent.
- File/hunk barriers apply to AWS, GCP, Azure, Twilio and AI context. Nested JSON
  AI configuration is parsed separately for each source fragment.
- GCP/Azure/SaaS line numbers and diagnostic text map back to the input diff.
  Rejected GCP/Twilio identifiers no longer suppress a later qualifying match.
- AWS context text is prepared once rather than rebuilding the full file for
  each key. A controlled 799,999-character input with 20,000 distinct AWS IDs
  scanned in 0.124 seconds on this machine. This is a synthetic performance check.
- AI eligibility lookup avoids repeatedly traversing every added line for every
  hunk. Full-file scans retain the same source handling.
- A repository scan that exceeds its timeout in its final file is marked partial
  and keeps any findings already obtained. UI partial-scan text includes decoding
  failures; Hugging Face no longer appears twice in the platform list.
- Simulation errors no longer echo a caller-supplied credential. Diff input is
  limited to 2,097,152 characters and rejected before scanning if oversized.

## Migration repair

The deleted `d5e6f7a8b9c0` revision had left the report/search migration with a
missing parent. It now follows the existing replacement `37cd4df9188c` revision.
The deleted file remains deleted; the replacement keeps its revision identity.

The replacement migration now preserves run IDs, groups, timestamps, severity
labels and latency units. Legacy milliseconds are converted to seconds. Original
rows, including fields absent from the current ORM, are retained in
`experiment_runs_legacy_37cd4df9188c`. Existing rows receive a valid Boolean
default, and the primary key is recreated after the legacy ID column is removed.

Empty databases support downgrade/re-upgrade across this transition. A populated
research-table downgrade is refused atomically because the old schema cannot
represent all current run metadata; restoring a verified backup is required for
such a rollback. No populated database is silently truncated or assigned fake
required values.

Validation covered fresh databases and populated legacy databases at
`c4d5e6f7a8b9`, including ORM inserts after upgrade. It does not automatically
reconcile an already-deployed database stamped with the deleted revision or
repair a database that previously applied the old replacement migration.
No existing application database was migrated or stamped during this review.
The running local test app continues to use its separate ORM-initialized database.

Repeat the disposable PostgreSQL checks with the isolated local test server up:

```sh
.venv/bin/python scripts/check_migrations.py
```

Only newly generated databases on `127.0.0.1:55432` are created and dropped.
The script refuses other servers. Results are saved to
`data/migration-verification.json`.

## Verification

- Backend: **1,246 passed, 2 skipped**. Existing deprecation/async-test warnings
  remain; these checks do not claim a complete security audit.
- Frontend: production build and lint passed. Existing bundle-size advisory remains.
- Migration graph: one connected head, `e8f9a0b1c2d3`.
- Real PostgreSQL: fresh upgrade, empty downgrade/re-upgrade, populated upgrade,
  original data/units/archive checks, primary keys, ORM inserts and atomic refusal
  of a populated downgrade passed. Temporary verification databases were removed.
- Live local API: false-positive cases are ignored; valid post-commit Sarvam
  reconstruction creates a masked detection-only incident; credential errors are
  redacted. The backend was restarted with these fixes.
- Public `shash-17/Notes-App-MERN` rescan: 38 files, zero candidates, complete under
  the disclosed snapshot policy. This is not proof of absence of all secrets.
  Live check evidence: `data/logic-review-live.json`.

The `data/` evidence files are local and gitignored. Test credentials are synthetic;
no detected credential was sent to a provider for validation.
