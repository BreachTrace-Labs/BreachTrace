# Run and test locally

The isolated local profile uses real application APIs, a separate PostgreSQL
database, and clearly labelled synthetic incident data. It does not consume cloud
credentials from the existing `.env`. Synthetic fixtures are not research evidence.

Setup verified on 2026-11-03: all 14 live smoke checks passed, including database
reads, semantic search, a timestamp query, masked AI detection, local Ollama model
access, and a public GitHub snapshot scan. Dependency validation (`pip check`) passed.

- UI: http://127.0.0.1:5173
- Backend/API docs: http://127.0.0.1:8000/docs
- Database: localhost:55432, `breachtrace_local_test` (separate Docker volume)
- Configuration: `.env.testing.local` (gitignored; never share its contents)
- Model preferences: `data/model-settings.testing.json`

## Restart

From the repository root, after Docker Desktop is running:

```sh
docker compose --project-name breachtrace-local-test --env-file .env.testing.local -f docker-compose.local.yml up -d --wait db
.venv/bin/python scripts/local_dev.py bootstrap
```

Start the backend and frontend in separate terminals:

```sh
.venv/bin/python scripts/local_dev.py backend
```

```sh
.venv/bin/python scripts/local_dev.py frontend
```

The initial profile was created with `.venv/bin/python scripts/local_dev.py prepare`.
It preserves an existing profile. Bootstrap is restricted to the named isolated
database and creates the current ORM schema, leaving the pre-existing migration
chain unchanged. It adds the single-organisation index to existing ORM-created
local test databases after checking that at most one organisation exists. An
Alembic-managed database must use migrations instead. It preserves existing sample
data instead of duplicating it.

## Try the new features

Six labelled [AI detection examples](ai-ui-demo.md) are available at
http://127.0.0.1:5173/?platform=ai, including encoded and split-key samples.
Reseed them with `.venv/bin/python scripts/seed_ai_demos.py` when needed.

1. **Monitor:** open the `local-test://synthetic-forensic-timeline` incident.
   Inspect its three timeline events and clearly labelled synthetic report.
2. **Search:** ask `what happened at 2026-11-03T12:00:30Z` or
   `how do I rotate a Twilio auth token`. Local embeddings and keyword retrieval
   are both configured.
3. **Settings:** deterministic reports are the default. For local generation,
   select Ollama and enter `llama3.2:latest` or `qwen2.5vl:3b`, save, then test.
   Ollama must remain running. Cloud providers require your own keys entered
   in Settings; they are not needed for local testing.
4. **Connect:** enter `https://github.com/fastapi/fastapi` in the repository URL
   field and click **Scan repository**. No webhook or GitHub token is needed
   for this public scan. Private repositories and webhook registration require
   a suitable GitHub token configured explicitly in the test profile and restart.
5. **AI detection:** `/test/simulate` in API docs can accept a synthetic credential
   diff. The automated smoke test adds a synthetic Groq-format detection-only
   incident. No detected key is validated with the provider.

Research tables are initially empty: synthetic setup data is deliberately not
inserted as measured research runs. Real cloud forensics needs explicit platform
credentials; the local testing profile leaves those empty.

Verify the running stack:

```sh
.venv/bin/python scripts/smoke_local.py
```

This creates a synthetic AI-detection incident, briefly tests a local model,
restores model preferences, and scans the public FastAPI snapshot. Results are
saved under `data/local-smoke-results.json`. Do not run it with production data
or cloud credentials. Use it only with the isolated profile described above.

To stop: Ctrl+C in each server terminal; stop the database with:

```sh
docker compose --project-name breachtrace-local-test --env-file .env.testing.local -f docker-compose.local.yml stop db
```

Do not use `down -v` unless you intend to delete the test database volume.
