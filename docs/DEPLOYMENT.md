# Deploy BreachTrace

The repository's Compose file starts PostgreSQL and the backend. Run the frontend separately, or serve its production build behind a web server. The supplied Compose file mounts the backend source and runs Uvicorn with reload; treat it as a development stack rather than a hardened production deployment.

## Configure secrets and origins

Copy `.env.example` to `.env` and replace the placeholders. Keep `.env` private and outside version control. Generate two independent random secrets with:

```sh
python3 -c 'import secrets; print(secrets.token_hex(32))'
python3 -c 'import secrets; print(secrets.token_hex(32))'
```

Set the first result as `JWT_SECRET_KEY` and the second as `WALLET_ENCRYPTION_KEY`. Keep the wallet encryption key safe and stable: changing or losing it makes saved provider credentials, project webhook secrets, and Slack webhook URLs unreadable. Set a strong `POSTGRES_PASSWORD` in `.env` before creating the database volume. Existing PostgreSQL volumes retain their original password; changing the environment variable does not rotate it.

Set `FRONTEND_ORIGIN` to the browser origin, including scheme and port, for example `https://breachtrace.example.com`. Separate multiple explicitly trusted origins with commas. Set `APP_URL` to the reachable frontend URL used in email links. The local defaults allow the two Vite loopback origins on port 5173. Configure `SMTP_HOST`, `SMTP_PORT`, `SMTP_FROM`, and any SMTP credentials to enable email; see [notifications.md](notifications.md).

Save a repository token for each project in Connect → Project GitHub connection; no `GITHUB_TOKEN` environment value is needed for project workflows. GitHub webhook delivery requires an externally reachable HTTPS URL. Each project uses its own encrypted webhook secret. The `/webhook/github` route validates GitHub's HMAC signature and does not require a JWT.

The current configuration validation requires the AWS, experiment, GitHub, database, and environment variables listed in `backend/config.py`. Set up only credentials you are authorized to use. `BREACHTRACE_LOCAL_TEST_MODE=true` relaxes the required provider settings for an isolated local test environment; it does not configure those providers.

## Start and migrate

With Docker and Docker Compose installed, from the repository root:

```sh
docker compose up --build -d
docker compose logs -f backend
```

The backend container runs `alembic upgrade head` automatically before Uvicorn starts. To apply migrations explicitly to the configured Compose database after it is ready:

```sh
docker compose run --rm backend alembic upgrade head
```

The backend listens on `http://localhost:8000`. Configure a frontend that can reach it, for example for local development:

```sh
cd client
npm ci
VITE_USE_MOCK=false VITE_API_URL=http://localhost:8000 npm run dev -- --host 127.0.0.1 --port 5173
```

Visit `http://127.0.0.1:5173/setup` for initial organization and administrator creation. Setup closes once an organization exists. Configure project membership, webhook, wallet, and notification destinations in the app.

The Compose command attempts model setup at startup and may need network access for model assets. No validated generative report model is bundled; deterministic reports do not require one.

## Operational boundaries

The login limit allows five requests per minute per direct client IP and uses process memory. Run a single backend process for this limit, or enforce a shared limit at a trusted reverse proxy when using multiple processes or replicas. A reverse proxy must pass a trustworthy client IP only when Uvicorn is explicitly configured to trust that proxy; otherwise the limit applies to the proxy address.

Each installation and database supports exactly one organization. A database constraint prevents a second; the migration refuses existing databases with multiple organizations without altering their data. Search, research and snapshot scans are organization-wide and restricted to admins and security leads, regardless of the selected project. Repository snapshots and model settings require a local operator connection. Project collection uses verified project wallet entries; legacy unassigned incidents use environment readers. The backend runs database-backed job workers; apply migrations before starting this version. Notification retries are at least once and may produce duplicates after an interrupted delivery. Restrict database and backend network access, use HTTPS at the public edge, and back up the database together with its encryption key.
