# Run BreachTrace

This guide covers the native frontend/backend with an isolated PostgreSQL database in Docker, local Ollama inference, project GitHub connections, and optional cloud forensics. It reflects the repository as of 18 November 2026.

Run commands from the repository root unless a step says otherwise. On this Mac, that is:

```sh
cd /Users/shashanksathish/BreachTrace
```

On another machine, use the directory where you cloned the repository. Never copy or commit someone else's private environment files.

## 1. Everyday startup on the configured machine

Start Docker Desktop first. Keep these terminal processes open:

| Terminal | Purpose | Command |
| --- | --- | --- |
| 1 | Start the local database; command exits when ready | `docker compose --project-name breachtrace-local-test --env-file .env.testing.local -f docker-compose.local.yml up -d --wait db` |
| 2 | Backend, including built-in database job workers | `.venv/bin/python scripts/local_dev.py backend` |
| 3 | Frontend using the real backend | `.venv/bin/python scripts/local_dev.py frontend` |
| 4, optional | Ollama, if its desktop app is not already running | `ollama serve` |
| 5, optional | Public tunnel for GitHub push deliveries | `ngrok http 8000` |

If a server is already listening on its port, use the running instance rather than starting a second copy. The Ollama desktop app already runs its server; `ollama serve` is unnecessary in that case.

Open:

- Application: <http://127.0.0.1:5173>
- API documentation: <http://127.0.0.1:8000/docs>
- Backend health: <http://127.0.0.1:8000/health>
- Ollama API model list: <http://127.0.0.1:11434/api/tags>

The database is on `127.0.0.1:55432`, database name `breachtrace_local_test`. Do not run `bootstrap` on every restart. Existing accounts, projects, connections and incident data persist in the Docker database volume.

## 2. First-time installation

### Prerequisites

Install Python 3.12, Node.js 22.12 or newer in the Node 22 line, npm, and Docker Desktop with Compose. Ollama is optional for deterministic reports and required for the Ollama models. ngrok is needed only when GitHub must reach a backend running locally.

### Install dependencies

If `.venv` already exists and works, keep it. For a fresh checkout:

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r backend/requirements.txt -r backend/requirements-dev.txt
npm --prefix client ci
```

For Gemini's adapter, also install its optional SDK:

```sh
.venv/bin/python -m pip install google-genai
```

### Create a private local profile

```sh
.venv/bin/python scripts/local_dev.py prepare
```

This creates `.env.testing.local` if it does not exist. It preserves an existing file. The file holds local infrastructure configuration; GitHub project tokens, provider wallet connections, and model keys can be entered in the application.

On a fresh profile, generate the authentication and wallet encryption keys below. This adds only missing keys, writes the file privately, and does not print their values:

```sh
.venv/bin/python - <<'PY'
from pathlib import Path
from dotenv import dotenv_values
import os
import secrets

path = Path('.env.testing.local')
if not path.exists():
    raise SystemExit('Run scripts/local_dev.py prepare first')
values = dotenv_values(path)
additions = []
for name in ('JWT_SECRET_KEY', 'WALLET_ENCRYPTION_KEY'):
    if not values.get(name):
        additions.append(f'{name}={secrets.token_hex(32)}')
if additions:
    with path.open('a') as stream:
        stream.write('\n' + '\n'.join(additions) + '\n')
os.chmod(path, 0o600)
print('Local infrastructure keys are configured; values were not printed.')
PY
```

Keep the wallet encryption key stable and backed up with the database. Losing or changing it prevents saved GitHub tokens, provider connections and webhook secrets from being decrypted. It also affects matching of repeated Azure secrets. These infrastructure keys are separate from GitHub webhook secrets and provider credentials.

### Create a fresh local database schema

```sh
docker compose --project-name breachtrace-local-test --env-file .env.testing.local -f docker-compose.local.yml up -d --wait db
.venv/bin/python scripts/local_dev.py bootstrap
```

Bootstrap is restricted to the isolated local database. It creates missing tables and a clearly labelled synthetic fixture. It does not create an administrator account, configure real cloud providers, or apply Alembic migrations.

**For an older local database:** `create_all` does not add new columns to existing tables. Do not assume rerunning bootstrap upgrades it. The current configured Mac has received the new local schema additions. For another older ORM-created local database, back it up and assess its schema before upgrading; do not stamp it as migrated or delete its volume to bypass the problem.

Start the backend and frontend using section 1. On a new installation, visit <http://127.0.0.1:5173/setup> and create the organization and administrator. Setup is closed once an organization exists; use **Sign in** on subsequent starts.

## 3. Sign in and create projects

1. Sign in with your BreachTrace account.
2. Open **Admin → Projects → New project**.
3. Enter the project name and GitHub repository URL.
4. Add members under the project's settings.
5. Select the project in the app before configuring its connections or reviewing incidents.

The installation supports one organization with multiple projects. Developers see their assigned projects. Search, research and repository snapshot scans are organization-wide features for admins and security leads. Model settings and snapshot scans also require a local operator connection.

Password invitations are created in **Admin → Users**. GitHub invitations require a configured GitHub OAuth application and a matching verified GitHub email; see [GitHub sign-in](docs/github-signin.md). SMTP must be configured for invitation emails to be delivered. Repository-token access and GitHub user sign-in are separate integrations.

## 4. Start and select local models

Start the Ollama desktop app, or run `ollama serve`. Model installation requires internet once. Do not pull models that are already installed:

```sh
ollama list
```

These models were installed on the configured Mac during development:

- `llama3.2:latest`
- `qwen2.5vl:3b`
- `qwen2.5:7b-instruct-q4_K_M`

To install one on a new machine, pull only the model you need:

```sh
ollama pull llama3.2:latest
ollama pull qwen2.5vl:3b
ollama pull qwen2.5:7b-instruct-q4_K_M
```

In **Settings → Model settings**, the configured local setup uses:

| Setting | Value |
| --- | --- |
| Provider | Local model via Ollama |
| Model name, for report prose | `llama3.2:latest` |
| Answer model | `qwen2.5vl:3b` |
| Ollama address | `http://127.0.0.1:11434` |
| Offline model mode | Enabled |

Save and click **Test saved model**. The test checks both selected Ollama models if they differ. Reports start with a deterministic template; checked model prose can upgrade them. A rejected or unavailable model output leaves the deterministic report available.

The Qwen 7B model is an additional comparison candidate, not a proven better default. Model preference is hardware- and task-dependent; the small synthetic pilot is not a reliable ranking.

### Embeddings and offline behavior

Search uses the configured `BAAI/bge-small-en-v1.5` embedding model plus keyword retrieval. The embedding files are already cached on the configured Mac. Offline model mode loads embeddings from cache only; without cached files, search falls back to keywords.

On a new machine, explicitly cache embedding files while online before relying on semantic retrieval offline:

```sh
.venv/bin/python - <<'PYEMBED'
from scripts.local_dev import load_profile
load_profile()
import config
from fastembed import TextEmbedding
model = TextEmbedding(config.EMBED_MODEL, cache_dir=config.MODEL_CACHE_DIR, local_files_only=False)
list(model.embed(['Synthetic embedding setup check.']))
print('Configured embedding files are cached.')
PYEMBED
```

This command can download the configured embedding model; it does not send incident evidence to a model service. Restart the backend afterward if it had already fallen back to keyword-only retrieval. See [offline models](docs/offline-models.md). Do not change embedding models on an existing index without rebuilding its vectors. In-app embedding-model switching and a reranker are not implemented.

Offline model mode covers model inference and embedding downloads. GitHub and cloud-provider log collection still require network access.

## 5. Ask about an incident

1. Open an incident from Monitor.
2. Find **Ask about this incident**.
3. Enter a question, such as “What activity was observed after exposure?”
4. Leave **Generate an answer** checked and click **Ask**.
5. Review the cited evidence with the answer. The selected answer model is shown beside the settings link.

Generation needs relevant retrieved evidence. If the model is unavailable or its response cannot be used, the retrieved evidence remains available. Model prose and a successful citation-format check do not establish factual accuracy.

For a cloud model, choose OpenAI, Groq, Gemini or Anthropic/Claude in Settings, enter an exact model ID supported by your account and your key, then save and test. Selecting a cloud provider switches offline-model mode off. Entered keys are held in backend memory until restart and are cleared when changing providers; they are not stored in the preferences JSON. Cloud requests send report facts or questions with retrieved passages and can incur charges.

## 6. Connect GitHub without editing environment tokens

In **Connect → Project GitHub connection**, save a personal access token for the selected repository. It is encrypted and used immediately for that project's commit reads, private snapshot scans and optional automatic webhook registration.

- **Contents: read** is needed for commit diffs and private snapshots.
- **Webhooks: read and write** is needed only if BreachTrace creates or updates the webhook automatically.
- A read-only repository token works with a webhook you configure manually in GitHub.

### Manual webhook setup

1. Keep `ngrok http 8000` running.
2. Copy its current HTTPS forwarding origin.
3. In Connect, set the webhook URL to that origin followed by `/webhook/github`.
4. Open **Set up the webhook in GitHub**. Click **Generate hex secret**, then **Copy secret**.
5. In GitHub repository **Settings → Webhooks**, create or update one webhook:
   - Payload URL: the complete HTTPS URL ending in `/webhook/github`.
   - Content type: `application/json`.
   - Secret: exactly the generated value.
   - SSL verification: enabled.
   - Events: just the `push` event.
   - Active: checked.
6. Save the GitHub webhook, then click **Save project secret** in BreachTrace using the same value.
7. Redeliver the ping from GitHub's **Recent Deliveries**. A valid delivery receives HTTP 202; reload BreachTrace to see **Signed delivery verified**.

A ping verifies connectivity and the shared secret. A later push tests commit processing. Only qualifying additions in commits create webhook findings; pings and connecting the webhook do not scan old commits. A current snapshot scan is separate and returns masked candidates rather than inventing exposure incidents.

If the ngrok origin changes, update the GitHub payload URL. Avoid duplicate hooks pointing at the same backend. See [project routing](docs/project-incident-routing.md) for scope and secret behavior.

## 7. Configure provider forensics

Open **Admin → Projects → your project → Credential wallet** and add a reader for each provider you want to collect from. Save and verify the connection before refreshing incidents. These are project-scoped, encrypted, write-only connections; a project missing a verified reader does not fall back to another project's credentials.

| Provider | Reader fields |
| --- | --- |
| AWS | Access key ID, secret access key, region |
| Google Cloud | Authorized service-account JSON with its project ID |
| Azure | Tenant ID, reader application/client ID, matching client secret value, subscription ID |
| Stripe | Secret or restricted Events reader key matching the affected account and test/live mode |
| Twilio | Owning Account SID and API key SID/secret, or Account Auth Token |

Verification checks a specific read operation; it does not prove every forensic permission or complete coverage. Use only reader credentials you own or are authorized to use. See [wallet requirements](docs/credential-wallet.md).

### Azure

- The reader needs Activity Log access for the intended subscription. **Monitoring Reader** at that subscription is one suitable built-in role.
- A secret-only finding needs the owning application's **Application (client) ID** associated on the incident page before collection can start. The application ID may differ from the reader's ID.
- For the separate **Azure sign-in evidence** query, the reader application needs Microsoft Graph **Application permission `AuditLog.Read.All`**, tenant admin consent, and appropriate Entra licensing/access. See [Microsoft's sign-in API requirements](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-beta).
- To compare sign-ins with an individual secret, supply its independently identified **credential key ID**, not its secret value.
- Activity Log is application-level evidence and can be identical for multiple secrets. Sign-in evidence does not automatically attribute later resource operations to that secret.

Open the incident, associate the owning application if prompted, and click **Collect Azure activity**. After association, **Refresh logs** retrieves recent available history. Earlier events remain historical context rather than commit-caused impact. No observed events in an exposure window does not prove the key was unused. See [exposure and attribution](docs/exposure-attribution.md).

## 8. Compare local report models

Open **Research → Local report model comparison**:

1. Refresh the installed model list.
2. Select up to four installed models.
3. Choose 1–12 synthetic cases per model.
4. Run the comparison and leave the backend/Ollama running.
5. Download the result JSON when complete.

The job compares identical facts and includes a deterministic baseline, model digests, fixture hash, prompt version, latency and validation/fact-coverage proxies. The page shows the latest run. The comparison can take minutes. It does not evaluate retrieval or RAG-answer accuracy, and small samples do not support general model rankings.

For a command-line report benchmark:

```sh
PYTHONPATH=backend .venv/bin/python -m research.model_benchmark --model llama3.2:latest --model qwen2.5:7b-instruct-q4_K_M --cases 4 --seed 20261103 --out data/model-comparison.json
```

Keep CLI comparisons separate from UI comparisons to avoid competing for the same model runtime. The CLI output file is not automatically imported into the Research page.

For the fixed keyword retrieval evaluation:

```sh
PYTHONPATH=backend DATABASE_URL=sqlite:// EMBED_ENABLED=false .venv/bin/python -m rag.evaluate
```

This evaluates a repository fixture, not independently labelled real incident accuracy.

## 9. Optional services

### Email and Slack

Email delivery requires SMTP infrastructure configured on the backend. Project email/Slack destinations are managed in the app. See [notifications](docs/notifications.md). Failed mail delivery does not mean the invitation account was never created; check delivery status before reinviting the same email.

### Stripe sandbox request stream

Normal Stripe Events collection uses the project wallet. Supplementary request capture requires the Stripe CLI and a separate worker:

```sh
.venv/bin/python scripts/stripe_request_logs.py --confirm-sandbox
```

Configure the dedicated sandbox restricted key, incident ID and ingestion token as described in [Stripe request capture](docs/stripe-request-stream.md) before running it. This worker is sandbox-only, captures new requests while connected, cannot backfill, and does not identify the key responsible. It is not required for the normal app or Azure collection.

### Alternative Docker backend

The repository also has `docker-compose.yml` for a database and backend using `.env`. This is a separate development deployment path; see [deployment](docs/DEPLOYMENT.md). It uses port 8000 as well, runs migrations and model setup at startup, and does not start the frontend. Do not run it alongside the native backend on the same port. Container loopback does not reach a host Ollama service at `127.0.0.1`; the current local-only model configuration is intended for the native backend path above.

## 10. Checks and troubleshooting

Frontend checks:

```sh
npm --prefix client run lint
npm --prefix client run build
npm --prefix client test
```

Backend tests:

```sh
.venv/bin/pytest -q --disable-warnings
```

Tests use isolated fixtures by default. A passing targeted check is not a guarantee that the full suite passes. Investigate any failures; some older tests still expect the previous in-process job behavior. Do not run live provider experiments by publishing active credentials.

For an **Alembic-managed database**, load its intended private `DATABASE_URL`, back it up, then run from the backend directory:

```sh
cd backend
../.venv/bin/alembic current
../.venv/bin/alembic heads
../.venv/bin/alembic upgrade head
```

Run `cd ..` to return to the repository root. This is not the upgrade procedure for an ORM-created local test database. Do not stamp an existing schema to bypass migration errors.

| Symptom | What to check |
| --- | --- |
| Port 8000, 5173 or 11434 already in use | A backend, frontend or Ollama server is already running. Reuse it or stop that specific process before restarting. |
| Database connection refused | Start Docker Desktop and the isolated Compose database. Check `docker compose --project-name breachtrace-local-test --env-file .env.testing.local -f docker-compose.local.yml ps`. |
| Missing table/column after pulling code | Database schema is older than the code. Distinguish Alembic-managed and ORM-created local databases before upgrading. |
| API 401 from the app | Sign in again; JWT keys or sessions may have changed. |
| Invalid webhook signature | Save the identical secret in GitHub and the selected BreachTrace project, then redeliver a ping. |
| Automatic registration denied | Use manual setup with a Contents-read token, or grant the saved token Webhooks-write permission. |
| Webhook status awaits verification | Send/redeliver a signed ping or push and reload. Saving a secret alone does not verify delivery. |
| No incident after a successful ping | A ping is not a push or scan. Test a harmless push; inspect its delivery and added content. |
| Detection only / no Refresh logs | The credential may lack its owning principal, or its provider has no supported forensic collector. Review the incident's explanation. |
| Azure returns repeated historical events | Several secrets may belong to one application. Compare timing and available key-specific sign-ins; do not relabel history as exposure impact. |
| Azure Graph query denied | Check `AuditLog.Read.All` application permission, admin consent, tenant/license and policies. Activity Log access is a separate permission. |
| Model check fails | Confirm Ollama is running, model names match installed tags, and sufficient memory is available; for cloud models check the model ID and key. |
| Cloud key stopped working after restart | Keys entered in model settings are memory-only; enter the key again. |
| Settings rejected from a remote URL | Model settings require local operator access. Open the local frontend at `127.0.0.1:5173`. |
| No semantic retrieval offline | Cache the configured embedding model first; keyword search remains available. |

## 11. Stop and preserve data

Use Ctrl+C in the terminals running the frontend, backend, ngrok and optional Stripe worker. Stop an explicit `ollama serve` process with Ctrl+C, or quit the Ollama desktop app if desired.

Stop the local database without deleting its volume:

```sh
docker compose --project-name breachtrace-local-test --env-file .env.testing.local -f docker-compose.local.yml stop db
```

Keep `.env.testing.local`, the database backup, and the stable wallet encryption key securely. Do not run `docker compose down -v` unless you intentionally want to delete the database volume. No shutdown command above deletes accounts, incidents, installed models or project connections.
