# BreachTrace

Universal credential forensics platform. Detects credentials across 12 types (AWS, GCP, Azure, Stripe, Twilio, Firebase, GitHub, Slack, NPM, HuggingFace, DB connection strings, SendGrid) leaked to public GitHub repos. For 6 platforms with audit APIs (Tier 1: AWS, GCP, Azure, Stripe, Twilio, Firebase), generates a full forensic report — which API calls were made, from where, on what resources — during the exposure window. For 6 detection-only platforms (Tier 2), provides exposure window, remediation checklist, and explains why forensic reconstruction is unavailable.

**Stack:** FastAPI · PostgreSQL · React + TypeScript · Tailwind · Gemini API · Multi-cloud (AWS CloudTrail, GCP Cloud Audit Logs, Azure Activity Log)

---

## Project Structure

```
breachtrace/
├── backend/
│   ├── main.py              # FastAPI app entry point
│   ├── config.py            # Env validation & settings
│   ├── pipeline.py          # End-to-end incident pipeline orchestration
│   ├── requirements.txt
│   ├── routers/             # API endpoints
│   │   ├── webhook.py       # GitHub webhook listener (POST /webhook/github)
│   │   ├── incidents.py     # Incident CRUD + details (GET/POST /incidents)
│   │   ├── research.py      # Research mode + accuracy experiments
│   │   └── simulate.py      # Manual incident simulation
│   ├── detector/            # Multi-platform regex credential scanner
│   │   ├── patterns.py      # Regex patterns for 12 credential types
│   │   └── scanner.py       # Scanner dispatch (AWS, GCP, Azure, SaaS)
│   ├── window/              # Exposure window & revocation monitoring
│   │   ├── calculator.py    # Exposure window (commit → revocation)
│   │   ├── azure_revocation.py
│   │   └── gcp_revocation.py
│   ├── collectors/          # Audit log collectors (Tier 1 platforms)
│   │   ├── aws.py           # AWS CloudTrail collector
│   │   ├── gcp.py           # GCP Cloud Audit Log collector
│   │   ├── azure.py         # Azure Activity Log collector
│   │   ├── stripe.py        # Stripe Events API collector
│   │   └── twilio.py        # Twilio logs collector
│   ├── normalizer/          # Pydantic schemas (ForensicEvent, IncidentRecord)
│   │   └── schema.py
│   ├── classifier/          # Impact taxonomy + rule classifier
│   │   ├── rules.py         # Platform-specific heuristics
│   │   ├── taxonomy_aws.py  # AWS API → impact category mapping
│   │   ├── taxonomy_gcp.py  # GCP API → impact category mapping
│   │   ├── taxonomy_azure.py# Azure API → impact category mapping
│   │   ├── taxonomy_stripe.py
│   │   └── taxonomy_twilio.py
│   ├── scorer/              # Severity aggregation (GDPR, financial impact)
│   │   └── severity.py
│   ├── reporter/            # Gemini LLM report generation
│   │   └── gemini.py
│   ├── db/                  # SQLAlchemy models + session
│   │   ├── database.py
│   │   ├── models.py        # IncidentRecord, ForensicEvent, collection_status
│   │   └── crud.py          # Database queries
│   ├── research/            # Experiment harness + cross-platform analysis
│   │   ├── harness.py       # run_aws_experiment, run_gcp_experiment, etc.
│   │   ├── analysis.py      # Cross-platform accuracy metrics
│   │   └── fp_corpus.py     # False-positive dataset
│   ├── migrations/          # Alembic DB schema migrations
│   │   └── versions/
│   └── tests/               # Full test suite (offline, no credentials needed)
├── client/                  # React + TypeScript + Tailwind frontend
│   └── src/
│       ├── pages/           # Dashboard, IncidentDetail, Research
│       ├── components/      # Timeline, BlastRadius, Severity, Platform icons
│       ├── api/             # Axios HTTP client
│       ├── lib/             # Utility functions
│       └── types/           # TypeScript schema mirror
├── data/                    # SecretBench CSV (Track A dataset, if obtained)
├── context/                 # Research docs & architecture notes
├── .env.example
├── docker-compose.yml
├── Dockerfile.backend
├── pytest.ini
├── README.md
└── .gitignore
```

---

## Setup

### Prerequisites

- **Python 3.12+** — Hard requirement. The codebase uses PEP 604 unions (`int | None`) in runtime-evaluated dataclass annotations. On Python 3.9 (the macOS system default), every test file fails at import with `TypeError: unsupported operand type(s) for |`. Verify with `python3 --version`.
- Node.js 20+
- PostgreSQL (local or Docker)
- **AWS account** with CloudTrail enabled in `us-east-1` (required for Tier 1 forensics)
- **GCP project** (optional, for GCP credential forensics)
- **Azure subscription** (optional, for Azure credential forensics)

### 1. Clone & configure environment

```bash
git clone <repo-url>
cd breachtrace
cp .env.example .env
# Fill in required variables (AWS, GitHub, Gemini, Database)
# GCP and Azure variables are optional — leave empty to disable those platforms
```

### 2. PostgreSQL Setup

Initialize a local PostgreSQL database:

```bash
# macOS (via Homebrew)
brew install postgresql
brew services start postgresql
createdb breachtrace

# Or use Docker
docker run --name breachtrace-postgres -e POSTGRES_PASSWORD=password -e POSTGRES_DB=breachtrace -p 5432:5432 -d postgres:15
```

Set `DATABASE_URL` in `.env`:

```env
DATABASE_URL=postgresql://postgres:password@localhost:5432/breachtrace
```

Run migrations:

```bash
cd backend
.venv/bin/alembic upgrade head
```

### 3. Backend

Create a Python 3.12+ virtualenv from the repo root (`.venv/` is gitignored):

```bash
python3.12 -m venv .venv
source .venv/bin/activate
```

Install runtime + dev dependencies:

```bash
pip install -r backend/requirements.txt -r backend/requirements-dev.txt
```

Start the server:

```bash
# From the backend/ directory
export PYTHONPATH=$(pwd)/..
uvicorn main:app --reload --port 8000
```

Verify: `GET http://localhost:8000/` → `{"status":"ok","message":"BreachTrace running"}`

> `config.py` validates all required env vars at startup and exits with a clear error if any are missing. GCP/Azure env vars are optional.

### 3a. Running the tests

From the **repo root** (not `backend/`) — `pytest.ini` sets `pythonpath = .`, so imports like `from detector.scanner import scan` resolve only from the root:

```bash
.venv/bin/python -m pytest backend/tests -q
```

No AWS, GCP, Azure, or database credentials are needed — the suite is fully offline.
Tests marked `integration` require live services and are excluded by default:

```bash
.venv/bin/python -m pytest backend/tests -q -m "not integration"
```

### 4. Frontend

```bash
cd client
npm install
npm run dev   # http://localhost:5173
```

Set the API base URL in `.env.local` inside `client/`:

```env
VITE_API_URL=http://localhost:8000
```

### 5. Expose backend with ngrok (for GitHub webhooks)

```bash
ngrok http 8000
# Copy the https://... URL → use as GitHub webhook URL
```

---

## Environment Variables

### Required (for any deployment)

| Variable | Description |
|---|---|
| `AWS_ACCESS_KEY_ID` | Admin IAM key — used for AWS CloudTrail queries |
| `AWS_SECRET_ACCESS_KEY` | Admin IAM secret |
| `AWS_REGION` | `us-east-1` |
| `EXPERIMENT_AWS_ACCESS_KEY_ID` | Read-only IAM key that gets "leaked" in tests (S3 + EC2 read-only) |
| `EXPERIMENT_AWS_SECRET_ACCESS_KEY` | Secret for the experiment key |
| `GITHUB_TOKEN` | GitHub PAT for webhook signature verification + API access |
| `GITHUB_WEBHOOK_SECRET` | Random 32-char string — set in GitHub webhook config |
| `GITHUB_TEST_REPO` | Public test repository for simulated leaks (`username/breachtrace-test-repo`) |
| `GEMINI_API_KEY` | Google AI Studio API key for forensic report generation |
| `DATABASE_URL` | PostgreSQL connection string (`postgresql://user:password@localhost:5432/breachtrace`) |
| `ENVIRONMENT` | `development` or `production` |

### Optional (GCP Tier 1 forensics — leave empty to disable)

| Variable | Description |
|---|---|
| `GCP_PROJECT_ID` | GCP project ID |
| `GCP_SERVICE_ACCOUNT_JSON` | Full service account JSON key (admin user for Cloud Audit Log queries) |
| `GCP_EXPERIMENT_CLIENT_EMAIL` | Experiment service account email (the "leaked" credential) |
| `GCP_EXPERIMENT_PRIVATE_KEY_ID` | Experiment service account key ID |
| `GCP_EXPERIMENT_PRIVATE_KEY` | Experiment service account private key (PEM format) |

### Optional (Azure Tier 1 forensics — leave empty to disable)

| Variable | Description |
|---|---|
| `AZURE_TENANT_ID` | Azure tenant ID (directory ID) |
| `AZURE_CLIENT_ID` | Admin app registration client ID (Reader + Log Analytics Reader roles) |
| `AZURE_CLIENT_SECRET` | Admin app registration client secret |
| `AZURE_SUBSCRIPTION_ID` | Azure subscription ID to monitor |
| `AZURE_EXPERIMENT_CLIENT_ID` | Experiment app registration client ID (the "leaked" credential) |
| `AZURE_EXPERIMENT_CLIENT_SECRET` | Experiment app registration client secret |

---

## Credential Coverage — Tier 1 (Forensic) vs Tier 2 (Detection-Only)

BreachTrace detects **12 credential types** across 12 platforms, but only **6 platforms have audit APIs** that enable forensic reconstruction.

### Tier 1 — Full Forensic Reconstruction
Generate detailed incident reports with blast radius analysis, timeline, and impact classification.

| Platform | Detector | Collector | Impact Categories | Status |
|---|---|---|---|---|
| **AWS** | ✅ AKIA + SecretKey | ✅ CloudTrail | reconnaissance, data_access, exfiltration, financial_impact | ✅ Complete |
| **GCP** | ✅ Service Account email + private_key | ✅ Cloud Audit Log | reconnaissance, data_access, exfiltration | In Sprint 3 |
| **Azure** | ✅ Client ID + Client Secret | ✅ Activity Log | reconnaissance, data_access, exfiltration | In Sprint 3 |
| **Stripe** | ✅ sk_live_* | ✅ Events API | data_access | In Sprint 3 |
| **Twilio** | ✅ AC* + auth token | ✅ Usage Records | data_access, exfiltration | In Sprint 3 |
| **Firebase** | ✅ Service Account (GCP) | ✅ Cloud Audit Log (reuses GCP) | reconnaissance, data_access, exfiltration | In Sprint 3 |

### Tier 2 — Detection Only
Identify credential leaks, classify credential type, provide remediation checklist, but cannot reconstruct activity (no audit API available or enterprise-only).

| Platform | Detector | Why Not Forensic |
|---|---|---|
| **GitHub PAT** | ✅ ghp_ | Enterprise orgs only |
| **Slack Webhook** | ✅ xoxb_ / xoxp_ | Enterprise Grid required |
| **NPM Token** | ✅ npm_* | No public per-token audit API |
| **SendGrid** | ✅ SG.* | Email Activity API is paid add-on |
| **HuggingFace** | ✅ hf_* | No audit API |
| **DB Connection String** | ✅ user:password@host | Audit depends on target DB |

---

## Cloud Setup (One-time)

### AWS (Required)

1. **Create a throwaway AWS account** with a disposable email (recommended for security)
2. **Create admin user `breachtrace-admin`:**
   - Generate access key → set as `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`
3. **Create experiment user `breachtrace-experiment`:**
   - Attach policies: `AmazonS3ReadOnlyAccess`, `AmazonEC2ReadOnlyAccess`
   - Generate access key → set as `EXPERIMENT_AWS_ACCESS_KEY_ID` and `EXPERIMENT_AWS_SECRET_ACCESS_KEY`
4. **Enable CloudTrail in `us-east-1`:**
   - AWS Console → CloudTrail → Create Trail
   - Name: `breachtrace-trail`
   - Enable for all regions
   - Management events: ON (Read + Write)

### GCP (Optional — for GCP credential forensics)

1. **Create a GCP project** (or use existing)
2. **Create service account for admin queries:**
   - IAM → Service Accounts → Create Service Account
   - Name: `breachtrace-admin`
   - Roles: `Logs Viewer`, `Project Viewer`, `Security Reviewer`
   - Download JSON key → paste into `GCP_SERVICE_ACCOUNT_JSON` as full JSON string
   - Set `GCP_PROJECT_ID` to your project ID
3. **Create experiment service account (the "leaked" credential):**
   - Name: `breachtrace-experiment`
   - Role: `Storage Object Viewer` (minimal permissions)
   - Download JSON key → extract:
     - `client_email` → `GCP_EXPERIMENT_CLIENT_EMAIL`
     - `private_key_id` → `GCP_EXPERIMENT_PRIVATE_KEY_ID`
     - `private_key` → `GCP_EXPERIMENT_PRIVATE_KEY`
4. **Enable Cloud Audit Logs:**
   - APIs & Services → Enable `Cloud Logging API`
   - Ensure Admin Activity and System Event logs are on

### Azure (Optional — for Azure credential forensics)

1. **Create or use existing Azure subscription**
2. **Create admin app registration:**
   - Azure Portal → App Registrations → New Registration
   - Name: `breachtrace-admin`
   - Assign roles to the app: `Reader`, `Log Analytics Reader` (on the subscription)
   - Create client secret
   - Set:
     - `AZURE_TENANT_ID` = Directory ID
     - `AZURE_CLIENT_ID` = App client ID
     - `AZURE_CLIENT_SECRET` = The secret value
     - `AZURE_SUBSCRIPTION_ID` = Subscription ID
3. **Create experiment app registration (the "leaked" credential):**
   - Name: `breachtrace-experiment`
   - Role: `Storage Blob Data Reader` (minimal permissions)
   - Create client secret → set as `AZURE_EXPERIMENT_CLIENT_ID` and `AZURE_EXPERIMENT_CLIENT_SECRET`
4. **Enable Activity Log:**
   - Monitor → Activity Log (enabled by default)
   - 90-day retention

---

## Team

| Member | Owns |
|---|---|
| Ritwik | FastAPI · Webhook · CloudTrail collector · DB · Deploy |
| Shashank | DB schema · API spec · Taxonomy · Severity · Paper |
| Yash | AWS regex · Rule classifier · Research harness |
| Vedant | React dashboard · D3 timeline · Gemini reports · Normalisation |

**Guide:** Dr. Irfan Siddavatam · K.J. Somaiya College of Engineering

