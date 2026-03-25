# BreachTrace

Automated credential forensics platform. Detects AWS keys leaked to public GitHub repos and generates a full impact report — which API calls were made, from where, on what resources — during the exposure window.

**Stack:** FastAPI · PostgreSQL · AWS CloudTrail · React + TypeScript · Tailwind · Gemini API

---

## Project Structure

```
breachtrace/
├── backend/
│   ├── main.py              # FastAPI app entry point
│   ├── config.py            # Env validation & settings
│   ├── requirements.txt
│   ├── detector/            # Regex credential scanner
│   ├── window/              # Exposure window calculator
│   ├── collectors/          # CloudTrail (+ future platforms)
│   ├── normalizer/          # Pydantic schema (ForensicEvent, IncidentRecord)
│   ├── classifier/          # Impact taxonomy + rule classifier
│   ├── scorer/              # Severity aggregation
│   ├── reporter/            # Gemini report generation
│   ├── db/                  # SQLAlchemy models + session
│   ├── research/            # Experiment harness + stats
│   └── tests/
├── client/                  # React + TypeScript + Tailwind frontend
│   └── src/
│       ├── pages/           # Dashboard, IncidentDetail, Research
│       ├── components/      # Timeline, BlastRadius, Severity, etc.
│       ├── api/client.ts    # Axios instance
│       └── types/index.ts   # TypeScript schema mirror
├── data/                    # SecretBench CSV (Track A dataset)
├── .env.example
└── .gitignore
```

---

## Setup

### Prerequisites

- Python 3.12+
- Node.js 20+
- PostgreSQL (local or Docker)
- AWS account with CloudTrail enabled in `us-east-1`

### 1. Clone & configure environment

```bash
git clone <repo-url>
cd breachtrace
cp .env.example .env
# Fill in all values in .env before proceeding
```

### 2. Backend

```bash
cd backend
pip install -r requirements.txt
```

Start the server:

```bash
# From the backend/ directory
$env:PYTHONPATH = (Get-Location).Path   # PowerShell
# export PYTHONPATH=$(pwd)              # bash/zsh

uvicorn main:app --reload --port 8000
```

Verify: `GET http://localhost:8000/` → `{"status":"ok","message":"BreachTrace running"}`

> `config.py` validates all required env vars at startup and exits with a clear error if any are missing.

### 3. Frontend

```bash
cd client
npm install
npm run dev   # http://localhost:5173
```

Set the API base URL in `.env.local` inside `client/`:

```env
VITE_API_URL=http://localhost:8000
```

### 4. Expose backend with ngrok (for GitHub webhooks)

```bash
ngrok http 8000
# Copy the https://... URL → use as GitHub webhook URL
```

---

## Environment Variables

All variables are required. See `.env.example` for the full template.

| Variable | Description |
|---|---|
| `AWS_ACCESS_KEY_ID` | Admin IAM key — used for CloudTrail queries |
| `AWS_SECRET_ACCESS_KEY` | Admin IAM secret |
| `AWS_REGION` | `us-east-1` |
| `EXPERIMENT_AWS_ACCESS_KEY_ID` | Read-only key that gets "leaked" in tests |
| `EXPERIMENT_AWS_SECRET_ACCESS_KEY` | Secret for the experiment key |
| `GITHUB_TOKEN` | PAT for GitHub API access |
| `GITHUB_WEBHOOK_SECRET` | Random 32-char string — set in GitHub webhook config |
| `GITHUB_TEST_REPO` | `username/breachtrace-test-repo` (public repo) |
| `GEMINI_API_KEY` | Google AI Studio key |
| `DATABASE_URL` | `postgresql://user:password@localhost:5432/breachtrace` |
| `ENVIRONMENT` | `development` or `production` |

---

## AWS Setup (one-time)

1. Create a **throwaway AWS root account** with a disposable email
2. Create IAM user `breachtrace-admin` → generate access key → set as `AWS_ACCESS_KEY_ID`
3. Create IAM user `breachtrace-experiment` with **only** `AmazonS3ReadOnlyAccess` + `AmazonEC2ReadOnlyAccess` → set as `EXPERIMENT_AWS_ACCESS_KEY_ID`
4. Enable CloudTrail: AWS Console → CloudTrail → Create Trail → name `breachtrace-trail` → all regions → management events ON → Read+Write

---

## Team

| Member | Owns |
|---|---|
| Ritwik | FastAPI · Webhook · CloudTrail collector · DB · Deploy |
| Shashank | DB schema · API spec · Taxonomy · Severity · Paper |
| Yash | AWS regex · Rule classifier · Research harness |
| Vedant | React dashboard · D3 timeline · Gemini reports · Normalisation |

**Guide:** Dr. Irfan Siddavatam · K.J. Somaiya College of Engineering

