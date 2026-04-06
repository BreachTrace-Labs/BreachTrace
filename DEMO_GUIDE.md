# BreachTrace — Complete Local Demo Guide

**Group 03 · K.J. Somaiya College of Engineering · Information Technology**
**Guide: Dr. Irfan Siddavatam**

---

## Overview

This guide walks through every step required to demonstrate BreachTrace locally in front of evaluators — from creating AWS credentials to seeing a live forensic report appear on the dashboard.

The demonstration flow is:
```
Make AWS API calls (15 min before demo)
     ↓
Start backend + frontend
     ↓
Trigger simulate endpoint (in front of evaluators)
     ↓
Dashboard shows incident appearing live
     ↓
Click incident → pipeline stepper advances in real time
     ↓
D3 timeline, blast radius, Gemini report, remediation checklist all appear
```

---

## PART 1 — AWS Account & Credentials Setup

### Step 1.1 — Create a Throwaway AWS Account

> Skip this if you already have an AWS account — just use it and create new IAM users inside it.

1. Go to [https://aws.amazon.com](https://aws.amazon.com) → **Create an AWS Account**
2. Use any email (a Gmail alias like `yourname+breachtrace@gmail.com` works)
3. Choose **Free tier**
4. Add a payment card — you will not be charged (all calls used are free tier)

---

### Step 1.2 — Create the Admin IAM User

This user's credentials go into `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` in `.env`. The backend uses these to query CloudTrail for what the leaked key did.

1. **AWS Console** → search **IAM** → **Users** → **Create user**
2. Username: `breachtrace-admin`
3. **Access type:** Programmatic access only (no AWS Console login needed)
4. **Permissions** — attach these managed policies:
   - `CloudTrailReadOnlyAccess`
   - `AmazonS3ReadOnlyAccess`
   - `AmazonEC2ReadOnlyAccess`
   - `IAMReadOnlyAccess`
5. On the final screen, **copy immediately** (you only see the secret once):
   ```
   AWS_ACCESS_KEY_ID=AKIA...
   AWS_SECRET_ACCESS_KEY=...
   ```

---

### Step 1.3 — Create the Experiment IAM User

This is the key that gets `"leaked"` in the demo diff text. It is **real but read-only** — zero damage possible.

1. **IAM** → **Users** → **Create user**
2. Username: `breachtrace-experiment`
3. **Programmatic access only**
4. **Permissions** — attach:
   - `AmazonS3ReadOnlyAccess`
   - `AmazonEC2ReadOnlyAccess`
   - `IAMReadOnlyAccess`
5. Copy credentials:
   ```
   EXPERIMENT_AWS_ACCESS_KEY_ID=AKIA...
   EXPERIMENT_AWS_SECRET_ACCESS_KEY=...
   ```

---

### Step 1.4 — Enable CloudTrail (CRITICAL — Must Be Done Before Any Demo)

Without this, no forensic events will be collected. CloudTrail must be active **before** you make the API calls in Part 7.

1. **AWS Console** → search **CloudTrail** → **Create trail**
2. Trail name: `breachtrace-trail`
3. Storage: Create new S3 bucket (keep auto-generated name)
4. SSE-KMS encryption: **No**
5. CloudWatch Logs: **No**
6. **Log events settings:**
   - Management events: **ON**
   - Read and Write events: **Both**
   - Data events: **OFF** (costs money)
   - Insights events: **OFF**
7. **Create trail**

> CloudTrail takes ~5 minutes to activate after creation. Events appear in `lookup_events` with up to a 15-minute delivery delay. Management events (all the IAM/S3/EC2 API calls) are **free**.

---

## PART 2 — GitHub Token

1. GitHub → profile picture → **Settings** → scroll to bottom → **Developer settings**
2. **Personal access tokens** → **Tokens (classic)** → **Generate new token (classic)**
3. Note: `breachtrace-demo`, Expiration: 7 days
4. Scopes: check only **`repo`**
5. Copy: `GITHUB_TOKEN=ghp_...`

For the webhook secret, generate a random string right now:

```powershell
-join ((65..90) + (97..122) + (48..57) | Get-Random -Count 32 | ForEach-Object {[char]$_})
```

Copy the output → this is your `GITHUB_WEBHOOK_SECRET`.

---

## PART 3 — Gemini API Key

1. Go to [https://aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey)
2. Sign in with Google → **Create API key** → **Create API key in new project**
3. Copy: `GEMINI_API_KEY=AIza...`

Free tier: 1,500 requests/day — far more than needed.

Test it immediately:
```powershell
cd C:\Users\ritwi\Downloads\BreachTrace
.\.venv\Scripts\Activate.ps1
cd backend
python -c "
import config
import google.generativeai as genai
genai.configure(api_key=config.GEMINI_API_KEY)
m = genai.GenerativeModel('gemini-2.5-flash')
print(m.generate_content('Respond with exactly: Gemini is working').text)
"
```

Expected output: `Gemini is working`

---

## PART 4 — PostgreSQL Database

### Option A — PostgreSQL Already Installed

```powershell
# Open psql as the postgres superuser:
psql -U postgres

# Inside psql, create the database:
CREATE DATABASE breachtrace;
\q
```

Your database URL will be:
```
DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@localhost:5432/breachtrace
```

> If your password contains special characters (e.g. `@`, `#`, `!`), URL-encode them:
> - `@` → `%40`
> - `#` → `%23`
> - `!` → `%21`
>
> Example: password `madhu@2020` → `madhu%402020`

Verify the connection works:
```powershell
python -c "
import psycopg2
conn = psycopg2.connect('postgresql://postgres:YOUR_PASSWORD@localhost:5432/breachtrace')
print('DB connection: OK')
conn.close()
"
```

### Option B — Docker (No PostgreSQL Install Required)

```powershell
docker run -d `
  --name breachtrace-pg `
  -e POSTGRES_USER=breachtrace `
  -e POSTGRES_PASSWORD=breachtrace `
  -e POSTGRES_DB=breachtrace `
  -p 5432:5432 `
  postgres:16

# Verify it started:
docker ps
```

Your database URL:
```
DATABASE_URL=postgresql://breachtrace:breachtrace@localhost:5432/breachtrace
```

---

## PART 5 — Fill in the `.env` File

The `.env` file lives at the **project root** (`C:\Users\ritwi\Downloads\BreachTrace\.env`). Every value must be filled in — the backend will print which keys are missing and refuse to start if any are absent.

```env
# AWS Admin (for CloudTrail queries)
AWS_ACCESS_KEY_ID=AKIA...your-breachtrace-admin-key...
AWS_SECRET_ACCESS_KEY=...your-breachtrace-admin-secret...
AWS_REGION=us-east-1

# AWS Experiment User (the key that gets "leaked" in the demo)
EXPERIMENT_AWS_ACCESS_KEY_ID=AKIA...your-experiment-key...
EXPERIMENT_AWS_SECRET_ACCESS_KEY=...your-experiment-secret...

# GitHub
GITHUB_TOKEN=ghp_...your-token...
GITHUB_WEBHOOK_SECRET=breachtrace-demo-secret-2026-group03
GITHUB_TEST_REPO=yourusername/breachtrace-test-repo

# Gemini
GEMINI_API_KEY=AIza...your-key...

# Database
DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@localhost:5432/breachtrace

# App
ENVIRONMENT=development
```

> **Never commit `.env` to Git.** It is already listed in `.gitignore`.

---

## PART 6 — Run Database Migrations

This step creates all four tables in your PostgreSQL database: `incident_records`, `forensic_events`, `collection_status`, and `experiment_runs`. It must be run once before the backend can start.

### Step 6.1 — Activate the virtual environment and navigate

```powershell
cd C:\Users\ritwi\Downloads\BreachTrace
.\.venv\Scripts\Activate.ps1
cd backend
```

Your prompt should now show `(.venv)` at the start.

### Step 6.2 — Run Alembic migrations

```powershell
python -m alembic upgrade head
```

**Expected output (success):**
```
INFO  [alembic.runtime.migration] Context impl PostgreSQLImpl.
INFO  [alembic.runtime.migration] Will assume transactional DDL.
INFO  [alembic.runtime.migration] Running upgrade  -> e70a65e1a493, initial schema
INFO  [alembic.runtime.migration] Running upgrade e70a65e1a493 -> a1b2c3d4e5f6, add principal_arn to forensic_events
```

### Step 6.3 — Verify the tables were created

```powershell
python -c "
from db.models import Base
from db.database import engine
from sqlalchemy import inspect

inspector = inspect(engine)
tables = inspector.get_table_names()
print('Tables in database:')
for t in tables:
    print(f'  ✓ {t}')
"
```

**Expected output:**
```
Tables in database:
  ✓ alembic_version
  ✓ collection_status
  ✓ experiment_runs
  ✓ forensic_events
  ✓ incident_records
```

### Step 6.4 — Troubleshooting Migrations

**Error: `Can't connect to PostgreSQL server`**

Your PostgreSQL isn't running or the DATABASE_URL is wrong.

```powershell
# Check PostgreSQL is running (Windows Service):
Get-Service -Name postgresql*

# If stopped, start it:
Start-Service -Name postgresql*        # adjust service name if different

# Or if using Docker:
docker start breachtrace-pg
```

Also double-check `DATABASE_URL` in `.env`:
- No double `postgresql://postgresql://` prefix — only one `postgresql://`
- Password special characters are URL-encoded (`@` → `%40`)
- Port is `5432`
- Database name `breachtrace` exists

**Error: `database "breachtrace" does not exist`**

```powershell
psql -U postgres -c "CREATE DATABASE breachtrace;"
```

**Error: `role "postgres" does not exist`** (common on fresh installs)

```powershell
# Find your actual postgres username:
psql -U $env:USERNAME breachtrace
# Or try:
psql -U $env:COMPUTERNAME breachtrace
```

Update `DATABASE_URL` with the correct username.

**Error: `relation "alembic_version" already exists` or `Table already exists`**

The database was partially migrated. Reset cleanly:

```powershell
# Drop and recreate the database (WARNING: deletes all data):
psql -U postgres -c "DROP DATABASE IF EXISTS breachtrace;"
psql -U postgres -c "CREATE DATABASE breachtrace;"
python -m alembic upgrade head
```

**Error: `FATAL: password authentication failed`**

Your password in DATABASE_URL is wrong. Test the exact connection string:

```powershell
python -c "
import psycopg2
try:
    conn = psycopg2.connect('YOUR_DATABASE_URL_HERE')
    print('Connected OK')
    conn.close()
except Exception as e:
    print(f'FAILED: {e}')
"
```

**Alternative: Skip Alembic entirely (nuclear option)**

If Alembic refuses to cooperate, create all tables directly from the ORM models:

```powershell
python -c "
from db.models import Base
from db.database import engine
Base.metadata.create_all(bind=engine)
print('All tables created directly from ORM models.')
"
```

This bypasses Alembic migration history entirely. Use this only if Step 6.2 fails after trying the fixes above.

### Step 6.5 — Clear old incidents before the demo

If you ran any test incidents during setup, clear them so the evaluators see a clean dashboard:

```powershell
python -c "
from db.database import SessionLocal
from db.models import IncidentRecord
db = SessionLocal()
count = db.query(IncidentRecord).delete()
db.commit()
db.close()
print(f'Deleted {count} incident(s). Dashboard is clean.')
"
```

---

## PART 7 — Make the CloudTrail Events (20+ Minutes Before Demo)

**This is the most time-sensitive step.** CloudTrail has up to a 15-minute delivery delay. Run these API calls at least 20 minutes before you trigger the simulation.

Open a new PowerShell terminal and set the experiment credentials for this session:

```powershell
$env:AWS_ACCESS_KEY_ID     = "AKIA...your-experiment-key..."
$env:AWS_SECRET_ACCESS_KEY = "...your-experiment-secret..."
$env:AWS_DEFAULT_REGION    = "us-east-1"
```

Now run these commands in order — this creates a realistic attacker scenario with multiple categories:

```powershell
# ── RECONNAISSANCE phase ──────────────────────────────────────────────────────
# These will be classified as category: reconnaissance, severity: LOW (green dots)
aws sts get-caller-identity
aws iam get-user
aws iam list-users
aws iam list-roles
aws iam list-policies --scope Local

# ── DATA ACCESS phase ─────────────────────────────────────────────────────────
# These will be classified as category: data_access, severity: MEDIUM (yellow dots)
aws s3 ls
aws ec2 describe-instances --region us-east-1
aws ec2 describe-security-groups --region us-east-1
aws ec2 describe-vpcs --region us-east-1

# ── BULK S3 ACCESS (triggers exfiltration detection) ─────────────────────────
# The classifier escalates same action called 5+ times from same IP to exfiltration
# This pushes overall severity to HIGH/CRITICAL
aws s3 ls
aws s3 ls
aws s3 ls
aws s3 ls
aws s3 ls
aws s3 ls

# ── IAM PRIVILEGE RECONNAISSANCE (makes GDPR banner appear) ──────────────────
aws iam list-access-keys --user-name breachtrace-experiment
aws iam get-account-summary
aws iam list-attached-user-policies --user-name breachtrace-experiment
aws iam get-user
```

> After running all commands, **set a 20-minute timer** and move on to Step 8. Do not trigger the simulation until the timer expires.

---

## PART 8 — Start the Application

Open **two separate PowerShell windows** side by side.

### Terminal A — Backend

```powershell
cd C:\Users\ritwi\Downloads\BreachTrace
.\.venv\Scripts\Activate.ps1
cd backend
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

**Expected output:**
```
INFO:     Started reloader process [xxxxx]
INFO:     Started server process [xxxxx]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
```

Verify in browser: `http://localhost:8000` → `{"status":"ok","message":"BreachTrace running"}`

API documentation (show evaluators this too): `http://localhost:8000/docs`

### Terminal B — Frontend

```powershell
cd C:\Users\ritwi\Downloads\BreachTrace\client
npm run dev
```

**Expected output:**
```
  VITE v8.0.2  ready in 312ms
  ➜  Local:   http://localhost:5173/
```

Open `http://localhost:5173` in Chrome. You should see:
- Dashboard with "No incidents detected yet"
- Stats cards showing all zeros
- No mock data — this is hitting the real backend

---

## PART 9 — Create the Demo Trigger Script

Create this file once, before demo day, with your real key pre-filled so nothing needs to be typed live:

```powershell
cd C:\Users\ritwi\Downloads\BreachTrace
```

Create `demo_trigger.py`:

```python
import requests
import json
from datetime import datetime, timezone, timedelta

# ── Fill these in once and save the file ──────────────────────────────────────
KEY_ID     = "AKIA...your-experiment-key..."      # <-- your real experiment key
REPO_URL   = "https://github.com/yourusername/student-project"
# ─────────────────────────────────────────────────────────────────────────────

# Set exposure_start to 25 minutes ago so all CloudTrail events fall inside the window
exposure_start = (datetime.now(timezone.utc) - timedelta(minutes=25)).isoformat()

# Construct the fake "leaked" diff — exactly what GitHub would send us
diff_text = (
    f"+  # WARNING: do not commit secrets\n"
    f"+  AWS_ACCESS_KEY_ID={KEY_ID}\n"
    f"+  AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
    f"+  AWS_REGION=us-east-1\n"
)

resp = requests.post("http://localhost:8000/test/simulate", json={
    "repo_url": REPO_URL,
    "diff_text": diff_text,
    "access_key_id": KEY_ID,
    "exposure_start": exposure_start,
})

if resp.status_code != 202:
    print(f"ERROR {resp.status_code}: {resp.text}")
else:
    data = resp.json()
    incident_id = data["incidents"][0]["incident_id"]
    print(json.dumps(data, indent=2))
    print()
    print("=" * 60)
    print(f"Incident created: {incident_id}")
    print(f"Open in browser:  http://localhost:5173/incident/{incident_id}")
    print("=" * 60)
```

To run it on demo day:
```powershell
python demo_trigger.py
```

---

## PART 10 — What Evaluators Will See (Second-by-Second)

After running `demo_trigger.py`, here is exactly what happens:

| Time | Backend | Dashboard |
|------|---------|-----------|
| 0s | Incident created, pipeline background task fires | New row appears in table, status **"collecting"** |
| 1–5s | CloudTrail query fires using admin key | Duration counter ticking live |
| 5–15s | CloudTrail returns events, saved to DB | Status → **"classifying"** |
| 15–18s | Classifier tags each event with category + severity weight | Status → **"scoring"** |
| 18–20s | score_incident() runs, GDPR flag checked, financial impact calculated | Status → **"reporting"**, **severity badge appears** |
| 20–50s | Gemini API called, 4-section report generated | Status still "reporting" |
| 50–60s | Report + remediation checklist parsed and saved | Status → **"complete" ✅** |

**Best time to click the incident row:** At ~15 seconds, while it's classifying. The evaluators see the pipeline stepper advance in real time.

---

## PART 11 — The Incident Detail Page — Section by Section

Click any incident row in the Dashboard to open the Incident Detail page. Walk evaluators through each section:

### 1. Pipeline Stepper (top right of header card)
Six dots: `detecting → collecting → classifying → scoring → reporting → complete`
Each lights up as its stage finishes. The active stage pulses.

### 2. Severity Badge (top left, next to credential hint)
Changes from `—` (pending) to a colour-coded badge:
- 🔴 **CRITICAL** — if privilege escalation or exfiltration detected
- 🟠 **HIGH** — if resource abuse or 5+ same calls from same IP
- 🟡 **MEDIUM** — data access events
- 🟢 **LOW** — reconnaissance only

With the API calls from Part 7, expect **HIGH** or **CRITICAL**.

### 3. GDPR Banner (inside header card, appears if PII accessed)
Red left-border warning: `"GDPR notification may be required — potential PII access detected"`
Appears if any `data_access` event touched a resource name containing `user`, `account`, `email`, or similar PII hints.

### 4. Financial Impact (inside header card)
Formatted string estimating cost — appears if `RunInstances`, large `GetObject` calls, or cluster creation was detected.

### 5. Gemini Incident Summary (full-width section)
Four sections generated by Gemini:
1. **Executive Summary** — one plain-English paragraph
2. **Chronological Narrative** — step-by-step attacker story
3. **Business Impact Assessment**
4. **Remediation Checklist** — numbered, each starting with ☐

### 6. D3 Forensic Timeline (left panel, 2/3 width)
- X-axis = time of each API call
- Y-axis = AWS service (s3.amazonaws.com, iam.amazonaws.com, ec2.amazonaws.com, sts.amazonaws.com)
- Each dot = one CloudTrail event, coloured by severity weight
- **Hover over any dot** → tooltip shows: API action, exact time, source IP, affected resource, impact category

### 7. Blast Radius Summary (right panel, top)
- "AWS CloudTrail — N events"
- Horizontal progress bars showing: Reconnaissance N%, Data Access N%, Exfiltration N%
- Overall severity badge at top right

### 8. Affected Resources (right panel, middle)
- Grouped by resource type: bucket, instance, key
- Each unique resource name shown in monospace
- Event count per resource type

### 9. Remediation Checklist (right panel, bottom)
- Clickable checkboxes — **click them live** as you walk through remediation steps
- Counter shows `0/N` → increments as you check each item

---

## PART 12 — Troubleshooting

### Pipeline completes but 0 events in timeline

**Cause:** CloudTrail hasn't delivered the events yet (< 15 min since Part 7 commands).
**Fix:** Wait. They will appear if you trigger again 20+ minutes after the API calls.

The system still runs — Gemini generates a report that says "No CloudTrail events were captured." The pipeline steps all complete. The forensic report and remediation checklist still display. Only the timeline will be empty.

### Backend fails to start: `MISSING required env var: X`

Open `.env` and confirm every one of the 11 keys has a non-empty value. The most commonly forgotten:
- `GITHUB_TEST_REPO` → even `test/test-repo` works for now
- `ENVIRONMENT` → set to `development`

### Frontend shows "Could not reach the backend"

- Confirm the backend terminal shows `Application startup complete` with no errors
- Confirm backend is on port 8000 (`http://localhost:8000` returns `{"status":"ok"}`)
- Check there is no `client/.env.local` file containing `VITE_USE_MOCK=true`

### Gemini returns the fallback template instead of a real report

```powershell
cd backend
python -c "
import config
import google.generativeai as genai
genai.configure(api_key=config.GEMINI_API_KEY)
m = genai.GenerativeModel('gemini-2.5-flash')
print(m.generate_content('Say OK').text)
"
```

If this fails, your `GEMINI_API_KEY` is wrong. Get a fresh key from [https://aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey).

### Status stuck on "collecting" indefinitely

**Cause:** CloudTrail query is failing (wrong admin credentials or CloudTrail not enabled).
**Check backend logs** — you should see one of:
- `CloudTrail returned 0 events` → no events yet, pipeline continues
- `CloudTrail collection failed` → admin credentials are wrong

Verify admin credentials work:
```powershell
python -c "
import boto3, config
ct = boto3.client('cloudtrail',
    region_name=config.AWS_REGION,
    aws_access_key_id=config.AWS_ACCESS_KEY_ID,
    aws_secret_access_key=config.AWS_SECRET_ACCESS_KEY)
resp = ct.describe_trails()
print('CloudTrail OK:', [t['Name'] for t in resp['trailList']])
"
```

---

## PART 13 — Pre-Demo Checklist (Night Before)

Run through this the evening before:

```
□ Step 1.4: CloudTrail trail active in us-east-1 (check AWS Console — trail shows "Logging: ON")
□ Step 1.2: Admin key (breachtrace-admin) in .env as AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY
□ Step 1.3: Experiment key in .env as EXPERIMENT_AWS_ACCESS_KEY_ID / EXPERIMENT_AWS_SECRET_ACCESS_KEY
□ Step 3:   Gemini test command returns "Gemini is working" (or any response)
□ Step 4:   PostgreSQL running, breachtrace database exists
□ Step 6.2: python -m alembic upgrade head  → exits without error
□ Step 6.3: All 4 tables visible (incident_records, forensic_events, collection_status, experiment_runs)
□ Step 8A:  uvicorn starts, http://localhost:8000 returns {"status":"ok"}
□ Step 8B:  npm run dev starts, http://localhost:5173 shows empty dashboard
□ Step 9:   demo_trigger.py file exists with REAL experiment KEY_ID filled in
□           Full test run: ran demo_trigger.py → incident appeared → pipeline reached "complete"
             → Gemini report visible → timeline has dots → remediation checklist populated
□           Clear test incidents: python -c "from db.database import SessionLocal; from db.models import IncidentRecord; db=SessionLocal(); db.query(IncidentRecord).delete(); db.commit()"
□ Step 7:   Made AWS API calls with experiment key TONIGHT (so CloudTrail has events ready)
```

---

## PART 14 — Demo Day Sequence (30 Minutes Before Evaluators Arrive)

```powershell
# ── 1. Start PostgreSQL (if using Docker) ─────────────────────────────────────
docker start breachtrace-pg

# ── 2. Make AWS API calls NOW ─────────────────────────────────────────────────
#    (Gives 15-20 min for CloudTrail to deliver them)
$env:AWS_ACCESS_KEY_ID     = "AKIA...experiment-key..."
$env:AWS_SECRET_ACCESS_KEY = "...experiment-secret..."
$env:AWS_DEFAULT_REGION    = "us-east-1"

aws sts get-caller-identity
aws iam get-user; aws iam list-users; aws iam list-roles
aws s3 ls; aws s3 ls; aws s3 ls; aws s3 ls; aws s3 ls; aws s3 ls
aws ec2 describe-instances --region us-east-1
aws ec2 describe-security-groups
aws iam list-access-keys --user-name breachtrace-experiment
aws iam get-account-summary

# ── 3. Start backend (Terminal A) ─────────────────────────────────────────────
cd C:\Users\ritwi\Downloads\BreachTrace
.\.venv\Scripts\Activate.ps1
cd backend
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000

# ── 4. Start frontend (Terminal B) ────────────────────────────────────────────
cd C:\Users\ritwi\Downloads\BreachTrace\client
npm run dev

# ── 5. Open browser ───────────────────────────────────────────────────────────
# Navigate to http://localhost:5173
# Dashboard should show: "No incidents detected yet"
# Have Incident Detail URL ready to open after trigger

# ── 6. When evaluators are watching, in Terminal C: ───────────────────────────
cd C:\Users\ritwi\Downloads\BreachTrace
python demo_trigger.py
```

---

## PART 15 — Research Page (Track A + Track B)

Navigate to `/research` (`http://localhost:5173/research`) to show:

- **Track A** — SecretBench detection accuracy panel (precision/recall/F1 targets)
- **Track B** — Experiment run metrics (avg detection time, avg report time, severity distribution)
- Experiment run table populates as you run more incidents

The Track B data only shows if `experiment_runs` rows exist. These are populated by the research harness (`backend/research/harness.py`) — not required for the demo, but if you have runs from SecretBench testing, they will appear here automatically.

---

*BreachTrace — Group 03 · KJSCE IT · 2026*
