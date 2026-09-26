# BreachTrace â€” Complete Local Demo Guide

**Group 03 Â· K.J. Somaiya College of Engineering Â· Information Technology**
**Guide: Dr. Irfan Siddavatam**

---

## Overview

This guide walks through every step required to demonstrate BreachTrace locally in front of evaluators â€” from creating cloud credentials across AWS, GCP, and Azure, to watching live forensic reports appear on the dashboard for all three platforms.

The demonstration flow is:
```
Make cloud API calls on ALL platforms (20 min before demo)
     â†“
Start backend + frontend (no Docker)
     â†“
Trigger simulate endpoint for each platform (in front of evaluators)
     â†“
Dashboard shows incidents appearing live with platform badges (AWS / GCP / Azure)
     â†“
Click incident â†’ pipeline stepper advances in real time
     â†“
D3 timeline, blast radius, Gemini report, remediation checklist all appear
```

**What you need accounts/access for:**
- AWS (free tier â€” IAM users, CloudTrail)
- GCP (free tier â€” Cloud Logging, service accounts)
- Azure (free subscription â€” Activity Logs, app registrations)
- GitHub (any account â€” personal access token)
- Google AI Studio (free â€” Gemini API key)
- PostgreSQL (local install)

---

## PART 1 â€” AWS Account & Credentials Setup

### Step 1.1 â€” Create / Use an AWS Account

> Skip to Step 1.2 if you already have an AWS account â€” just create new IAM users inside it.

1. Go to [https://aws.amazon.com](https://aws.amazon.com) â†’ **Create an AWS Account**
2. Use any email (a Gmail alias like `yourname+breachtrace@gmail.com` works)
3. Choose **Free tier**
4. Add a payment card â€” you will **not** be charged (all calls used are free-tier management events)

---

### Step 1.2 â€” Create the Admin IAM User

These credentials go into `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`. The backend uses them to query CloudTrail for what the leaked key did.

1. **AWS Console** â†’ **IAM** â†’ **Users** â†’ **Create user**
2. Username: `breachtrace-admin`
3. Uncheck "Provide user access to the AWS Management Console"
4. **Next** â†’ **Attach policies directly** â†’ attach all four:
   - `CloudTrailReadOnlyAccess`
   - `AmazonS3ReadOnlyAccess`
   - `AmazonEC2ReadOnlyAccess`
   - `IAMReadOnlyAccess`
5. **Create user** â†’ click the new user â†’ **Security credentials** tab â†’ **Create access key**
6. Use case: **Command Line Interface (CLI)** â†’ confirm â†’ **Next** â†’ **Create access key**
7. **Copy immediately** (the secret is shown only once):
   ```
   AWS_ACCESS_KEY_ID=AKIA...
   AWS_SECRET_ACCESS_KEY=...
   ```

---

### Step 1.3 â€” Create the Experiment IAM User

This is the key that gets "leaked" in the demo diff text. Read-only â€” zero damage possible.

1. **IAM** â†’ **Users** â†’ **Create user**
2. Username: `breachtrace-experiment`
3. **Attach policies directly**:
   - `AmazonS3ReadOnlyAccess`
   - `AmazonEC2ReadOnlyAccess`
   - `IAMReadOnlyAccess`
4. Create access key (same steps as above). Copy:
   ```
   EXPERIMENT_AWS_ACCESS_KEY_ID=AKIA...
   EXPERIMENT_AWS_SECRET_ACCESS_KEY=...
   ```

---

### Step 1.4 â€” Enable CloudTrail

Without this, no AWS forensic events are collected. Must be active **before** you make the API calls in Part 9.

1. **AWS Console** â†’ **CloudTrail** â†’ **Create trail**
2. Trail name: `breachtrace-trail`
3. Storage: **Create new S3 bucket** (keep auto-generated name)
4. SSE-KMS encryption: **No** | CloudWatch Logs: **No**
5. Management events: **ON** â€” Read + Write: **Both** â€” Data events: **OFF** â€” Insights: **OFF**
6. **Create trail**

> Events appear in `lookup_events` with up to a 15-minute delivery delay. Management events are **free**.

---

## PART 2 â€” GCP Setup

You need two service accounts: an **admin** account (queries Audit Logs) and an **experiment** account (the one that gets "leaked").

### Step 2.1 â€” Create a GCP Project

1. Go to [https://console.cloud.google.com](https://console.cloud.google.com)
2. Click the project dropdown (top-left) â†’ **New Project**
3. Name: `breachtrace` â†’ **Create**
4. Note your **Project ID** (e.g. `breachtrace-420819`) â€” this is `GCP_PROJECT_ID`

---

### Step 2.2 â€” Enable Required APIs

In your project, go to **APIs & Services** â†’ **Enable APIs and Services** â†’ search for and enable:

1. **Cloud Logging API** â€” mandatory for audit log queries
2. **Cloud Resource Manager API** â€” needed for project metadata
3. **Cloud Storage API** â€” so the experiment SA can make storable API calls
4. **Identity and Access Management (IAM) API** â€” for service account operations

Or enable them all at once in Cloud Shell:
```bash
gcloud services enable logging.googleapis.com cloudresourcemanager.googleapis.com storage.googleapis.com iam.googleapis.com
```

---

### Step 2.3 â€” Enable Data Access Audit Logs (CRITICAL)

By default GCP only logs **Admin Activity** (free). To log what the experiment SA reads/writes you must enable **Data Access** logs.

1. **IAM & Admin** â†’ **Audit Logs**
2. Find **Cloud Storage** in the list â†’ check **DATA_READ** and **DATA_WRITE**
3. Also enable **DATA_READ** + **DATA_WRITE** for **Identity and Access Management (IAM)**
4. Click **Save**

> Data Access audit logs are **free** for admin (IAM/resource manager) operations. Storage data access logs may count toward your free tier quota (~50 GiB/month free in Cloud Logging).

---

### Step 2.4 â€” Create the Admin Service Account

This SA's JSON key goes into `GCP_SERVICE_ACCOUNT_JSON`. It is used only for reading logs â€” never for making calls.

1. **IAM & Admin** â†’ **Service Accounts** â†’ **Create Service Account**
2. Name: `breachtrace-admin` â†’ **Create and Continue**
3. Roles â€” add both:
   - `Logging Viewer` (roles/logging.viewer)
   - `Viewer` (roles/viewer)
4. **Done**
5. Click on `breachtrace-admin@...` â†’ **Keys** tab â†’ **Add Key** â†’ **Create new key** â†’ **JSON** â†’ **Create**
6. The browser downloads `breachtrace-admin-xxxx.json` â€” **keep this file safe**

---

### Step 2.5 â€” Create the Experiment Service Account

This SA's email is what gets "leaked" in the demo. It needs just enough permissions to actually generate audit log entries.

1. **Service Accounts** â†’ **Create Service Account**
2. Name: `breachtrace-experiment` â†’ **Create and Continue**
3. Role: `Storage Object Viewer` (roles/storage.objectViewer)
4. **Done**
5. Click on `breachtrace-experiment@...` â†’ **Keys** tab â†’ **Add Key** â†’ **Create new key** â†’ **JSON** â†’ **Create**
6. Save `breachtrace-experiment-xxxx.json`
7. Note these values from the JSON file:
   - `client_email` â†’ `GCP_EXPERIMENT_CLIENT_EMAIL`
   - `private_key_id` â†’ `GCP_EXPERIMENT_PRIVATE_KEY_ID`
   - `private_key` â†’ `GCP_EXPERIMENT_PRIVATE_KEY`

---

### Step 2.6 â€” Convert the Admin JSON Key for .env

The `.env` file needs the admin SA key as a single-line JSON string. Run this in your BreachTrace `.venv`:

```powershell
cd C:\Users\ritwi\Downloads\BreachTrace
.\.venv\Scripts\Activate.ps1
python -c "
import json
with open(r'C:\Users\ritwi\Downloads\breachtrace-admin-xxxx.json') as f:
    data = json.load(f)
print('GCP_SERVICE_ACCOUNT_JSON=' + json.dumps(data))
"
```

Copy the entire output line (starting with `GCP_SERVICE_ACCOUNT_JSON=`) and paste it into your `.env` file.

> **Why this works:** `json.dumps()` converts actual newlines in the `private_key` value to `\n` escape sequences, producing a valid single-line JSON string that `json.loads()` in the backend can parse correctly.

---

### Step 2.7 â€” Verify GCP Admin Access

```powershell
cd C:\Users\ritwi\Downloads\BreachTrace
.\.venv\Scripts\Activate.ps1
cd backend
python -c "
import config, json
from google.cloud import logging as gcp_logging
from google.oauth2 import service_account

creds_info = json.loads(config.GCP_SERVICE_ACCOUNT_JSON)
credentials = service_account.Credentials.from_service_account_info(
    creds_info, scopes=['https://www.googleapis.com/auth/logging.read'])
client = gcp_logging.Client(project=config.GCP_PROJECT_ID, credentials=credentials)

entries = list(client.list_entries(
    filter_='logName:\"cloudaudit.googleapis.com\"',
    max_results=3
))
print(f'GCP Audit Log connection: OK â€” {len(entries)} recent entries found')
"
```

Expected: `GCP Audit Log connection: OK â€” N recent entries found` (N may be 0 if no activity yet)

---

## PART 3 â€” Azure Setup

You need two app registrations: an **admin** app (queries Activity Logs) and an **experiment** app (the one that gets "leaked").

### Step 3.1 â€” Azure Subscription

You need an active Azure subscription. Options:
- Free 12-month trial: [https://azure.microsoft.com/free](https://azure.microsoft.com/free) ($200 credit)
- Students: [https://azure.microsoft.com/free/students](https://azure.microsoft.com/free/students) (no card required)
- Existing subscription: any works

Note your **Subscription ID** â€” visible in **Subscriptions** in the portal.

---

### Step 3.2 â€” Register the Admin App

This app's credentials query Azure Monitor Activity Logs.

1. **Azure Portal** â†’ **Azure Active Directory** â†’ **App registrations** â†’ **New registration**
2. Name: `breachtrace-admin`
3. Supported account types: **Accounts in this organizational directory only**
4. Redirect URI: leave blank
5. **Register**
6. On the app overview page, note:
   - **Application (client) ID** â†’ `AZURE_CLIENT_ID`
   - **Directory (tenant) ID** â†’ `AZURE_TENANT_ID`
7. **Certificates & secrets** â†’ **Client secrets** â†’ **New client secret**
   - Description: `breachtrace-admin-secret`
   - Expires: 6 months (or longest available)
   - **Add** â†’ **copy the Value immediately** (shown only once) â†’ `AZURE_CLIENT_SECRET`

---

### Step 3.3 â€” Grant the Admin App Access to Activity Logs

1. **Portal** â†’ **Subscriptions** â†’ select your subscription â†’ **Access control (IAM)** â†’ **Add** â†’ **Add role assignment**
2. Role: **Reader** â†’ **Next**
3. Assign access to: **User, group, or service principal** â†’ **Select members** â†’ search `breachtrace-admin` â†’ select it
4. **Review + assign**
5. Repeat the same process to also assign **Monitoring Reader** role:
   - Role: **Monitoring Reader** â†’ **Next** â†’ same app â†’ **Review + assign**

---

### Step 3.4 â€” Register the Experiment App

This app is the "leaked" service principal. Needs minimal permissions so it generates Activity Log entries.

1. **App registrations** â†’ **New registration**
2. Name: `breachtrace-experiment`
3. **Register**
4. Note:
   - **Application (client) ID** â†’ `AZURE_EXPERIMENT_CLIENT_ID`
5. **Certificates & secrets** â†’ **New client secret**
   - Description: `experiment-secret`
   - **Add** â†’ copy **Value** â†’ `AZURE_EXPERIMENT_CLIENT_SECRET`
6. Assign a role on your subscription (so it can make ARM calls):
   - **Subscriptions** â†’ subscription â†’ **Access control (IAM)** â†’ **Add role assignment**
   - Role: **Reader** â†’ assign to `breachtrace-experiment` â†’ **Review + assign**

---

### Step 3.5 â€” Find the Experiment App's Service Principal Object ID

> **Important:** Azure Activity Logs record the **Service Principal Object ID** as the `caller` field â€” this is **different** from the Application Client ID. You need the Object ID for the pipeline to match Activity Log events.

1. **Azure Active Directory** â†’ **Enterprise applications**
2. Search for `breachtrace-experiment`
3. Click on it â†’ note the **Object ID** on the overview page

This **Object ID** is what you use in the demo diff text and also set as `AZURE_EXPERIMENT_CLIENT_ID` in `.env`. It is what Azure records as `caller` in Activity Logs.

> If you want revocation checking to also work, set `AZURE_EXPERIMENT_CLIENT_ID` to the **Application (client) ID** and use the Object ID in the diff text only. For simplicity in this demo, use the Object ID for both.

---

### Step 3.6 â€” Verify Azure Admin Access

```powershell
cd C:\Users\ritwi\Downloads\BreachTrace
.\.venv\Scripts\Activate.ps1
cd backend
python -c "
import config
from azure.identity import ClientSecretCredential
from azure.mgmt.monitor import MonitorManagementClient
from datetime import datetime, timezone, timedelta

credential = ClientSecretCredential(
    tenant_id=config.AZURE_TENANT_ID,
    client_id=config.AZURE_CLIENT_ID,
    client_secret=config.AZURE_CLIENT_SECRET,
)
client = MonitorManagementClient(credential, config.AZURE_SUBSCRIPTION_ID)

end = datetime.now(timezone.utc)
start = end - timedelta(hours=1)
filter_str = f\"eventTimestamp ge '{start.isoformat()}' and eventTimestamp le '{end.isoformat()}'\"
events = list(client.activity_logs.list(filter=filter_str, select='eventTimestamp,caller'))
print(f'Azure Activity Log connection: OK â€” {len(events)} events in last hour')
"
```

Expected: `Azure Activity Log connection: OK â€” N events in last hour`

---

## PART 4 â€” GitHub Token

1. GitHub â†’ profile picture â†’ **Settings** â†’ **Developer settings** â†’ **Personal access tokens** â†’ **Tokens (classic)** â†’ **Generate new token (classic)**
2. Note: `breachtrace-demo` | Expiration: 7 days | Scopes: **`repo`** only
3. Copy: `GITHUB_TOKEN=ghp_...`

Generate a webhook secret:
```powershell
-join ((65..90) + (97..122) + (48..57) | Get-Random -Count 32 | ForEach-Object {[char]$_})
```
Copy the output â†’ `GITHUB_WEBHOOK_SECRET`

---

## PART 5 â€” Gemini API Key

1. Go to [https://aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey)
2. Sign in with Google â†’ **Create API key** â†’ **Create API key in new project**
3. Copy: `GEMINI_API_KEY=AIza...`

Verify it works:
```powershell
cd C:\Users\ritwi\Downloads\BreachTrace
.\.venv\Scripts\Activate.ps1
cd backend
python -c "
import config, google.generativeai as genai
genai.configure(api_key=config.GEMINI_API_KEY)
m = genai.GenerativeModel('gemini-2.5-flash')
print(m.generate_content('Respond with exactly: Gemini is working').text)
"
```
Expected: `Gemini is working`

---

## PART 6 â€” PostgreSQL Database (Local Install Only)

### Step 6.1 â€” Install PostgreSQL if not already installed

Download from [https://www.postgresql.org/download/windows](https://www.postgresql.org/download/windows) â†’ run the installer â†’ remember the **postgres** user password you set.

### Step 6.2 â€” Create the database

```powershell
# Open psql as the postgres superuser
psql -U postgres

# Inside psql:
CREATE DATABASE breachtrace;
\q
```

Your DATABASE_URL:
```
DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@localhost:5432/breachtrace
```

> If your password contains special characters: `@` â†’ `%40`, `#` â†’ `%23`, `!` â†’ `%21`
> Example: password `pass@123` â†’ `DATABASE_URL=postgresql://postgres:pass%40123@localhost:5432/breachtrace`

Verify:
```powershell
.\.venv\Scripts\Activate.ps1
python -c "
import psycopg2
conn = psycopg2.connect('postgresql://postgres:YOUR_PASSWORD@localhost:5432/breachtrace')
print('DB connection: OK')
conn.close()
"
```

### Step 6.3 â€” Start PostgreSQL service

```powershell
# Check if running:
Get-Service -Name postgresql*

# If stopped:
Start-Service -Name postgresql*    # adjust the name to match what Get-Service shows
```

---

## PART 7 â€” Fill in the `.env` File

The `.env` lives at `C:\Users\ritwi\Downloads\BreachTrace\.env`. Create it now with all values filled in:

```env
# â”€â”€ AWS Admin (queries CloudTrail) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
AWS_ACCESS_KEY_ID=AKIA...your-admin-key...
AWS_SECRET_ACCESS_KEY=...your-admin-secret...
AWS_REGION=us-east-1

# â”€â”€ AWS Experiment (the "leaked" key) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
EXPERIMENT_AWS_ACCESS_KEY_ID=AKIA...your-experiment-key...
EXPERIMENT_AWS_SECRET_ACCESS_KEY=...your-experiment-secret...

# â”€â”€ GCP Admin (queries Cloud Audit Logs) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Paste the single-line JSON string from Step 2.6
GCP_PROJECT_ID=your-project-id
GCP_SERVICE_ACCOUNT_JSON={"type":"service_account","project_id":"your-project-id",...}

# â”€â”€ GCP Experiment (the "leaked" SA email) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
GCP_EXPERIMENT_CLIENT_EMAIL=breachtrace-experiment@your-project-id.iam.gserviceaccount.com
GCP_EXPERIMENT_PRIVATE_KEY_ID=<40-char hex from experiment SA JSON key file>
GCP_EXPERIMENT_PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n

# â”€â”€ Azure Admin (queries Activity Logs) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
AZURE_TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AZURE_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AZURE_CLIENT_SECRET=<breachtrace-admin app client secret>
AZURE_SUBSCRIPTION_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# â”€â”€ Azure Experiment (the "leaked" service principal) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Use the Service Principal OBJECT ID from Enterprise Applications (Step 3.5)
AZURE_EXPERIMENT_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AZURE_EXPERIMENT_CLIENT_SECRET=<breachtrace-experiment app client secret>

# â”€â”€ GitHub â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
GITHUB_TOKEN=ghp_...
GITHUB_WEBHOOK_SECRET=<32-char random string from Part 4>
GITHUB_TEST_REPO=yourusername/breachtrace-test-repo

# â”€â”€ Gemini â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
GEMINI_API_KEY=AIza...

# â”€â”€ Database â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@localhost:5432/breachtrace

# â”€â”€ App â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
ENVIRONMENT=development
```

> **Never commit `.env` to Git.** It is in `.gitignore` already.

### How to fill in GCP_EXPERIMENT_PRIVATE_KEY

Open your `breachtrace-experiment-xxxx.json` file in a text editor. Find the `private_key` field:
```json
"private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIB...\n-----END RSA PRIVATE KEY-----\n"
```
Copy just the **value** (the string between the outer `"` quotes) and paste it as:
```env
GCP_EXPERIMENT_PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----\nMIIEowIB...\n-----END RSA PRIVATE KEY-----\n
```
The `\n` sequences must remain as literal backslash-n (not real newlines) in the `.env` file.

---

## PART 8 â€” Run Database Migrations

Run once before the first start. Creates tables: `incident_records`, `forensic_events`, `collection_status`, `experiment_runs`.

```powershell
cd C:\Users\ritwi\Downloads\BreachTrace
.\.venv\Scripts\Activate.ps1
cd backend
python -m alembic upgrade head
```

**Expected output:**
```
INFO  [alembic.runtime.migration] Running upgrade  -> e70a65e1a493, initial schema
INFO  [alembic.runtime.migration] Running upgrade e70a65e1a493 -> a1b2c3d4e5f6, add principal_arn to forensic_events
```

Verify tables:
```powershell
python -c "
from db.database import engine
from sqlalchemy import inspect
for t in inspect(engine).get_table_names():
    print('  âœ“', t)
"
```

**If Alembic fails entirely**, create tables directly:
```powershell
python -c "
from db.models import Base
from db.database import engine
Base.metadata.create_all(bind=engine)
print('All tables created.')
"
```

Clear any test incidents before the demo:
```powershell
python -c "
from db.database import SessionLocal
from db.models import IncidentRecord
db = SessionLocal()
n = db.query(IncidentRecord).delete()
db.commit(); db.close()
print(f'Deleted {n} incident(s). Dashboard is clean.')
"
```

---

## PART 9 â€” Generate Real Cloud Activity (20+ Minutes Before Demo)

**Time-critical for AWS** (CloudTrail has ~15 min delivery delay). GCP and Azure are near-real-time.

### 9A â€” AWS (run at least 20 min before the demo)

Open a terminal and set the experiment credentials for this session only:

```powershell
$env:AWS_ACCESS_KEY_ID     = "AKIA...your-experiment-key..."
$env:AWS_SECRET_ACCESS_KEY = "...your-experiment-secret..."
$env:AWS_DEFAULT_REGION    = "ap-south-1"
```

Run these commands to create a realistic multi-stage attacker scenario:

```powershell
# RECONNAISSANCE â€” classified as LOW severity
aws sts get-caller-identity
aws iam get-user
aws iam list-users
aws iam list-roles
aws iam list-policies --scope Local

# DATA ACCESS â€” classified as MEDIUM severity
aws s3 ls
aws ec2 describe-instances --region us-east-1
aws ec2 describe-security-groups
aws ec2 describe-vpcs

# BULK S3 ACCESS â€” 6 identical calls trigger EXFILTRATION classification â†’ severity goes HIGH/CRITICAL
aws s3 ls; aws s3 ls; aws s3 ls; aws s3 ls; aws s3 ls; aws s3 ls

# IAM RECON â€” triggers GDPR banner in the UI
aws iam list-access-keys --user-name breachtrace-experiment
aws iam get-account-summary
aws iam list-attached-user-policies --user-name breachtrace-experiment
```

**Set a 20-minute timer.** Do not trigger the simulation until it expires.

---

### 9B â€” GCP (run 5 minutes before the demo â€” near-real-time)

Activate the experiment service account and make a few Cloud Storage API calls so they appear in Audit Logs.

**Option A: Using gcloud CLI** (install from [https://cloud.google.com/sdk/docs/install](https://cloud.google.com/sdk/docs/install) if not installed)

```powershell
# Activate the experiment SA
gcloud auth activate-service-account --key-file="C:\Users\ritwi\Downloads\breachtrace-experiment-xxxx.json"
gcloud config set project your-project-id

# Make API calls that generate Cloud Audit Log entries
gcloud storage buckets list   # lists all GCS buckets â€” generates DATA_READ audit log
gcloud projects describe your-project-id   # project metadata â€” generates DATA_READ
gcloud iam service-accounts list   # IAM list â€” generates DATA_READ
gcloud storage buckets list   # repeat 3 times for exfiltration signal
gcloud storage buckets list
gcloud storage buckets list
```

**Option B: Python script** (no gcloud CLI needed â€” uses the .venv):

```powershell
cd C:\Users\ritwi\Downloads\BreachTrace
.\.venv\Scripts\Activate.ps1
python -c "
from google.oauth2 import service_account
from google.cloud import storage
import json

# Load experiment key
with open(r'C:\Users\ritwi\Downloads\breachtrace-experiment-xxxx.json') as f:
    info = json.load(f)

creds = service_account.Credentials.from_service_account_info(info)
client = storage.Client(project=info['project_id'], credentials=creds)

# List buckets several times â€” generates DATA_READ audit log entries
for i in range(6):
    buckets = list(client.list_buckets())
    print(f'Run {i+1}: {len(buckets)} buckets visible')

print('GCP activity generated â€” audit logs will appear in ~30 seconds')
"
```

> GCP Cloud Audit Logs appear within **30â€“60 seconds**, not 15 minutes like AWS CloudTrail. You can run these calls just before triggering the simulation.

---

### 9C â€” Azure (run 5 minutes before the demo â€” near-real-time)

Make some ARM API calls using the experiment app so they appear in Activity Logs.

**Using Azure CLI** (install from [https://aka.ms/installazurecliwindows](https://aka.ms/installazurecliwindows) if not installed):

```powershell
# Login as the experiment service principal
az login --service-principal `
  --username "AZURE_EXPERIMENT_APPLICATION_CLIENT_ID" `
  --password "AZURE_EXPERIMENT_CLIENT_SECRET" `
  --tenant "AZURE_TENANT_ID"

# Make ARM calls that appear in Activity Logs
az resource list --subscription "AZURE_SUBSCRIPTION_ID"
az storage account list --subscription "AZURE_SUBSCRIPTION_ID"
az group list
az network vnet list --subscription "AZURE_SUBSCRIPTION_ID"
az resource list  # repeat for exfiltration signal
az resource list
az resource list
az resource list

# Log out
az logout
```

**Using Python** (no Azure CLI needed):

```powershell
cd C:\Users\ritwi\Downloads\BreachTrace
.\.venv\Scripts\Activate.ps1
python -c "
import config
from azure.identity import ClientSecretCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient

# Use the experiment app credentials directly
cred = ClientSecretCredential(
    tenant_id=config.AZURE_TENANT_ID,
    client_id='PASTE_EXPERIMENT_APPLICATION_CLIENT_ID_HERE',
    client_secret=config.AZURE_EXPERIMENT_CLIENT_SECRET,
)

# List resources â€” generates Activity Log entries
rm_client = ResourceManagementClient(cred, config.AZURE_SUBSCRIPTION_ID)
for i in range(4):
    groups = list(rm_client.resource_groups.list())
    print(f'Run {i+1}: {len(groups)} resource groups')

print('Azure activity generated â€” Activity Logs appear within 1-2 minutes')
"
```

> Azure Activity Logs appear within **1â€“2 minutes**. Run these calls just before triggering the simulation.

---

## PART 10 â€” Expose the Backend via ngrok (GitHub Webhook Path Only)

> **Skip this part entirely if you are only using `demo_trigger.py`** (Path A below).
> ngrok is required only so that GitHub.com can POST webhook events to your local backend.
> The React frontend does **not** need ngrok — it runs on the same machine and calls `localhost:8000` directly.

---

### Why ngrok is needed

GitHub must deliver webhook POST requests to a public HTTPS URL. Your local `localhost:8000`
is unreachable from the internet. ngrok creates a secure TLS tunnel from a public URL to it.

---

### Step 10.1 â€” Install ngrok

1. Download from **https://ngrok.com/download** — Windows — extract `ngrok.exe` to any folder on your PATH.
2. Sign up at **https://dashboard.ngrok.com** and copy your Authtoken.
3. Register the authtoken (run once):

```powershell
ngrok config add-authtoken YOUR_TOKEN_HERE
```

---

### Step 10.2 â€” Start the tunnel (Terminal C — after starting the backend in Part 11)

```powershell
ngrok http 8000
```

Expected output:

```
Forwarding    https://abc123def456.ngrok-free.app -> http://localhost:8000
```

Copy the **Forwarding URL** (e.g. `https://abc123def456.ngrok-free.app`).

> ngrok free-tier URLs change on every restart. If you restart ngrok, repeat Step 10.3.

---

### Step 10.3 â€” Register the webhook via the Connect page

1. Open **http://localhost:5173/connect**
2. The Webhook URL field auto-populates with `http://localhost:8000/webhook/github`
3. Edit it to: `https://abc123def456.ngrok-free.app/webhook/github`
4. Enter your GitHub repo URL and click **Register Webhook**
5. Verify: GitHub → repo **Settings** → **Webhooks** → green tick ✓

---

## PART 11 â€” Start the Application

Open **two** separate PowerShell windows (add a third for ngrok if using the GitHub webhook path).

### Terminal A â€” Backend

```powershell
cd C:\Users\ritwi\Downloads\BreachTrace
.\.venv\Scripts\Activate.ps1
cd backend
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Expected: `Uvicorn running on http://0.0.0.0:8000`

### Terminal B â€” Frontend

```powershell
cd C:\Users\ritwi\Downloads\BreachTrace\client
npm run dev
```

Open **http://localhost:5173** — the dashboard should appear empty (live backend, no mock data).

> If the dashboard shows sample/mock incidents: confirm there is **no** file at `client/.env.local`.

### Terminal C â€” ngrok (only for GitHub webhook path)

```powershell
ngrok http 8000
```

Then follow Step 10.3 to register the public URL with GitHub.

---

## PART 12 â€” Trigger Demo Incidents

### Path A â€” Simulate (fastest, no ngrok needed) — USE THIS FOR DEMO

```powershell
cd C:\Users\ritwi\Downloads\BreachTrace
python demo_trigger.py          # AWS + GCP + Azure at once
python demo_trigger.py aws      # single platform
python demo_trigger.py gcp
python demo_trigger.py azure
```

> GCP and Azure values in `demo_trigger.py` are pre-filled from `.env`. No edits needed.
> AWS and Azure incidents will show full forensic timelines.
> GCP incidents will work once you complete PART 2 (GCP service account setup).

---

### Path B â€” Real GitHub Push (requires ngrok + Connect page from Part 10)

```powershell
# In a fresh directory outside the project:
git clone https://github.com/YOUR_USERNAME/YOUR_REPO.git test-repo
cd test-repo

# Add a file that contains the experiment AWS key
"AWS_ACCESS_KEY_ID=AKIAUDOTYKQPCWNJ4GXV" | Out-File leaked-creds.txt
git add leaked-creds.txt
git commit -m "chore: config update"
git push
```

GitHub sends a webhook POST → backend detects the key → incident appears on the dashboard in **2–3 seconds**.

---

## PART 13 â€” What Evaluators Will See

After triggering, here is the second-by-second progression for each platform:

| Time | Backend | Dashboard |
|------|---------|-----------|
| 0s | Incident created, background pipeline fires | Row appears with platform badge **(AWS / GCP / Azure)**, status **collecting** |
| 1â€“5s | Cloud query fires (AWS: CloudTrail, GCP: Cloud Logging, Azure: Activity Logs) | Duration counter ticking |
| 5â€“20s | Events returned and saved to DB | Status â†’ **classifying** |
| 20â€“22s | Classifier tags each event; scorer runs | Status â†’ **scoring** â†’ **reporting**, severity badge appears |
| 25â€“60s | Gemini generates 4-section report | Status still **reporting** |
| 60s | Report + checklist saved | Status â†’ **complete âœ…** |

**Best time to click the incident row:** at ~10â€“15 seconds while it is classifying â€” evaluators see the pipeline stepper advance in real time.

**Dashboard platform filter tabs:** at the top of the dashboard, click **GCP** or **Azure** to filter the incident list by platform.

---

## PART 14 â€” Incident Detail Page â€” What to Show

### For all platforms

1. **Pipeline Stepper** â€” six dots light up sequentially (detecting â†’ collecting â†’ classifying â†’ scoring â†’ reporting â†’ complete)
2. **Platform Badge** â€” coloured chip next to credential hint: orange for AWS, blue for GCP, teal for Azure
3. **Severity Badge** â€” colour-coded (CRITICAL / HIGH / MEDIUM / LOW)
4. **GDPR Banner** â€” appears if PII-related resources were accessed
5. **Gemini Report** â€” executive summary, chronological narrative, business impact, remediation checklist

### Platform-specific differences

| Section | AWS | GCP | Azure |
|---------|-----|-----|-------|
| Timeline shapes | Circles | Squares | Diamonds |
| Timeline Y-axis | AWS service names | GCP service names | Azure resource providers |
| Blast Radius card | AWS CloudTrail | GCP Cloud Audit Logs | Azure Activity Logs |
| Identity tile | Access Key ID | Service Account Email | Service Principal Object ID |
| Location tile | AWS Region | GCP Resource Type | Azure Resource Group |

### Live interactions to demo

- **Hover over timeline dots** â†’ tooltip shows: API action, exact time, source IP, affected resource, category
- **Click checkboxes** in the Remediation Checklist â†’ counter increments (0/N â†’ 1/N â†’ ...)
- **Platform filter tabs** on Dashboard â†’ show only GCP incidents, then only Azure

---

## PART 15 â€” Troubleshooting

### AWS: Pipeline completes but 0 events in timeline

CloudTrail hasn't delivered the events yet (<15 min since Part 9A).

**Fix:** Wait, then hit the **Refresh** button on the incident detail page (re-runs the collection). Events will appear if you wait 20+ minutes after the API calls.

The pipeline still completes â€” Gemini generates "no CloudTrail events were captured." The report, checklist, and all UI sections still display. Only the timeline dots are missing.

### GCP: Status goes to "error"

**Check 1:** Verify `GCP_SERVICE_ACCOUNT_JSON` is valid:
```powershell
cd backend
python -c "
import config, json
data = json.loads(config.GCP_SERVICE_ACCOUNT_JSON)
print('JSON valid â€” client_email:', data.get('client_email'))
"
```

**Check 2:** Verify Cloud Logging API is enabled:
```powershell
python -c "
import config, json
from google.oauth2 import service_account
from google.cloud import logging as gcp_logging
creds = service_account.Credentials.from_service_account_info(
    json.loads(config.GCP_SERVICE_ACCOUNT_JSON),
    scopes=['https://www.googleapis.com/auth/logging.read'])
client = gcp_logging.Client(project=config.GCP_PROJECT_ID, credentials=creds)
print('GCP connected OK')
"
```

If this throws `403 PERMISSION_DENIED`: the admin SA is missing `roles/logging.viewer`. Go back to Step 2.4 and add the role.

If this throws `API not enabled`: go to GCP Console â†’ APIs & Services â†’ enable Cloud Logging API.

### Azure: Status goes to "error"

**Check admin credentials:**
```powershell
cd backend
python -c "
import config
from azure.identity import ClientSecretCredential
cred = ClientSecretCredential(
    tenant_id=config.AZURE_TENANT_ID,
    client_id=config.AZURE_CLIENT_ID,
    client_secret=config.AZURE_CLIENT_SECRET)
token = cred.get_token('https://management.azure.com/.default')
print('Azure admin token OK â€” expires:', token.expires_on)
"
```

If this throws `ClientAuthenticationError`: `AZURE_CLIENT_SECRET` is wrong or expired. Go back to Step 3.2 and create a new secret.

If this throws `403`: the admin app is missing Reader/Monitoring Reader on the subscription. Go back to Step 3.3.

### Azure: 0 events collected but no error

This can happen because Azure Activity Logs record the service principal **Object ID** as `caller`, not the Application Client ID. If the `AZURE_EXPERIMENT_CLIENT_ID` in `.env` is the Application Client ID (not Object ID), the filter won't match.

**Fix:** Get the correct Object ID:
- Azure AD â†’ Enterprise Applications â†’ search `breachtrace-experiment` â†’ copy **Object ID**
- Update `AZURE_EXPERIMENT_CLIENT_ID` in `.env` with this Object ID
- Update `AZURE_CLIENT_ID` field in `demo_trigger.py` with this Object ID
- Restart the backend

### Backend fails to start: `MISSING required env var: X`

Open `.env` and confirm every key in this list has a non-empty value:
`AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION, EXPERIMENT_AWS_ACCESS_KEY_ID, EXPERIMENT_AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN, GITHUB_WEBHOOK_SECRET, GITHUB_TEST_REPO, GEMINI_API_KEY, DATABASE_URL, ENVIRONMENT`

Note: GCP and Azure vars are **optional** at startup â€” missing them will cause incidents for those platforms to fail with "error" status (gracefully), not prevent the backend from starting.

### Frontend shows "Could not reach the backend"

- Confirm backend terminal shows `Application startup complete` with no errors
- Confirm `http://localhost:8000` returns `{"status":"ok"}`
- Check there is no `client/.env.local` file with `VITE_USE_MOCK=true`

### Gemini returns the fallback template instead of a real report

```powershell
cd backend
python -c "
import config, google.generativeai as genai
genai.configure(api_key=config.GEMINI_API_KEY)
print(genai.GenerativeModel('gemini-2.5-flash').generate_content('Say OK').text)
"
```

If this fails: get a new key from [https://aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey).

### GCP: Events detected but wrong SA email in diff

The scanner looks for `*.iam.gserviceaccount.com` emails in the diff. The `GCP_CLIENT_EMAIL` in `demo_trigger.py` must exactly match the experiment SA's `client_email` in `.env`.

```powershell
python -c "import config; print('Watching for email:', config.GCP_EXPERIMENT_CLIENT_EMAIL)"
```

Make sure the same email is in the `GCP_DIFF` string in `demo_trigger.py`.

---

## PART 16 â€” Pre-Demo Checklist (Night Before)

### AWS
```
â–¡ CloudTrail trail active in us-east-1 (AWS Console â†’ CloudTrail â†’ trail shows "Logging: ON")
â–¡ Admin key in .env: AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY
â–¡ Experiment key in .env: EXPERIMENT_AWS_ACCESS_KEY_ID / EXPERIMENT_AWS_SECRET_ACCESS_KEY
â–¡ Made AWS API calls tonight with experiment key â†’ wait 20 min â†’ ran demo_trigger.py aws â†’ incident appeared
```

### GCP
```
â–¡ Cloud Logging API enabled in GCP project
â–¡ Data Access audit logs enabled for Cloud Storage (Step 2.3)
â–¡ Admin SA has Logging Viewer + Viewer roles
â–¡ GCP_SERVICE_ACCOUNT_JSON in .env parses correctly (Step 2.7 verification command passes)
â–¡ GCP_EXPERIMENT_CLIENT_EMAIL matches exactly what is in demo_trigger.py
â–¡ Ran gcloud / Python script to generate GCP activity â†’ ran demo_trigger.py gcp â†’ incident appeared
```

### Azure
```
â–¡ Admin app has Reader + Monitoring Reader roles on subscription
â–¡ AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_SUBSCRIPTION_ID in .env
â–¡ AZURE_EXPERIMENT_CLIENT_ID set to Service Principal OBJECT ID (from Enterprise Applications)
â–¡ Azure admin credential verification command (Step 3.6) passes
â–¡ Ran az / Python script to generate Azure activity â†’ ran demo_trigger.py azure â†’ incident appeared
```

### All Platforms
```
â–¡ Gemini test returns a response
â–¡ PostgreSQL running, breachtrace database exists
â–¡ python -m alembic upgrade head â†’ no errors
â–¡ Backend starts: http://localhost:8000 returns {"status":"ok"}
â–¡ Frontend starts: http://localhost:5173 shows empty dashboard
â–¡ demo_trigger.py has real values filled in for all three platforms
â–¡ Full end-to-end test: ran demo_trigger.py â†’ all 3 incidents appeared â†’ all reached "complete"
   â†’ Gemini reports visible â†’ timelines have dots
â–¡ CLEARED test incidents:
     python -c "from db.database import SessionLocal; from db.models import IncidentRecord; db=SessionLocal(); db.query(IncidentRecord).delete(); db.commit()"
```

---

## PART 17 â€” Demo Day Sequence (30 Minutes Before Evaluators Arrive)

```powershell
# â”€â”€ Terminal A: Backend â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
cd C:\Users\ritwi\Downloads\BreachTrace
.\.venv\Scripts\Activate.ps1
cd backend
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000

# â”€â”€ Terminal B: Frontend â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
cd C:\Users\ritwi\Downloads\BreachTrace\client
npm run dev

# â”€â”€ Terminal C: ngrok (only if using GitHub webhook path) â”€â”€
ngrok http 8000
# After it starts, update the webhook URL in the Connect page (Part 10)

# â”€â”€ Terminal D: Generate cloud activity NOW (25 min before trigger for AWS) â”€â”€â”€

# --- AWS (run now, wait ~20 min before triggering) ---
$env:AWS_ACCESS_KEY_ID = "AKIA...experiment..."
$env:AWS_SECRET_ACCESS_KEY = "...experiment-secret..."
$env:AWS_DEFAULT_REGION = "ap-south-1"
aws sts get-caller-identity; aws iam get-user; aws iam list-users; aws iam list-roles
aws s3 ls; aws s3 ls; aws s3 ls; aws s3 ls; aws s3 ls; aws s3 ls
aws ec2 describe-instances; aws iam get-account-summary

# --- GCP (can run just 5 min before trigger) ---
.\.venv\Scripts\Activate.ps1
python -c "
from google.oauth2 import service_account
from google.cloud import storage
import json
with open(r'C:\Users\ritwi\Downloads\breachtrace-experiment-xxxx.json') as f:
    info = json.load(f)
creds = service_account.Credentials.from_service_account_info(info)
client = storage.Client(project=info['project_id'], credentials=creds)
for i in range(6): list(client.list_buckets()); print(f'GCP run {i+1} done')
"

# --- Azure (can run just 5 min before trigger) ---
az login --service-principal -u EXPERIMENT_APP_CLIENT_ID -p EXPERIMENT_SECRET --tenant TENANT_ID
az resource list; az resource list; az resource list; az group list; az storage account list
az logout

# â”€â”€ Open browser at http://localhost:5173 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Dashboard should show: "No incidents detected yet"

# â”€â”€ When evaluators are watching: Terminal E â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
cd C:\Users\ritwi\Downloads\BreachTrace
python demo_trigger.py          # fires all three platforms at once
# OR one by one:
python demo_trigger.py aws      # then show AWS incident
python demo_trigger.py gcp      # then show GCP incident
python demo_trigger.py azure    # then show Azure incident
```

---

## PART 18 â€” Research Page

Navigate to `http://localhost:5173/research` to show:

- **Track A** â€” SecretBench detection accuracy panel (precision/recall/F1 for AWS/GCP/Azure patterns)
- **Track B** â€” Experiment run metrics (avg detection time, avg report time, severity distribution across platforms)

Track B data populates automatically as you run more incidents through `demo_trigger.py`. Each simulation run is recorded as an experiment run.

---

*BreachTrace â€” Group 03 Â· KJSCE IT Â· 2026*

