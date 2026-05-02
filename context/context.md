# BREACHTRACE — One-Week AWS CloudTrail Forensic Sprint
### Complete End-to-End Pipeline Implementation Plan
**Group 03 | Dept. of Information Technology | K.J. Somaiya College of Engineering**
**Guide: Dr. Irfan Siddavatam**

| RITWIK | SHASHANK | YASH | VEDANT |
|--------|----------|------|--------|
| FastAPI · Webhook · CloudTrail Collector · DB · Docker · Deploy | DB Schema · API Spec · Taxonomy · Severity · Paper + Analysis | AWS Regex Pattern · Rule Classifier · Research Harness · Stats Analysis | React Dashboard · D3 Timeline · Gemini Reports · Normalisation |

---

## CHOSEN PLATFORM: AWS CloudTrail

> **Richest forensic data · Most impressive demo · 100–200 detection tests via SecretBench · 35+ self-created pipeline runs**

---

## SECTION 1 — Platform Selection & Dataset Strategy

### 1.1 Why AWS CloudTrail

The evaluators require a complete end-to-end flow for one platform, validated across **100–200 credentials from public datasets** OR **30+ self-created experiment runs**. AWS CloudTrail wins on every dimension.

| Criterion | AWS CloudTrail | GitHub PAT | Stripe |
|-----------|---------------|-----------|--------|
| Forensic data richness | ★★★★★ Full API call, source IP, resource, timestamp, success/fail per event | ★★★ Action type, repo, actor IP | ★★★★ Event type, customer ID, amount |
| Demo impressiveness | ★★★★★ S3 access, EC2 spin-up, IAM escalation — visible in real time | ★★★ Repo clone, code access | ★★★★ Fraudulent charges, customer data |
| Public detection dataset | ★★★★★ SecretBench has 1,000+ AWS key patterns from real GitHub repos | ★★★★ GitHub PATs also in SecretBench | ★★ Fewer public Stripe key samples |
| Self-experiment feasibility | ★★★★★ 1 throwaway AWS account → 35 IAM keys → 35 full runs in 1 day | ★★★★ Easy PAT rotation | ★★★★★ Test mode instant |
| Audit log API quality | ★★★★★ CloudTrail lookup_events: immediate, paginated, reliable | ★★★ Audit Log needs org | ★★★★ Stripe Events fast |
| Academic citation | ★★★★★ Most referenced in security research | ★★★ GitHub also strong | ★★★ Less cited |

---

### 1.2 Dataset Strategy — Satisfying Both Evaluator Criteria

Both tracks must be ready by Day 7.

#### Track A — 100–200 Public Samples (SecretBench)

- **What it is:** Detection accuracy across 100–200 real-format AWS key samples from the SecretBench public dataset
- **How you get it:** Download SecretBench (Basak et al. 2023 — reference [5] in your project doc) from `https://github.com/setu1421/SecretBench`. Filter for `secret_type = 'AWS'` AND `ground_truth = 'true'`. Extract 200 rows as `data/secretbench_aws_200.csv`. Run your regex detector against all 200. Compare output to ground-truth labels.
- **What you report:** Precision: X%, Recall: X%, F1: X% across 200 real GitHub samples. Proves your detector generalises to real-world leaked credentials.

> **SecretBench:** Paper by Basak, S.K. et al. (2023) — MIT licensed, publicly available. Contains 97,479 true positive and 1,427,212 false positive code snippets, all manually labelled. Your filter yields 500+ AWS rows — use 200.

#### Track B — 35 Self-Created Experiment Runs

- **What it is:** 35 complete forensic pipeline runs using throwaway AWS IAM keys
- **How you get it:** 1 throwaway AWS root account. Create experiment keys (read-only: ListBuckets + DescribeInstances only). Each run: commit key to public GitHub repo via harness → make controlled API calls from second device → BreachTrace collects CloudTrail data → classifies → generates report → records result. Revoke key. Repeat 35 times.
- **What you report:** 35 complete forensic pipeline runs. Metrics: time-to-detection (< 30s target), time-to-report (< 60s target), classification accuracy, blast radius distribution.

---

### 1.3 What 'Complete Flow' Means for the Evaluators

Seven steps, all automated, all wired together:

**Step 1 — GitHub Webhook fires within 30 seconds of commit**
- A real commit containing a fake AWS key (AKIA... format) is pushed to a public GitHub repository
- GitHub fires an HTTP POST to the BreachTrace webhook endpoint
- Webhook received, payload validated, commit diff extracted
- AWS key regex matches → CredentialMatch object created

**Step 2 — Exposure Window recorded**
- Incident record written to PostgreSQL: masked credential hint, repo URL, commit hash, exposure_start, status='collecting'
- Revocation monitoring starts: every 60s, check if key still valid via AWS STS GetCallerIdentity
- When revocation detected: exposure_end is set

**Step 3 — AWS CloudTrail Forensic Collection**
- `boto3 CloudTrail.lookup_events(AccessKeyId=key_id, StartTime=start, EndTime=end)`
- All API calls made with that key during the window returned
- Each event normalised into a ForensicEvent object
- Events persisted to DB. Status → 'classifying'

**Step 4 — Impact Classification**
- Every ForensicEvent passed through the rule-based classifier
- Each event gets: impact_category + severity_weight (1–4)
- Bulk detection: same api_action called 5+ times from same IP → escalate data_access to exfiltration
- Status → 'scoring'

**Step 5 — Severity Score computed**
- Overall severity computed from classified events using escalation rules
- GDPR flag set if data_access/exfiltration events touch PII-hinting resource names
- Status → 'reporting'

**Step 6 — Gemini generates the forensic report**
- Classified events + severity + affected resources + source IPs → Gemini API prompt
- Gemini returns: plain English summary, chronological narrative, remediation checklist
- Report stored in incident record. Status → 'complete'

**Step 7 — React Dashboard displays the complete report**
- D3 forensic timeline: X-axis = time, events as coloured circles by severity
- Blast Radius Summary: AWS card with event count + worst category
- Affected Resources: S3 buckets, EC2 instances, IAM entities
- Source IP intelligence with geolocation
- Gemini report + numbered remediation checklist
- GDPR banner if flagged

---

## SECTION 2 — Pre-Week Preparation (Do the Night Before Day 1)

> Everything below must be done the evening before the week starts. If Day 1 begins with accounts still being created, you lose 4 hours.

### 2.1 Accounts & Access

| What to Create | Who | Exact Steps & Notes |
|---------------|-----|---------------------|
| AWS throwaway root account | Ritwik | aws.amazon.com → new account with throwaway email. Enable billing alerts. Create admin IAM user. Note: Account ID, admin key + secret. |
| AWS restricted IAM user for experiments | Ritwik | Create IAM user `breachtrace-experiment`. Attach ONLY: `AmazonS3ReadOnlyAccess` + `AmazonEC2ReadOnlyAccess`. Generate access key. This is the key that gets "leaked" — zero damage possible if actually exploited. |
| Enable CloudTrail in us-east-1 | Ritwik | AWS Console → CloudTrail → Create Trail. Name: `breachtrace-trail`. Apply to all regions. S3 bucket for logs (auto-created). Management events ON, Read/Write = All. **Must be done before any experiments.** |
| GitHub monorepo (private) | Ritwik | Create on GitHub.com. Name: breachtrace. Add all teammates. Branch protection on main. Create exact folder structure from Section 3.1. |
| Public GitHub test repo | Ritwik | Create SEPARATE **public** repo called `breachtrace-test-repo`. Fake credentials get committed here during experiments. Must be public. |
| SecretBench dataset | Yash | `git clone https://github.com/setu1421/SecretBench`. Filter CSV for `secret_type='AWS'` AND `ground_truth='true'`. Export 200 rows as `data/secretbench_aws_200.csv`. |
| Google Gemini API key | Vedant | `https://aistudio.google.com/app/apikey`. Create key. Test with one API call immediately. Free tier = 60 req/min, 1500/day. |
| Railway.app account | Ritwik | Sign up with GitHub login. Create project linked to monorepo. This is the production URL for the webhook. |
| Netlify/Vercel account | Vedant | Sign up at Netlify.com. For frontend deployment from Day 3 onwards. |

### 2.2 .env File Template

> **Add `.env` to `.gitignore` immediately on Day 1, before any git commit.**

```env
# AWS (admin user — for CloudTrail queries and managing experiments)
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
AWS_REGION=us-east-1

# AWS Experiment User (this key gets "leaked" — read-only only)
EXPERIMENT_AWS_ACCESS_KEY_ID=AKIA...
EXPERIMENT_AWS_SECRET_ACCESS_KEY=...

# GitHub
GITHUB_TOKEN=ghp_...
GITHUB_WEBHOOK_SECRET=...          # Random 32-char string — you choose this
GITHUB_TEST_REPO=yourusername/breachtrace-test-repo

# Gemini
GEMINI_API_KEY=...

# Database
DATABASE_URL=postgresql://user:password@localhost:5432/breachtrace

# App
ENVIRONMENT=development
```

---

## SECTION 3 — Repository Structure & Shared Schema

### 3.1 Monorepo Directory Layout (Ritwik creates on Day 1 morning)

```
breachtrace/
  ├── backend/
  │   ├── main.py                     ← FastAPI app: all routes + webhook (Ritwik)
  │   ├── config.py                   ← Load .env, validate all keys present (Ritwik)
  │   ├── detector/
  │   │   ├── __init__.py
  │   │   ├── patterns.py             ← AWS regex patterns ONLY this week (Yash)
  │   │   └── scanner.py              ← Scans commit diff, returns CredentialMatch list (Ritwik stub, Yash logic)
  │   ├── window/
  │   │   ├── __init__.py
  │   │   └── calculator.py           ← Exposure window: start/end, revocation check (Ritwik)
  │   ├── collectors/
  │   │   ├── __init__.py
  │   │   ├── base.py                 ← Abstract BaseCollector class (Ritwik)
  │   │   └── aws.py                  ← AWS CloudTrail collector — ONLY collector this week (Ritwik + Yash mapping)
  │   ├── normalizer/
  │   │   ├── __init__.py
  │   │   └── schema.py               ← ForensicEvent + IncidentRecord Pydantic models (Shashank design, Vedant implements)
  │   ├── classifier/
  │   │   ├── __init__.py
  │   │   ├── taxonomy_aws.py         ← AWS-only taxonomy as Python constants (Shashank design, Yash codes)
  │   │   └── rules.py                ← Rule-based classifier for AWS events (Yash)
  │   ├── scorer/
  │   │   ├── __init__.py
  │   │   └── severity.py             ← Severity aggregation (Shashank design, Ritwik codes)
  │   ├── reporter/
  │   │   ├── __init__.py
  │   │   └── gemini.py               ← Gemini API report generation (Vedant)
  │   ├── db/
  │   │   ├── __init__.py
  │   │   ├── models.py               ← SQLAlchemy ORM models (Shashank spec, Ritwik implements)
  │   │   └── database.py             ← DB engine, session factory (Ritwik)
  │   ├── research/
  │   │   ├── __init__.py
  │   │   ├── harness.py              ← Automated experiment runner (Yash)
  │   │   └── analysis.py             ← Stats analysis of experiment results (Yash)
  │   ├── tests/
  │   │   ├── test_aws_pattern.py     ← AWS key regex tests (Yash)
  │   │   ├── test_secretbench.py     ← 200-sample SecretBench accuracy test (Yash)
  │   │   ├── test_aws_classifier.py  ← Classifier unit tests (Yash)
  │   │   └── test_pipeline.py        ← Full E2E integration test (Ritwik)
  │   └── requirements.txt
  ├── frontend/
  │   ├── src/
  │   │   ├── App.jsx                 ← Router setup (Vedant)
  │   │   ├── pages/
  │   │   │   ├── Dashboard.jsx       ← Incidents list (Vedant)
  │   │   │   ├── IncidentDetail.jsx  ← Full forensic report (Vedant)
  │   │   │   └── Research.jsx        ← Track A + B results charts (Vedant)
  │   │   ├── components/
  │   │   │   ├── ForensicTimeline.jsx
  │   │   │   ├── BlastRadiusSummary.jsx
  │   │   │   ├── SeverityBadge.jsx
  │   │   │   ├── RemediationChecklist.jsx
  │   │   │   └── AffectedResources.jsx
  │   │   └── api/
  │   │       └── client.js           ← Axios instance (Vedant)
  │   └── package.json
  ├── data/
  │   └── secretbench_aws_200.csv     ← Track A test set (Yash downloads pre-week)
  ├── docker-compose.yml
  ├── Dockerfile.backend
  ├── .env.example
  ├── .gitignore                      ← Must include: .env, __pycache__, node_modules
  └── README.md                       ← Shashank writes
```

### 3.2 The ForensicEvent Schema (Shashank designs, Vedant implements — agreed before any collector code)

> **Nobody writes collector code until `schema.py` is committed to the repo.**

```python
class ForensicEvent(BaseModel):
    event_id:            str          # UUID, auto-generated with uuid4()
    platform:            str          # Always 'aws' this week
    timestamp:           datetime     # EventTime from CloudTrail (UTC)
    api_action:          str          # EventName e.g. 'GetObject', 'RunInstances'
    event_source:        str          # EventSource e.g. 's3.amazonaws.com'
    source_ip:           str | None   # SourceIPAddress from CloudTrail
    user_agent:          str | None   # UserAgent from CloudTrail
    affected_resource:   str | None   # Resources[0].ResourceName
    resource_type:       str | None   # Resources[0].ResourceType
    success:             bool         # True if ErrorCode is absent
    error_code:          str | None   # ErrorCode if present
    raw_data:            dict         # Full original CloudTrail event (stored as JSONB)
    # Filled by classifier (Day 4):
    impact_category:     str | None   # One of 7 AWS categories
    severity_weight:     int | None   # 1=Low 2=Medium 3=High 4=Critical

class IncidentRecord(BaseModel):
    incident_id:         str
    credential_type:     str          # 'aws_access_key'
    credential_hint:     str          # 'AKIA' + '****' + last 4 chars ONLY
    access_key_id:       str          # Full AKIA... key ID (NOT the secret) — needed for CloudTrail query
    repo_url:            str
    commit_hash:         str
    exposure_start:      datetime
    exposure_end:        datetime | None
    status:              str          # 'detecting'|'collecting'|'classifying'|'scoring'|'reporting'|'complete'
    events:              list[ForensicEvent]
    overall_severity:    str | None
    report_text:         str | None
    remediation_steps:   list[str]
    gdpr_flag:           bool
    estimated_financial_impact: str | None
```

---

## SECTION 4 — Day-by-Day Implementation Plan

| Day | Primary Goal | End-of-Day Deliverable |
|-----|-------------|----------------------|
| **Day 1 (Mon)** | Repo, schema, accounts, FastAPI skeleton, CloudTrail enabled, SecretBench downloaded | FastAPI runs. Schema committed. AWS trail active. |
| **Day 2 (Tue)** | Webhook listener + AWS pattern detector working end-to-end | `POST /webhook/github` detects an AWS key live |
| **Day 3 (Wed)** | AWS CloudTrail collector complete + integrated | `GET /incidents/{id}` returns real CloudTrail events |
| **Day 4 (Thu)** | Classifier + severity scorer + Gemini report. Full pipeline fires. | Full report appears in DB under 60 seconds |
| **Day 5 (Fri)** | React dashboard complete, D3 timeline live, Docker working | Live dashboard shows the full forensic report |
| **Day 6 (Sat)** | 35+ research experiments + Track A evaluation complete | 35+ rows in `experiment_runs`. Accuracy computed. |
| **Day 7 (Sun)** | Integration polish, demo rehearsal, evaluator prep | 3-minute demo rehearsed ×3. Backup slides ready. |

---

### Day 1 (Monday) — Environment, Schema, Accounts, Skeleton

**Goal:** Everyone leaves with a running environment, all accounts set up, the ForensicEvent schema committed, and zero ambiguity about who owns what. The AWS trail must be active today.

#### RITWIK
- Create GitHub monorepo with exact folder structure from Section 3.1
- `requirements.txt`: fastapi, uvicorn, sqlalchemy, alembic, asyncpg, boto3, pydantic, google-generativeai, PyGithub, tenacity, python-dotenv, psycopg2-binary
- Write `config.py`: loads `.env`, validates all keys present at startup — print which are missing and exit if any absent
- Write `main.py`: `GET /` returns `{status: 'ok', message: 'BreachTrace running'}`
- Run: `uvicorn main:app --reload` — confirm it starts on port 8000
- Install ngrok, create tunnel: `ngrok http 8000`
- Set up AWS admin IAM user, **enable CloudTrail in us-east-1** (see Section 2.1)
- Set up Railway.app project linked to monorepo
- Add `.gitignore`: `.env`, `__pycache__`, `*.pyc`, `node_modules`, `.env.local`

#### SHASHANK
- Design and write the ForensicEvent + IncidentRecord schema (Section 3.2) in Notion first — discuss with team — then Vedant implements it
- Write the complete DB table spec: column names, types, nullability, indexes for all 4 tables
- Write the AWS taxonomy spec for `taxonomy_aws.py`: map 50+ AWS API call names to 7 categories. Use Claude to help — paste the 7 categories + 50 action names and ask for classification.
- Write all API endpoint specs in Notion: `GET /incidents`, `GET /incidents/{id}`, `GET /incidents/{id}/timeline`, `POST /test/simulate`, `GET /health` — request/response format, error cases
- Write the `README.md` skeleton

#### YASH
- Download SecretBench from `https://github.com/setu1421/SecretBench`. Filter to 200 AWS rows. Save as `data/secretbench_aws_200.csv`.
- Understand the CSV columns: `snippet` (code text), `secret_type`, `ground_truth` (true/false), `line_number`
- Write `patterns.py`: the AWS access key regex — `AKIA[0-9A-Z]{16}` — and adjacent secret key detection
- Test the pattern on 10 real AKIA... strings from the CSV — does it match all of them?
- Write 20 unit tests in `test_aws_pattern.py`: positive cases (real AKIA format), negative cases (BKIA..., AKIA123, etc.)
- Read the ForensicEvent schema carefully — you will write `map_cloudtrail_event()` tomorrow

#### VEDANT
- Create React project: `npm create vite@latest frontend -- --template react`
- Install: `npm install axios react-router-dom d3 chart.js react-chartjs-2`
- Follow Tailwind CSS + Vite setup guide exactly (4 steps at tailwindcss.com/docs/guides/vite)
- Create three page stubs: `Dashboard.jsx`, `IncidentDetail.jsx`, `Research.jsx` — each returns a styled `<div>` with the page title
- Set up React Router in `App.jsx`: `/` → Dashboard, `/incident/:id` → IncidentDetail, `/research` → Research
- Create `api/client.js`: Axios instance with `baseURL = import.meta.env.VITE_API_URL`, 30-second timeout
- Implement ForensicEvent + IncidentRecord Pydantic schema in `schema.py` (from Shashank's Notion doc — implement exactly, don't improvise)
- Test Gemini API: `import google.generativeai as genai; genai.configure(api_key=KEY); model = genai.GenerativeModel('gemini-1.5-flash'); print(model.generate_content('Hello').text)`

> **Day 1 Hard Stops — do not move to Day 2 until all are true:**
> - Ritwik: FastAPI runs on localhost:8000. Railway project created. AWS CloudTrail enabled in us-east-1.
> - Shashank: ForensicEvent schema committed to `schema.py`. DB table spec written in Notion. 50+ AWS API calls mapped.
> - Yash: SecretBench CSV at 200 AWS rows. Pattern written. 20 unit tests passing.
> - Vedant: React runs on localhost:3000. Axios client set up. `schema.py` committed. Gemini API call returns a response.
> - All: `.gitignore` has `.env`. No credentials in any committed file.

---

### Day 2 (Tuesday) — Webhook Listener, Credential Scanner, DB Working

**Goal:** A real GitHub push containing a fake AWS key is detected within 30 seconds. The incident is written to the DB. `GET /incidents` returns it.

#### RITWIK
- Build `POST /webhook/github` in `main.py`
- Validate `X-Hub-Signature-256` header: compute HMAC-SHA256 of raw request body using `GITHUB_WEBHOOK_SECRET`, compare to header — reject with 401 if mismatch
- Parse push event payload: extract `repository.html_url`, `head_commit.id`, `head_commit.timestamp`, `commits` array
- For each commit: use PyGitHub to fetch full diff text — `Github(GITHUB_TOKEN).get_repo(repo_name).get_commit(sha).files` — extract each file's `.patch` string, concatenate into `diff_text`
- Call `scanner.scan(diff_text)` → returns list of `CredentialMatch` objects
- For each match: create `IncidentRecord` in DB, trigger background collection task
- Build `POST /test/simulate`: accepts `{repo_url, diff_text, access_key_id}` — bypasses GitHub API, goes directly to scanner — **critical for testing without real webhooks**
- Build `GET /incidents` and `GET /incidents/{id}` from Shashank's spec
- Set up PostgreSQL: implement DB models from Shashank's spec in `models.py`. Run `alembic init` + first migration.
- Add actual GitHub webhook to the public test repo: Settings → Webhooks → URL = ngrok/Railway URL + `/webhook/github`. Content type: `application/json`. Secret = `GITHUB_WEBHOOK_SECRET`.
- **Live test:** commit the string `AKIAIOSFODNN7EXAMPLE` to the test repo. Watch webhook fire. Confirm incident appears in DB.

#### SHASHANK
- Implement DB `models.py` — Ritwik codes it, you verify it matches your spec exactly after he commits
- Specify indexes: `incident_records(credential_type)`, `incident_records(exposure_start)`, `forensic_events(incident_id)`, `forensic_events(platform)`
- Write the revocation check logic as pseudocode: `boto3.client('sts', aws_access_key_id=EXPERIMENT_KEY_ID, ...).get_caller_identity()` — if it succeeds: key valid; if `ClientError` with code `'InvalidClientTokenId'`: key revoked
- Write exposure window pseudocode: start = commit_timestamp. Every 60s in a background loop, call revocation check. When revoked: set `exposure_end = now()`. Timeout after 10 minutes.
- Expand the AWS taxonomy to 80+ entries. Focus on all S3, EC2, IAM actions. Assign category + severity weight to each.
- Begin converting Notion taxonomy table to `taxonomy_aws.py` Python dict

#### YASH
- Complete `scanner.py` logic (Ritwik writes the function signature, you fill in the body):
  - `scan(diff_text: str) → list[CredentialMatch]`
  - Iterate all lines, run the AWS key regex against each
  - If match found: check adjacent lines for secret key pattern (40-char alphanumeric)
  - Create `CredentialMatch(type='aws_access_key', access_key_id=matched_key_id, hint='AKIA****'+last4, line_number=n)`
  - False-positive reduction: AKIA key must be exactly 20 chars. Secret key must be exactly 40 chars. Reject if either fails.
- Write `test_secretbench.py`: load CSV, for each row call `scanner.scan(snippet_text)`, compare to `ground_truth` label, compute precision/recall/F1. Run it and record the numbers. Target: Precision > 95%, Recall > 90%.
- Write 20 more unit tests — bring total to 40+

#### VEDANT
- Build `Dashboard.jsx`: fetch `GET /incidents` on mount. Display table: incident ID (truncated), `credential_hint`, `exposure_start` (formatted local time), severity badge, status.
- Build `SeverityBadge.jsx`: styled span — `Low`=green, `Medium`=yellow, `High`=orange, `Critical`=red (Tailwind classes).
- Build `IncidentDetail.jsx` stub: fetch `GET /incidents/:id` on mount, display `credential_hint`, `credential_type`, `exposure_start`, `exposure_end`, `status`. Leave timeline as `'Loading events...'` placeholder.
- Wire React Router: clicking a row in Dashboard navigates to `/incident/{id}`
- Empty state: if no incidents, show `'No incidents detected yet. Connect your GitHub repository to begin monitoring.'`
- Ensure `npm run build` completes with zero errors

> **Day 2 verification test:** POST `/test/simulate` with a fake diff containing `AKIAIOSFODNN7EXAMPLE` → check logs show detection → `GET /incidents` returns the incident → `GET /incidents/{id}` shows `status='collecting'`. All five steps must pass.

---

### Day 3 (Wednesday) — AWS CloudTrail Collector Complete + Integrated

**Goal:** The CloudTrail collector queries real CloudTrail events for the exposure window and returns real `ForensicEvent` objects. Full pipeline from webhook to events-in-DB is complete.

#### RITWIK
- Write `collectors/base.py`: abstract `BaseCollector` class with abstract method `collect(access_key_id, exposure_start, exposure_end) → list[ForensicEvent]`
- Write `collectors/aws.py` — `AWSCollector(BaseCollector)` — the single most important file this week:
  - `boto3.client('cloudtrail', region_name=AWS_REGION, aws_access_key_id=ADMIN_KEY_ID, aws_secret_access_key=ADMIN_SECRET)`
  - `lookup_events(LookupAttributes=[{'AttributeKey':'AccessKeyId','AttributeValue':access_key_id}], StartTime=exposure_start, EndTime=exposure_end, MaxResults=50)`
  - Loop: `while True: process events; if 'NextToken' in response: call again with NextToken; else: break`
  - For each raw event: call Yash's `map_cloudtrail_event(event)` → `ForensicEvent`
  - Wrap in `tenacity @retry(wait=wait_exponential(multiplier=1, min=2, max=30), stop=stop_after_attempt(5))`
- Implement the parallel orchestrator: after detection, fire `AWSCollector` in a `FastAPI BackgroundTask` — NOT blocking the webhook response
- Implement `window/calculator.py` from Shashank's pseudocode
- **Live test:** use `EXPERIMENT_AWS_ACCESS_KEY_ID`. From a second terminal: `aws s3 ls --profile experiment`. Trigger a simulated incident. Wait 2 minutes. `GET /incidents/{id}` — confirm events appear.
- Deploy to Railway.app. Update GitHub webhook URL to Railway HTTPS URL.

> **CloudTrail notes:**
> - Pass the full AKIA... key ID (not the secret) to `lookup_events`
> - CloudTrail has up to 15-minute delivery delay — set `EndTime = exposure_end + 20 minutes`
> - The experiment key is read-only. CloudTrail still logs ListBuckets and DescribeInstances calls.
> - Test first: make 2 API calls with the experiment key, check CloudTrail console in 15 minutes, confirm events appear — only then will the collector work.

#### SHASHANK
- Deploy to Railway: push to main branch, get the live HTTPS URL, update GitHub webhook
- Write the `collection_status` table migration: per-incident, per-platform status (`success`/`error`/`no_activity`), event count, error message
- Add collection status to `GET /incidents/{id}` response
- Verify DB migration works on Railway's PostgreSQL
- Review Yash's `map_cloudtrail_event()` — does every field map correctly?
- Complete `taxonomy_aws.py`: 80+ entries committed to repo
- Write severity algorithm pseudocode for `severity.py` including all escalation rules

#### YASH
- Write `map_cloudtrail_event(raw_event: dict) -> ForensicEvent`:
  - `raw_event['EventTime']` → `timestamp`
  - `raw_event['EventName']` → `api_action`
  - `raw_event['EventSource']` → `event_source`
  - `raw_event['SourceIPAddress']` → `source_ip`
  - `raw_event['UserAgent']` → `user_agent`
  - `raw_event['Resources'][0]['ResourceName']` → `affected_resource` (if list is non-empty)
  - `raw_event['Resources'][0]['ResourceType']` → `resource_type`
  - `raw_event.get('ErrorCode')` → `error_code`; `success = (error_code is None)`
  - `event_id = str(uuid4())`, `platform = 'aws'`, `raw_data = raw_event`
- Write 30 unit tests in `test_aws_classifier.py` using real-format CloudTrail event dicts from AWS docs
- Run `pytest tests/test_aws_pattern.py` — all must pass. Run `test_secretbench.py` — record accuracy.

#### VEDANT
- Build `AffectedResources.jsx`: groups ForensicEvents by `resource_type`, shows a card per type with resource names and event counts
- Wire `IncidentDetail.jsx` to real API data: fetch `GET /incidents/:id/timeline`, display events in a scrollable table: timestamp | api_action | event_source | source_ip | affected_resource
- Build `ForensicTimeline.jsx` skeleton: accepts `events[]` prop, render a simple HTML timeline as `<div>` elements (NOT D3 yet — D3 comes Day 5)
- Add status progress indicator to `IncidentDetail`: detecting → collecting → classifying → reporting → complete as a horizontal step indicator
- Deploy React frontend to Netlify/Vercel: set `VITE_API_URL` env variable to Railway backend URL

---

### Day 4 (Thursday) — Classifier, Severity Scorer, Gemini Report

**Goal:** Every CloudTrail event gets classified. The incident gets a severity score. Gemini generates a readable report. The full pipeline fires automatically within 60 seconds.

#### RITWIK
- Wire the intelligence pipeline: after `AWSCollector.collect()` finishes, automatically fire `classify_all_events(incident_id)` → `score_incident(incident_id)` → `generate_report(incident_id)` as chained `BackgroundTask`s
- Each step updates incident status: `collecting → classifying → scoring → reporting → complete`
- Implement `GET /incidents/{id}/timeline`: ForensicEvents sorted by timestamp, with `impact_category` and `severity_weight` filled
- Implement `PATCH /incidents/{id}`: accepts `{report_text, remediation_steps, gdpr_flag, financial_impact, overall_severity}`
- Time the full pipeline: must be under 60 seconds. Log timing per stage.
- Build GDPR flag check: after classification, scan `affected_resource` strings for `'user'`, `'customer'`, `'pii'`, `'email'`, `'personal'`, `'private'` — if any `data_access` or `exfiltration` event matches, set `gdpr_flag=True`

#### SHASHANK
- Implement `severity.py` — pure Python, no APIs:
  ```
  def score_incident(events: list[ForensicEvent]) -> str:
      categories = {e.impact_category for e in events if e.impact_category}
      if any of {'privilege_escalation', 'exfiltration', 'code_compromise'} in categories:
          return 'Critical'
      max_weight = max(e.severity_weight or 0 for e in events)
      if 'financial_abuse' in categories and max_weight >= 3: return 'Critical'
      elif 'financial_abuse' in categories: return 'High'
      map: 4→'Critical', 3→'High', 2→'Medium', 1→'Low', 0→'Low'
  ```
- Also implement `compute_financial_impact(events)`: look for `RunInstances` events (EC2 cost), `GetObject` with large resources (data transfer), return formatted string
- Write 15 tests for `severity.py`
- Review Yash's classifier output on 3 real incidents
- Finalise all 80+ taxonomy entries — `taxonomy_aws.py` committed

#### YASH
- Build `classifier/rules.py` — your primary contribution this week:
  ```
  classify_event(event: ForensicEvent) -> tuple[str, int]:
    Step 1: exact lookup → taxonomy_aws.CATEGORY_RULES[event.platform].get(event.api_action)
    Step 2: prefix heuristics for unknown actions:
            'List*' or 'Describe*' → ('reconnaissance', 1)
            'Get*' (single call)   → ('data_access', 2)
            'Put*' or 'Create*'    → ('resource_abuse', 3)
            'Delete*'              → ('resource_abuse', 3)
    Step 3: special overrides:
            CreateAccessKey, AttachUserPolicy, PutRolePolicy → ('privilege_escalation', 4)
            RunInstances, CreateCluster              → ('resource_abuse', 3)
    Step 4: fallback → ('reconnaissance', 1)
  ```
- Write `classify_all_events(incident_id, db)`: fetches all events, classifies each, updates DB
- Bulk detection: after classifying all events, if same `api_action` called 5+ times from same `source_ip` and current category is `'data_access'` → update all those events to `('exfiltration', 4)`
- Run `test_aws_classifier.py` — all 30+ tests passing

#### VEDANT
- Build `reporter/gemini.py` — `generate_report(incident: IncidentRecord) -> str`:
  - Build prompt with 3 sections: (1) context — credential type, repo, duration in human-readable format, (2) events list — `TIMESTAMP — EventName from SOURCE_IP on RESOURCE (category: CATEGORY)`, (3) stats — totals, highest severity
  - Instruction to Gemini: `'Generate a forensic incident report in four sections: (1) Executive Summary (1 paragraph, plain English, no jargon), (2) Chronological Narrative (what the attacker did step by step), (3) Business Impact Assessment, (4) Remediation Checklist (number each item, start with ☐, be specific — include exact resource names).'`
  - Parse response: extract checkbox items from Section 4 as `list[str]` → `remediation_steps`
  - Call `PATCH /incidents/{id}` to store `report_text` + `remediation_steps` + `gdpr_flag`
- Build `RemediationChecklist.jsx`: styled checklist, each item as a checkbox row
- Test on one real incident. Read the output. Adjust prompt if unclear.

> **Gemini prompt notes:**
> - Add: `'The audience is a developer with no security background. Avoid acronyms. Use plain language.'`
> - Add: `'If any resource name contains user, customer, email, pii — flag this as a GDPR notification requirement.'`
> - Add: `'Keep the entire report under 400 words. Use exact resource names provided.'`
> - Model: `gemini-1.5-flash` (faster than Pro, free tier more generous)
> - Build a template-based fallback in case Gemini API fails — ensures pipeline never crashes

---

### Day 5 (Friday) — React Dashboard, D3 Timeline, Docker, Full Demo

**Goal:** Full pipeline result visible in a polished React dashboard. D3 timeline works. Docker brings up the whole stack. Team runs a complete demo for themselves for the first time.

#### RITWIK
- Write `Dockerfile.backend`: `FROM python:3.11-slim`, `COPY requirements.txt`, `RUN pip install`, `COPY . .`, `CMD uvicorn main:app --host 0.0.0.0 --port 8000`
- Write `docker-compose.yml`: services `backend` (Dockerfile.backend) + `db` (postgres:15-alpine). Backend `depends_on` db. Env vars from `.env`.
- Test: `docker-compose up` — backend starts, DB starts, migrations run, `GET /health` returns 200
- Run full pipeline E2E: real GitHub push → webhook fires → CloudTrail queried → events classified → Gemini report → `status=complete`. Time it. Log each stage.
- Target: < 60 seconds total
- Add `GET /incidents/stats`: total count, counts by severity, average detection time, average report time, top categories
- Final Railway deployment: confirm auto-deploy on git push is working

#### SHASHANK
- Watch the internal demo run. Take notes on what's broken.
- Open the DB and check 10 classified events — is every `impact_category` and `severity_weight` correct?
- If misclassifications found: update `taxonomy_aws.py` and push a fix
- Review the Gemini report: is it readable? Give Vedant specific feedback.
- Begin writing paper Section 3 (System Design): describe the 8-module architecture. Target 500 words in Google Docs.

#### YASH
- Verify the full classifier pipeline on a real incident: every `ForensicEvent` must have `impact_category` and `severity_weight` filled
- Fix any classification bugs
- Begin `harness.py` for Day 6:
  - `push_fake_credential(access_key_id, secret_key)`: use PyGitHub to create/update `config.env` in the test repo with content `AWS_ACCESS_KEY_ID={key}\nAWS_SECRET_ACCESS_KEY={secret}`
  - `simulate_attacker_activity(access_key_id, secret_key)`: create a boto3 session using the experiment key and make 3 calls: `s3.list_buckets()`, `ec2.describe_instances()`, `sts.get_caller_identity()`
  - `delete_credential_from_repo()`: deletes `config.env` from test repo
  - `revoke_iam_key(access_key_id)`: calls `boto3 IAM` with admin credentials to delete the experiment key
- Write `test_pipeline.py`: calls `POST /test/simulate`, waits 90 seconds, asserts `status='complete'` and events are classified

#### VEDANT
- Build the real `D3.js ForensicTimeline.jsx`:
  1. `useRef(null)` for SVG container. `useEffect` runs when `props.events` changes.
  2. Inside `useEffect`: clear existing SVG (`d3.select(ref.current).selectAll('*').remove()`). Append `<g>` with margin offsets.
  3. X-axis: `d3.scaleTime().domain([exposure_start, exposure_end || new Date()]).range([0, innerWidth])`
  4. Y-axis: `d3.scaleBand().domain(unique_event_sources).range([0, innerHeight]).padding(0.2)`
  5. Draw circles: `cx=xScale(event.timestamp)`, `cy=yScale(event.event_source)+bandWidth/2`, `r=8`, `fill=severityColor(event.severity_weight)`
  6. Tooltip: on mouseover show floating div with timestamp | api_action | source_ip | affected_resource | impact_category
  7. Draw X axis (`d3.axisBottom`) and Y axis (`d3.axisLeft` with service names)
- Build `BlastRadiusSummary.jsx`: AWS card showing total events, worst category, severity badge, bar chart of events per category
- Final `IncidentDetail` page layout: header (credential hint, duration, severity badge) → status bar → Gemini report → ForensicTimeline → BlastRadiusSummary → AffectedResources → RemediationChecklist → GDPR banner

> **Day 5 internal demo — run this with the full team before bed:**
> Push a fake AWS key. On second laptop: run 3 AWS CLI commands with experiment key. Wait for pipeline to complete. Open dashboard.
> Must show: dashboard lists incident within 30s · D3 timeline with 3 events plotted · BlastRadiusSummary with categories · Gemini report with plain English summary · Remediation checklist with ≥ 3 steps.
> If this demo works cleanly, you have a complete MVP.

---

### Day 6 (Saturday) — Research Harness: 35+ Experiments + Track A Evaluation

**Goal:** 35+ fully automated forensic pipeline experiments in the DB. Track A (SecretBench 200) accuracy finalised. All research data ready for evaluators.

#### RITWIK
- Help Yash run the research harness — manage AWS IAM key rotation
- Key rotation strategy: 1 IAM user `experiment-user-1`. Per experiment: create a new IAM access key (AWS allows 2 active keys per user — delete old one each time). Sequence: create key → run experiment → delete key → repeat.
- Write `research/key_manager.py`: `create_experiment_key() → (access_key_id, secret_access_key)` and `delete_experiment_key(key_id)`
- Monitor the full harness run. Fix errors immediately. Target: 35 successful complete runs.
- After 35 runs: verify DB — `SELECT * FROM experiment_runs` — confirm all fields populated

#### SHASHANK
- Write `GET /research/export` endpoint: returns all `experiment_runs` rows as JSON (and optionally CSV via `?format=csv`)
- Track which experiments show external (non-team) API calls vs only team's simulated calls. Flag in the experiment record.
- After 35 runs: immediately compute preliminary stats: mean/median `detection_time_s`, mean/median `report_time_s`, severity distribution
- Write a research summary in Notion — this is what you present to evaluators
- Begin paper Section 5 (Evaluation): describe experiment methodology, setup, 35-run design

#### YASH
- Complete and run `harness.py` — the full experiment loop (35 iterations):

  ```
  Loop 35 times:
  1.  create_experiment_key() → (key_id, secret)
  2.  experiment_start = datetime.now()
  3.  push_fake_credential(key_id, secret)
  4.  Wait 60 seconds
  5.  simulate_attacker_activity(key_id, secret)
  6.  Wait 120 seconds
  7.  GET /incidents to find the incident created in step 3
  8.  Poll for status='complete' (every 10s, max 3 min)
  9.  Record: detection_time_s, report_time_s, impact_categories, overall_severity
  10. delete_experiment_key(key_id)
  11. delete_credential_from_repo()
  12. Wait 30 seconds. Repeat.
  ```

- **Vary the 3 API calls across experiments:**
  - Runs 1–12 **(Group A — Standard):** `ListBuckets + DescribeInstances + GetCallerIdentity` → expected severity: Low
  - Runs 13–25 **(Group B — Bulk):** `ListBuckets + GetObject × 5` → triggers bulk detection → expected severity: Critical
  - Runs 26–35 **(Group C — Minimal):** `GetCallerIdentity` only → expected severity: Low
- Write all results to `experiment_runs` table via `POST /research/record`
- Run `analysis.py` after 35 runs: compute mean/median/stdev for `detection_time_s` and `report_time_s`
- Run `test_secretbench.py` one final time — record the accuracy

#### VEDANT
- Build `Research.jsx` with real data from `/research/export`:
  - **Chart 1 (Bar):** pipeline timing — `Time to Detection` and `Time to Report` with 30s/60s target lines
  - **Chart 2 (Doughnut):** blast radius severity distribution across 35 runs
  - **Chart 3 (Stacked Bar):** impact categories per experiment group (A/B/C) — shows how attacker behaviour affects blast radius
  - **Track A metric card:** `'Detection Accuracy on 200 Public Samples: Precision X% | Recall X% | F1 X%'`
  - **Track B metric card:** `'35 Full Pipeline Runs: Avg Detection Time X.Xs | Avg Report Time X.Xs'`
- Add `'Download Report'` button on IncidentDetail: `window.print()` with print CSS hiding sidebar/nav

> **Experiment variation matters for the paper:** three groups produce three distinct blast radius outcomes — minimal activity → Low, standard reconnaissance → Low/Medium, bulk data access → Critical.

---

### Day 7 (Sunday) — Integration Polish, Demo Rehearsal, Evaluator Preparation

**Goal:** System is demo-ready. 3-minute demo rehearsed to perfection. Every number is accurate. Backup plan exists.

#### RITWIK
- Run the full E2E pipeline 5 times and log detection + report latency for each. Both must be under their targets. Compute mean.
- Fix the 3 most critical bugs from Days 5–6
- Prepare one pre-loaded incident in the DB from a real pipeline run — the 'backup incident' shown if live demo has issues
- Ensure GitHub test repo webhook points to Railway. Test by committing something.
- Record a 90-second screen recording of the dashboard — ultimate fallback if live demo completely fails
- Demo rehearsal ×3: time yourself, must be under 3 minutes

#### SHASHANK
- Compile all research numbers into a single summary table for the evaluators
- Rehearse the guide pitch ×3: 90 seconds
- Rehearse Minute 3 of the demo (research findings)
- Prepare 5 backup slides: (1) architecture diagram, (2) forensic report screenshot, (3) D3 timeline screenshot, (4) research results table, (5) pre-loaded incident

#### YASH
- `pytest tests/` — all tests must pass
- Run `analysis.py` one final time. Print the clean results table.
- Write Track A summary: `'BreachTrace detected X of 200 real-world AWS key samples correctly. False positives: X. These occurred because [reason].'`
- Code cleanup: remove all `print()` debug statements, hardcoded values

#### VEDANT
- Full end-to-end UI test from a different device using the deployed Netlify URL
- Ensure all charts on `Research.jsx` render with real data
- Take 10 high-quality screenshots: Dashboard · IncidentDetail header · D3 timeline · Gemini report · Remediation checklist · Blast radius summary · Affected resources · Research page · Track A card · Track B card
- Ensure print-to-PDF button works cleanly on Chrome

> **Week Exit Criteria — all must pass before evaluator presentation:**
> 1. AWS key detected in a real GitHub push within 30 seconds
> 2. CloudTrail events in DB as ForensicEvent objects with all fields populated
> 3. Every event has `impact_category` and `severity_weight` assigned correctly
> 4. Overall incident severity correctly computed
> 5. Gemini report is readable, specific, includes remediation checklist
> 6. D3 timeline renders with real events — tooltips work
> 7. Full pipeline completes in under 60 seconds
> 8. Track A: 200 SecretBench samples tested, Precision ≥ 90%
> 9. Track B: 35 complete pipeline runs in `experiment_runs` table with statistics
> 10. `docker-compose up` starts the entire system cleanly
> 11. `Research.jsx` shows real Track A and Track B numbers
> 12. 3-minute demo rehearsed at least 3 times

---

## SECTION 5 — Technical Implementation Details

### 5.1 AWS Taxonomy (taxonomy_aws.py) — Shashank designs, Yash implements

| Weight | Category | AWS API Actions (must all be in taxonomy) | Notes |
|--------|----------|------------------------------------------|-------|
| 1 | `reconnaissance` | ListBuckets, ListObjects, DescribeInstances, DescribeSecurityGroups, DescribeVpcs, ListUsers, ListGroups, ListRoles, ListPolicies, GetCallerIdentity, DescribeRegions, ListFunctions, ListTables, GetAccountSummary | Any `List*` or `Describe*` call. Attacker is mapping the account. |
| 2 | `data_access` | GetObject, GetItem, GetSecretValue, DescribeSecret, HeadObject, GetBucketPolicy, GetBucketAcl, GetRolePolicy, GetUserPolicy, ListObjectVersions, SelectObjectContent | Single `Get*` on a specific resource. 5+ times from same IP → escalate to exfiltration. |
| 4 | `exfiltration` | GetObject (×5+), CopyObject (batch), ExportTableToPointInTime, CreateExportTask, BatchGetItem (large), SelectObjectContent (data scan) | Bulk retrieval. If `GetObject` appears 5+ times from same `source_ip` → reclassify ALL those events to exfiltration. |
| 3 | `resource_abuse` | RunInstances, StartInstances, CreateLoadBalancer, AllocateAddress, CreateSnapshot, CreateImage, CreateCluster, CreateFunction, CreateTable, RequestSpotInstances | Attacker using the account's compute. EC2 spin-up is the clearest signal. |
| 4 | `privilege_escalation` | CreateAccessKey, DeleteAccessKey, AttachUserPolicy, DetachUserPolicy, AttachRolePolicy, PutUserPolicy, PutRolePolicy, AddUserToGroup, CreateRole, CreateUser, UpdateAccessKey, SetDefaultPolicyVersion | Any IAM modification = privilege escalation. **Always weight 4. Always triggers Critical minimum.** |
| 3 | `financial_abuse` | RunInstances (high count), CreateCluster (GPU), RequestSpotInstances (bulk), CreateDBInstance, CreateDomain | AWS financial abuse via large compute creation. Count threshold: 5+ instances = financial_abuse. |
| 2 | `communication_abuse` | Publish (SNS), SendMessage (SQS), SendEmail (SES), SendRawEmail, SendBulkTemplatedEmail | AWS messaging used to send spam or phishing. |

### 5.2 DB Schema

```sql
TABLE: incident_records
  incident_id         UUID PRIMARY KEY DEFAULT gen_random_uuid()
  credential_type     VARCHAR(50) NOT NULL           -- 'aws_access_key'
  credential_hint     VARCHAR(20) NOT NULL           -- 'AKIA****MPLE'
  access_key_id       VARCHAR(30)                    -- full AKIA... key ID (not secret)
  repo_url            TEXT NOT NULL
  commit_hash         VARCHAR(40)
  exposure_start      TIMESTAMPTZ NOT NULL
  exposure_end        TIMESTAMPTZ
  status              VARCHAR(20) DEFAULT 'detecting'
  overall_severity    VARCHAR(10)
  report_text         TEXT
  remediation_steps   JSONB DEFAULT '[]'
  gdpr_flag           BOOLEAN DEFAULT FALSE
  financial_impact    TEXT
  created_at          TIMESTAMPTZ DEFAULT NOW()
  INDEX ON: credential_type, exposure_start, status

TABLE: forensic_events
  event_id            UUID PRIMARY KEY
  incident_id         UUID REFERENCES incident_records(incident_id) ON DELETE CASCADE
  platform            VARCHAR(20) DEFAULT 'aws'
  timestamp           TIMESTAMPTZ NOT NULL
  api_action          VARCHAR(100) NOT NULL
  event_source        VARCHAR(100)
  source_ip           VARCHAR(50)
  user_agent          TEXT
  affected_resource   TEXT
  resource_type       VARCHAR(100)
  success             BOOLEAN DEFAULT TRUE
  error_code          VARCHAR(50)
  impact_category     VARCHAR(50)
  severity_weight     INTEGER CHECK (severity_weight BETWEEN 1 AND 4)
  raw_data            JSONB NOT NULL
  INDEX ON: incident_id, timestamp, impact_category

TABLE: collection_status
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid()
  incident_id         UUID REFERENCES incident_records(incident_id)
  platform            VARCHAR(20) DEFAULT 'aws'
  status              VARCHAR(20)    -- 'success' | 'no_activity' | 'error'
  event_count         INTEGER DEFAULT 0
  error_message       TEXT
  queried_at          TIMESTAMPTZ DEFAULT NOW()

TABLE: experiment_runs
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid()
  incident_id         UUID REFERENCES incident_records(incident_id)
  run_number          INTEGER
  experiment_group    VARCHAR(10)    -- 'A' | 'B' | 'C'
  exposure_start      TIMESTAMPTZ
  attacker_sim_start  TIMESTAMPTZ
  detection_time_s    INTEGER
  report_time_s       INTEGER
  api_calls_made      JSONB
  impact_categories   JSONB
  overall_severity    VARCHAR(10)
  external_use_detected BOOLEAN DEFAULT FALSE
  notes               TEXT
  created_at          TIMESTAMPTZ DEFAULT NOW()
```

### 5.3 Complete API Endpoint Reference

| Endpoint | Owner | Purpose | Notes |
|----------|-------|---------|-------|
| `POST /webhook/github` | Ritwik | GitHub push event — triggers full pipeline | Validate X-Hub-Signature-256. Return 200 immediately, process async. |
| `POST /test/simulate` | Ritwik | Test without real GitHub push | Body: `{repo_url, diff_text, access_key_id}` |
| `GET /incidents` | Ritwik | List all incidents | Returns: `[{incident_id, credential_hint, exposure_start, overall_severity, status, event_count}]` |
| `GET /incidents/{id}` | Ritwik | Full incident with nested events | Includes all ForensicEvents, report_text, remediation_steps, gdpr_flag |
| `GET /incidents/{id}/timeline` | Ritwik | Events sorted by timestamp | Used by D3 timeline directly |
| `POST /incidents/{id}/collect` | Ritwik | Manually re-trigger collection | For retry after failure |
| `POST /incidents/{id}/classify` | Ritwik | Manually re-run classifier | Used when taxonomy is updated |
| `PATCH /incidents/{id}` | Ritwik | Update report fields | Accepts: `{report_text, remediation_steps, gdpr_flag, financial_impact, overall_severity}` |
| `GET /incidents/stats` | Ritwik | Aggregate statistics | `{total, by_severity, avg_detection_time_s, avg_report_time_s, top_categories}` |
| `POST /research/record` | Ritwik | Save experiment run result | Called by `harness.py` after each run |
| `GET /research/export` | Ritwik | Export all experiment runs | JSON array of all `experiment_runs` rows. `?format=csv` for CSV. |
| `GET /health` | Ritwik | System health check | `{status:'ok', db:'connected', last_incident_at, environment}` |

---

## SECTION 6 — Evaluator Presentation Script

### 6.1 What the Evaluators Will See

| Time | What Happens |
|------|-------------|
| 0:00–1:00 | Shashank delivers the problem pitch. Shows the empty dashboard. |
| 1:00–2:30 | Ritwik commits the fake AWS key. Live pipeline runs. D3 timeline appears. Full report shown. |
| 2:30–3:00 | Shashank presents research findings: Track A accuracy + Track B pipeline timing from Research page. |
| 3:00+ | Q&A: evaluators examine the dashboard. Shashank answers architecture questions. Yash explains the classifier. Vedant explains the report. |

### 6.2 Pre-Demo Setup (15 minutes before evaluators arrive)

1. On demo laptop: open 3 tabs — Tab 1 = BreachTrace Dashboard (Netlify URL), Tab 2 = GitHub test repo, Tab 3 = Research page
2. Confirm Railway backend is alive: open Tab 1, it should show the incident list or empty state
3. On second laptop: run `aws sts get-caller-identity --profile experiment` — confirm it returns the account ID. If it fails, create a new experiment key via `key_manager`.
4. In the DB: confirm ≥ 35 rows in `experiment_runs` table. Confirm ≥ 1 pre-existing complete incident (backup incident).
5. Open Research page (Tab 3): confirm all 3 charts loading with real data, both metric cards show real numbers
6. Have the backup slides open in the background

### 6.3 Minute 1 — The Problem (Shashank speaks)

> *"Credential leaks are the most common, most costly security mistake in software development."*
>
> *"Every day, developers accidentally commit API keys to public GitHub repositories. Automated bots find those keys within minutes — and start using them."*
>
> *"Tools like GitGuardian send you an alert: your AWS key was leaked. Rotate it. But they never tell you what actually happened because it leaked."*
>
> *"Was your S3 bucket accessed? Were EC2 instances spun up? Was a new root key created?"*
>
> *"Developers rotate the key and hope for the best. They never actually know."*
>
> *"BreachTrace fills that gap. It automatically correlates the GitHub exposure event with AWS CloudTrail and produces a complete forensic impact report in under 60 seconds."*
>
> *[Open the dashboard] "This is BreachTrace. Let us show you how it works."*

### 6.4 Minute 2 — Live Demo (Ritwik drives)

1. **[Ritwik]** "I am now going to push a fake AWS key to a public GitHub repository." Open Tab 2. One git push command. Execute.
2. **[All]** Switch to Tab 1. New incident appears within ~10 seconds. Show it appearing live.
3. Status bar progresses: Detecting → Collecting → Classifying → Reporting → Complete
4. **[Second laptop]** Execute the 3 pre-scripted attacker simulation commands with the experiment key. Show the terminal. *"This simulates what an attacker would do."*
5. Click the incident. Full report page opens.
6. **[Shashank]** *"The forensic timeline shows 3 events during the exposure window — all from the same IP address."* Point to D3 timeline. Hover over an event to show the tooltip.
7. *"AWS: 2 reconnaissance calls and 1 data access. Severity: Medium. No privilege escalation. No data exfiltration."*
8. Read the first sentence of the Gemini executive summary aloud.
9. Scroll to the remediation checklist. *"Three specific steps — including the exact AWS CLI commands."*

### 6.5 Minute 3 — Research Findings (Shashank, switch to Research page)

> *"Beyond the system itself, we ran a systematic evaluation to validate BreachTrace."*
>
> *"Track A: we tested our AWS credential detector against 200 real leaked credential samples from the SecretBench public dataset — a benchmark used in academic security research."*
>
> *[Point to Track A metric card] "Precision: X%. Recall: X%. F1: X%."*
>
> *"Track B: we ran 35 complete forensic pipeline experiments using controlled credential exposures."*
>
> *[Point to timing chart] "Mean time to detection: X seconds against our 30-second target. Mean time to report: X seconds against our 60-second target."*
>
> *[Point to severity chart] "Across 35 runs with different attacker behaviour: minimal activity produced Low severity, bulk data access triggered Critical — the classifier correctly distinguishes reconnaissance from exfiltration."*

### 6.6 Backup Plan

> **If the live pipeline does not complete in 90 seconds: switch to the pre-loaded incident immediately.**
>
> Say: *"Let me show you a completed incident from our earlier test run."* Click the backup incident. Continue from Step 5 (timeline) using the backup.
>
> After the demo: show the evaluators the live pipeline completing on its own.

---

## SECTION 7 — Anticipated Evaluator Questions & Answers

**Q: Why only AWS CloudTrail this week?**
> **Shashank:** "The evaluators asked for one complete platform this week. AWS CloudTrail gives the richest forensic data: per-call timestamps, source IPs, affected resources, success/failure. The architecture is designed so other collectors — GCP, Stripe, GitHub, Twilio — are added as separate modules using the same BaseCollector interface. They are next in our one-month plan."

**Q: How do you validate that 100–200 credentials were tested?**
> **Yash:** "We used the SecretBench public dataset from Basak et al. 2023 — cited as reference [5] in our project document. It contains 97,000+ manually labelled code snippets from GitHub. We filtered for AWS key samples — 200 rows. We ran our regex detector against all 200 and compared to the ground-truth labels. Our test file is `tests/test_secretbench.py` and the dataset is at `data/secretbench_aws_200.csv`."

**Q: What if someone actually uses the exposed test key?**
> **Ritwik:** "The experiment IAM key has only two permissions: S3:ListBuckets and EC2:DescribeInstances — both read-only. Even if an external attacker finds and uses it, they can only list empty bucket names and see EC2 metadata. No data can be read, no resources can be created, no costs incurred. And CloudTrail logs their access — which gives us a legitimate 'external use detected' data point for the research."

**Q: How accurate is the classifier?**
> **Yash:** "The rule-based classifier has two layers. First: exact lookup against our taxonomy of 80+ AWS API call mappings. Second: prefix heuristics for unknown calls. We measured classification accuracy against 30 manually-labelled CloudTrail events — the number is on the Research page. The taxonomy itself is the novel research contribution."

**Q: Is this only useful for security experts?**
> **Vedant:** "The dashboard is designed for developers with no security background. The Gemini report uses plain English — no MITRE references, no CVE numbers. The remediation checklist includes the exact AWS CLI commands to run. A developer who has never heard of CloudTrail can look at this report and know exactly what happened and what to do."

**Q: Why use Gemini instead of a fine-tuned security model?**
> **Shashank:** "We use Gemini for natural language generation only — not for classification. The impact taxonomy and severity rules are our own deterministic system. Gemini takes already-classified, already-structured data and converts it into a readable report. Fine-tuned models require training data we don't have. Gemini's free tier is sufficient, runs in under 3 seconds, and the output quality is better than template strings."

---

## SECTION 8 — Final Notes

> **The one-week goal in one sentence:** By the end of Day 7, you must be able to commit a fake AWS key to a public GitHub repo, watch BreachTrace detect it, collect real CloudTrail events, classify them, generate a Gemini report, display a D3 timeline — all in under 60 seconds — and show 200 detection accuracy + 35 pipeline run results to evaluators on a live Research dashboard.

**To Yash specifically — the research harness is your most important Day 6 task.** The logic is a loop with 4 function calls, a wait, and a DB write. The functions are designed above. The only parts that may feel unfamiliar are the GitHub API push (PyGitHub) and the AWS IAM key creation (boto3 IAM) — ask Ritwik to write those two API calls. You fill in the orchestration loop. 35 runs across 3 groups (12 + 13 + 10) is exactly the distribution that makes a meaningful research result. Do not deviate from the groups.

---

*— END OF ONE-WEEK SPRINT PLAN —*