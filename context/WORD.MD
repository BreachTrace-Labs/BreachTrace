**BREACHTRACE**

**One-Week AWS CloudTrail Forensic Sprint**

Complete End-to-End Pipeline Implementation Plan

**CHOSEN PLATFORM: AWS CloudTrail**

Richest forensic data · Most impressive demo · 100-200 detection tests via SecretBench · 35+ self-created pipeline runs

| **RITWIK**                                                  | **SHASHANK**                                              | **YASH**                                                          | **VEDANT**                                               |
| ----------------------------------------------------------- | --------------------------------------------------------- | ----------------------------------------------------------------- | -------------------------------------------------------- |
| FastAPI · Webhook CloudTrail Collector DB · Docker · Deploy | DB Schema · API Spec Taxonomy · Severity Paper + Analysis | AWS Regex Pattern Rule Classifier Research Harness Stats Analysis | React Dashboard D3 Timeline Gemini Reports Normalisation |

Guide: Dr. Irfan Siddavatam · K.J. Somaiya College of Engineering · Department of Information Technology

# SECTION 1 - PLATFORM SELECTION & DATASET STRATEGY

## 1.1 Why AWS CloudTrail

The evaluators require a **complete end-to-end flow** for one platform, validated across **100-200 credentials from public datasets** OR **30+ self-created experiment runs**. The chosen platform must maximise both evaluation criteria. AWS CloudTrail wins on every dimension.

| **Criterion**                   | **AWS CloudTrail**                                                          | **GitHub PAT**                      | **Stripe**                                       |
| ------------------------------- | --------------------------------------------------------------------------- | ----------------------------------- | ------------------------------------------------ |
| **Forensic data richness**      | ★★★★★ Full API call, source IP, resource, timestamp, success/fail per event | ★★★ Action type, repo, actor IP     | ★★★★ Event type, customer ID, amount             |
| **Demo impressiveness**         | ★★★★★ S3 access, EC2 spin-up, IAM escalation - all visible in real time     | ★★★ Repo clone, code access         | ★★★★ Fraudulent charges, customer data retrieval |
| **Public detection dataset**    | ★★★★★ SecretBench contains 1,000+ AWS key patterns from real GitHub repos   | ★★★★ GitHub PATs in SecretBench too | ★★ Fewer public stripe key samples               |
| **Self-experiment feasibility** | ★★★★★ 1 throwaway AWS account → 35 IAM keys → 35 full runs in 1 day         | ★★★★ Easy PAT rotation              | ★★★★★ Test mode instant                          |
| **Audit log API quality**       | ★★★★★ CloudTrail lookup_events: immediate, paginated, reliable              | ★★★ Audit Log needs org             | ★★★★ Stripe Events fast                          |
| **Academic citation**           | ★★★★★ AWS CloudTrail most referenced in security research                   | ★★★ GitHub also strong              | ★★★ Less cited                                   |

## 1.2 Dataset Strategy - Satisfying Both Evaluator Criteria

**The evaluators will be satisfied by two parallel data tracks. Both must be ready by Day 7.**

| **Track** | **What It Is**                                                                                    | **How You Get It**                                                                                                                                                                                                                                                                                                                    | **What You Report to Evaluators**                                                                                                                                                                             |
| --------- | ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **A**     | Detection accuracy across 100-200 real-format AWS key samples from the SecretBench public dataset | Download SecretBench dataset (Basak et al. 2023 - referenced in your project as \[5\]). It contains thousands of labelled code snippets from GitHub, many containing AWS access keys in AKIA... format. Extract 100-200 AWS key-containing snippets. Run your regex detector against them. Compare output to the ground-truth labels. | Precision: X%, Recall: X%, F1: X% across 100-200 real GitHub samples. This proves your detector generalises to real-world leaked credentials, not just test strings you wrote yourself.                       |
| **B**     | Full forensic pipeline runs: 35 complete experiments using self-created throwaway AWS IAM keys    | Create 1 throwaway AWS root account. Create 35 IAM access keys (or rotate the same user). Each experiment: commit key to public GitHub repo via harness → make controlled API calls from a second device → BreachTrace collects CloudTrail data → classifies → generates report → records result. Revoke key. Repeat.                 | 35 complete forensic pipeline runs. Metrics: time-to-detection (< 30s target), time-to-report (< 60s target), classification accuracy on controlled calls, blast radius distribution across the 35 scenarios. |

**📚 SecretBench - Where to Get It**

Paper: Basak, S.K. et al. (2023). 'A Comparative Study of Software Secrets Reporting by Secret Detection Tools.' ACM/IEEE ESEM 2023.

Dataset: <https://github.com/setu1421/SecretBench> (public GitHub repo, MIT licensed for research)

Contents: 97,479 true positive and 1,427,212 false positive code snippets - all manually labelled.

Your filter: grep for rows where secret_type = 'AWS' AND label = 'true_positive'. You will get 500+ rows.

Use 100-200 of these as your detection test set. Compare your regex output vs the ground-truth label.

This dataset is already cited in your project document as reference \[5\].

## 1.3 What 'Complete Flow' Means for the Evaluators

The evaluators need to see one platform's pipeline working fully - not a demo with fake data, not a stub with placeholders. The complete flow for AWS CloudTrail is:

| **1** | **GitHub Webhook fires within 30 seconds of commit**<br><br>• A real commit containing a fake AWS key (AKIA... format) is pushed to a public GitHub repository<br><br>• GitHub fires an HTTP POST to the BreachTrace webhook endpoint<br><br>• The webhook is received, the payload is validated, the commit diff is extracted<br><br>• The AWS key regex matches - CredentialMatch object created with type='aws_access_key', hint, timestamp |
| ----- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |

| **2** | **Exposure Window is recorded**<br><br>• Incident record written to PostgreSQL: incident_id, credential_hint (masked), repo_url, commit_hash, exposure_start (= commit timestamp), status='collecting'<br><br>• Revocation monitoring starts in background: every 60 seconds, check if the key is still valid (AWS STS GetCallerIdentity with the key - if it throws InvalidClientTokenId, key is revoked)<br><br>• When revocation detected: exposure_end is set in DB |
| ----- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |

| **3** | **AWS CloudTrail Forensic Collection runs**<br><br>• boto3 CloudTrail.lookup_events(LookupAttributes=\[{AccessKeyId: key_id}\], StartTime=exposure_start, EndTime=exposure_end)<br><br>• All API calls made with that key ID during the window are returned<br><br>• Each CloudTrail event is normalised into a ForensicEvent object: platform, timestamp, api_action, source_ip, affected_resource, success<br><br>• All events persisted to forensic_events table. Status updated to 'classifying' |
| ----- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |

| **4** | **Impact Classification runs on every event**<br><br>• Every ForensicEvent is passed through the rule-based classifier<br><br>• Each event gets: impact_category (one of 8 categories) + severity_weight (1-4)<br><br>• Bulk detection: if same api_action called 5+ times from same IP → escalate from data_access to exfiltration<br><br>• Status updated to 'scoring' |
| ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |

| **5** | **Severity Score computed**<br><br>• Overall severity computed from classified events using the escalation rules<br><br>• GDPR flag set if data_access or exfiltration events touch resources with PII-hinting names<br><br>• Status updated to 'reporting' |
| ----- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |

| **6** | **Gemini generates the forensic report**<br><br>• Classified events + severity + affected resources + source IPs → Gemini API prompt<br><br>• Gemini returns: plain English summary, chronological narrative, remediation checklist<br><br>• Report stored in incident record. Status updated to 'complete' |
| ----- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |

| **7** | **React Dashboard displays the complete report**<br><br>• Forensic timeline (D3.js): X-axis = time, events plotted as coloured circles by severity<br><br>• Blast Radius Summary: one AWS card showing event count + worst category<br><br>• Affected Resources: S3 buckets, EC2 instances, IAM entities listed<br><br>• Source IP Intelligence: IP geolocation, times used<br><br>• Gemini report: plain English narrative + numbered remediation checklist<br><br>• GDPR banner if flagged |
| ----- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |

# SECTION 2 - PRE-WEEK PREPARATION (DO THE NIGHT BEFORE DAY 1)

**Everything in this section must be done the evening before the week starts. If Day 1 begins with accounts still being created, you lose 4 hours. Do not let that happen.**

## 2.1 Accounts & Access

| **What to Create**                          | **Who Does It** | **Exact Steps + Notes**                                                                                                                                                                                                                                                                                                                                      |
| ------------------------------------------- | --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **AWS throwaway root account**              | Ritwik          | Go to aws.amazon.com → Create new account with a personal/throwaway email. Add a credit card (won't be charged with free tier). Enable billing alerts. Create IAM user with AdministratorAccess for day-to-day work. DO NOT use root account for anything except creating the admin IAM user. Note down: AWS Account ID, admin IAM user access key + secret. |
| **AWS restricted IAM user for experiments** | Ritwik          | In the AWS console, create a second IAM user: 'breachtrace-experiment'. Attach ONLY these policies: AmazonS3ReadOnlyAccess + AmazonEC2ReadOnlyAccess. Generate an access key for this user. This is the key that gets 'leaked' in experiments. It can only read S3 and EC2 - zero damage possible if actually exploited.                                     |
| **Enable CloudTrail in us-east-1**          | Ritwik          | AWS Console → CloudTrail → Create Trail → name='breachtrace-trail' → apply to all regions → S3 bucket for logs (auto-created). Ensure 'Management events' is ON and 'Read/Write events' is set to 'All'. This must be done BEFORE any experiments - events before trail creation are not logged.                                                             |
| **GitHub monorepo (private)**               | Ritwik          | Create on GitHub.com. Name: breachtrace. Add all teammates as collaborators. Set branch protection on main (require PR). Create the exact folder structure from Section 3.1 immediately.                                                                                                                                                                     |
| **Public GitHub test repo**                 | Ritwik          | Create a SEPARATE public GitHub repo called 'breachtrace-test-repo'. This is the repo where fake credentials get committed during experiments. It must be public for the webhook to fire and for the experiments to be realistic.                                                                                                                            |
| **SecretBench dataset**                     | Yash            | Go to <https://github.com/setu1421/SecretBench>. Clone or download the repo. Find the CSV/JSON file with labelled code snippets. Filter for secret_type = 'AWS' AND ground_truth = 'true'. Export 200 rows as a CSV. Save it as secretbench_aws_200.csv. This is your Track A test set.                                                                      |
| **Google Gemini API key**                   | Vedant          | Go to <https://aistudio.google.com/app/apikey>. Create API key. Test immediately with one API call (see Day 1 tasks). Free tier = 60 requests/minute, 1500 per day - more than enough.                                                                                                                                                                       |
| **Railway.app account**                     | Ritwik          | Sign up at Railway.app with GitHub login. Create a new project. Link it to the GitHub monorepo. This will be the production URL for the webhook. The GitHub webhook must point to this URL (not ngrok) for reliable operation.                                                                                                                               |
| **Netlify/Vercel account**                  | Vedant          | Sign up at Netlify.com with GitHub login. Will be used to deploy the React frontend. Can deploy from Day 3 onwards.                                                                                                                                                                                                                                          |
| **Postman (local)**                         | All             | Download Postman desktop app. You will use this to test every API endpoint before the frontend is built. Have it open from Day 1.                                                                                                                                                                                                                            |

## 2.2 .env File Template - Everyone Must Have This on Day 1

**📋 .env file - create this before Day 1 (NEVER commit this file to git)**

\# AWS (admin user - for CloudTrail queries and managing experiments)

AWS_ACCESS_KEY_ID=AKIA... # Admin IAM user key

AWS_SECRET_ACCESS_KEY=... # Admin IAM user secret

AWS_REGION=us-east-1

\# AWS Experiment User (this key gets 'leaked' - read-only only)

EXPERIMENT_AWS_ACCESS_KEY_ID=AKIA... # breachtrace-experiment user key

EXPERIMENT_AWS_SECRET_ACCESS_KEY=...

\# GitHub

GITHUB*TOKEN=ghp*... # Your personal admin PAT for fetching commit diffs

GITHUB_WEBHOOK_SECRET=... # Random 32-char string - you choose this

GITHUB_TEST_REPO=yourusername/breachtrace-test-repo

\# Gemini

GEMINI_API_KEY=...

\# Database

DATABASE_URL=postgresql://user:password@localhost:5432/breachtrace

\# App

ENVIRONMENT=development

**⚠️ Security Rules for the .env File**

1\. Add .env to .gitignore IMMEDIATELY on Day 1, before any git commit.

2\. The EXPERIMENT_AWS_ACCESS_KEY_ID key is deliberately read-only. Even if it gets accidentally committed or exploited, zero damage is possible.

3\. Never put a full-access AWS key in the .env file that gets committed anywhere.

4\. Ritwik reviews every PR to ensure no credentials appear in diffs.

# SECTION 3 - REPOSITORY STRUCTURE & SHARED SCHEMA

## 3.1 Monorepo Directory Layout (Ritwik creates on Day 1 morning)

**📁 breachtrace/ - create this exact structure before writing any code**

breachtrace/

├── backend/

│ ├── main.py ← FastAPI app: all routes + webhook endpoint (Ritwik)

│ ├── config.py ← Load .env vars, validate all required keys present (Ritwik)

│ ├── detector/

│ │ ├── \__init_\_.py

│ │ ├── patterns.py ← AWS regex patterns ONLY this week (Yash)

│ │ └── scanner.py ← Scans commit diff, returns CredentialMatch list (Ritwik stub, Yash logic)

│ ├── window/

│ │ ├── \__init_\_.py

│ │ └── calculator.py ← Exposure window: start/end, revocation check (Ritwik)

│ ├── collectors/

│ │ ├── \__init_\_.py

│ │ ├── base.py ← Abstract BaseCollector class (Ritwik)

│ │ └── aws.py ← AWS CloudTrail collector - the ONLY collector this week (Ritwik + Yash mapping)

│ ├── normalizer/

│ │ ├── \__init_\_.py

│ │ └── schema.py ← ForensicEvent + IncidentRecord Pydantic models (Shashank design, Vedant implements)

│ ├── classifier/

│ │ ├── \__init_\_.py

│ │ ├── taxonomy_aws.py ← AWS-only taxonomy as Python constants (Shashank design, Yash codes)

│ │ └── rules.py ← Rule-based classifier for AWS events (Yash)

│ ├── scorer/

│ │ ├── \__init_\_.py

│ │ └── severity.py ← Severity aggregation for AWS events (Shashank design, Ritwik codes)

│ ├── reporter/

│ │ ├── \__init_\_.py

│ │ └── gemini.py ← Gemini API report generation (Vedant)

│ ├── db/

│ │ ├── \__init_\_.py

│ │ ├── models.py ← SQLAlchemy ORM models (Shashank spec, Ritwik implements)

│ │ └── database.py ← DB engine, session factory (Ritwik)

│ ├── research/

│ │ ├── \__init_\_.py

│ │ ├── harness.py ← Automated experiment runner (Yash)

│ │ └── analysis.py ← Stats analysis of experiment results (Yash)

│ ├── tests/

│ │ ├── test_aws_pattern.py ← AWS key regex tests - Track A detection tests (Yash)

│ │ ├── test_secretbench.py ← 200-sample SecretBench accuracy test (Yash)

│ │ ├── test_aws_classifier.py ← Classifier unit tests (Yash)

│ │ └── test_pipeline.py ← Full E2E pipeline integration test (Ritwik)

│ └── requirements.txt

├── frontend/

│ ├── src/

│ │ ├── App.jsx ← Router setup (Vedant)

│ │ ├── pages/

│ │ │ ├── Dashboard.jsx ← Incidents list page (Vedant)

│ │ │ ├── IncidentDetail.jsx ← Full forensic report page (Vedant)

│ │ │ └── Research.jsx ← Track A + Track B results charts (Vedant)

│ │ ├── components/

│ │ │ ├── ForensicTimeline.jsx ← D3.js interactive timeline (Vedant)

│ │ │ ├── BlastRadiusSummary.jsx ← AWS platform card (Vedant)

│ │ │ ├── SeverityBadge.jsx ← Colour-coded severity indicator (Vedant)

│ │ │ ├── RemediationChecklist.jsx← Numbered remediation steps (Vedant)

│ │ │ └── AffectedResources.jsx ← S3/EC2/IAM resource list (Vedant)

│ │ └── api/

│ │ └── client.js ← Axios instance (Vedant)

│ └── package.json

├── data/

│ └── secretbench_aws_200.csv ← Track A test set (Yash downloads pre-week)

├── docker-compose.yml ← Backend + Postgres (Ritwik Day 5)

├── Dockerfile.backend ← Backend Docker image (Ritwik Day 5)

├── .env.example ← Template with all required keys (no values)

├── .gitignore ← Must include .env, \__pycache_\_, node_modules

└── README.md ← Shashank writes

## 3.2 The ForensicEvent Schema - Agreed Before Any Collector Code is Written

**Shashank designs this and commits it to schema.py on Day 1. Nobody writes collector code until schema.py is in the repo.**

**📐 ForensicEvent Pydantic Model - AWS-focused this week (Shashank designs, Vedant implements)**

class ForensicEvent(BaseModel):

event_id: str # UUID, auto-generated with uuid4()

platform: str # Always 'aws' this week

timestamp: datetime # EventTime from CloudTrail (UTC)

api_action: str # EventName from CloudTrail e.g. 'GetObject', 'RunInstances'

event_source: str # EventSource e.g. 's3.amazonaws.com', 'ec2.amazonaws.com'

source_ip: str | None # SourceIPAddress from CloudTrail

user_agent: str | None # UserAgent from CloudTrail

affected_resource: str | None # Resources\[0\].ResourceName (first resource)

resource_type: str | None # Resources\[0\].ResourceType: 'AWS::S3::Bucket' etc.

success: bool # True if ErrorCode is absent

error_code: str | None # ErrorCode if present (AccessDenied etc.)

raw_data: dict # Full original CloudTrail event dict (stored as JSONB)

\# Filled by classifier (Day 4):

impact_category: str | None # One of the 7 AWS categories

severity_weight: int | None # 1=Low 2=Medium 3=High 4=Critical

class IncidentRecord(BaseModel):

incident_id: str # UUID

credential_type: str # 'aws_access_key' this week

credential_hint: str # 'AKIA' + '\*\*\*\*' + last 4 chars ONLY

access_key_id: str # Full AKIA... key ID (NOT the secret) - needed for CloudTrail query

repo_url: str # e.g. 'github.com/user/breachtrace-test-repo'

commit_hash: str # 40-char SHA

exposure_start: datetime # Commit timestamp

exposure_end: datetime | None # When key was revoked (None = still open)

status: str # 'detecting'|'collecting'|'classifying'|'scoring'|'reporting'|'complete'

events: list\[ForensicEvent\] # All CloudTrail events found

overall_severity: str | None # 'Low'|'Medium'|'High'|'Critical'

report_text: str | None # Full Gemini report

remediation_steps: list\[str\] # Parsed from Gemini output

gdpr_flag: bool # True if personal data access detected

estimated_financial_impact: str | None # Computed from EC2 instances, data transfer

# SECTION 4 - DAY-BY-DAY IMPLEMENTATION PLAN

| **Day**         | **Primary Goal**                                                                                  | **End-of-Day Deliverable**                                |
| --------------- | ------------------------------------------------------------------------------------------------- | --------------------------------------------------------- |
| **Day 1 (Mon)** | Repo, schema, accounts, FastAPI skeleton, AWS CloudTrail enabled, SecretBench downloaded          | **FastAPI runs. Schema committed. AWS trail active.**     |
| **Day 2 (Tue)** | Webhook listener + AWS pattern detector working end-to-end. Commit diff → detection → DB write.   | **POST /webhook/github detects an AWS key live.**         |
| **Day 3 (Wed)** | AWS CloudTrail collector complete + integrated. Full pipeline: detect → collect → persist events. | **GET /incidents/{id} returns real CloudTrail events.**   |
| **Day 4 (Thu)** | Classifier + severity scorer + Gemini report generator. Full pipeline fires automatically.        | **Full report appears in DB under 60 seconds.**           |
| **Day 5 (Fri)** | React dashboard complete. D3 timeline live. Frontend deployed. Docker working.                    | **Live dashboard shows the full forensic report.**        |
| **Day 6 (Sat)** | Research harness runs 35+ experiments. Track A (SecretBench 200) detection test complete.         | **35+ rows in experiment_runs table. Accuracy computed.** |
| **Day 7 (Sun)** | Integration polish, demo rehearsal, evaluator presentation preparation.                           | **3-minute demo rehearsed x3. Backup slides ready.**      |

## Day 1 (Monday) - Environment, Schema, Accounts, Skeleton

**Goal:** Everyone leaves with a running environment, all accounts set up, the ForensicEvent schema committed to the repo, and zero ambiguity about who owns what. The AWS trail must be active today - events only log from when the trail is enabled.

| **DAY 1 - Foundation: repo, schema, AWS trail, environments**<br><br>_All four working in parallel from 9am_ | | | |
| --- | | | | --- | --- | --- |
| **RITWIK** | **SHASHANK** | **YASH** | **VEDANT** |
| • Create GitHub monorepo: exact folder structure from Section 3.1 | • Design and write the ForensicEvent + IncidentRecord Pydantic schema (Section 3.2) in a Notion doc first - 30 minutes - then confirm with team, then Vedant implements it | • Download SecretBench dataset from <https://github.com/setu1421/SecretBench> - save the CSV as data/secretbench_aws_200.csv | • Create React project: npm create vite@latest frontend -- --template react |
| • Create requirements.txt with ALL backend deps: fastapi, uvicorn, sqlalchemy, alembic, asyncpg, boto3, pydantic, google-generativeai, PyGithub, tenacity, python-dotenv, psycopg2-binary | • Write the complete DB table spec: incident_records columns, forensic_events columns, collection_status columns, experiment_runs columns - column names, types, nullability, indexes | • Open the CSV, understand the columns: snippet (code text), secret_type, ground_truth (true/false), line_number - these are the fields you will use | • Install: npm install axios react-router-dom d3 chart.js react-chartjs-2 |
| • Write config.py: loads .env, validates all keys present at startup (if any missing, print which ones and exit) | • Write the complete AWS taxonomy for taxonomy_aws.py: list every AWS API call you know of and which of 7 categories it belongs to. Use Claude to help - paste 'here are 7 categories, here are 50 AWS API action names, classify each' | • Filter for secret_type='AWS' AND ground_truth='true' - count how many rows exist. Target 200. If fewer, supplement with manual examples. | • Follow Tailwind CSS + Vite setup: <https://tailwindcss.com/docs/guides/vite> - exactly 4 steps |
| • Write FastAPI main.py: GET / returns {status:'ok', message:'BreachTrace running'} | • Target: 50+ AWS API calls mapped before Day 1 ends | • Write patterns.py: the AWS access key regex pattern. This week you only need ONE pattern: AKIA\[0-9A-Z\]{16}. But also detect the adjacent secret key on the next line. | • Create three page stubs: Dashboard.jsx, IncidentDetail.jsx, Research.jsx - each returns a styled &lt;div&gt; with the page title and a placeholder message |
| • Run: uvicorn main:app --reload - confirm it starts on port 8000 | • Write all API endpoint specs in Notion: GET /incidents, GET /incidents/{id}, GET /incidents/{id}/timeline, POST /test/simulate, GET /health - request format, response format, error cases | • Test the pattern on 10 real AKIA... strings from the SecretBench CSV - does it match all of them? | • Set up React Router in App.jsx: / → Dashboard, /incident/:id → IncidentDetail, /research → Research |
| • Install ngrok, create tunnel: ngrok http 8000 | • Write the README.md skeleton: title, problem, solution, tech stack, setup instructions with blanks | • Write the first 20 unit tests in test_aws_pattern.py: positive cases (real AKIA format), negative cases (similar-looking strings that should NOT match: BKIA..., AKIA123, etc.) | • Create api/client.js: Axios instance with baseURL = import.meta.env.VITE_API_URL, 30-second timeout, error logging |
| • Set up AWS admin IAM user, enable CloudTrail in us-east-1 (see Section 2.1) | • Create the Notion daily standup page | • Understand the ForensicEvent schema Shashank designed - read it carefully. You will be writing the map_cloudtrail_event() function tomorrow. | • Implement the ForensicEvent + IncidentRecord Pydantic schema in schema.py (from Shashank's Notion doc - implement exactly what he designed, don't improvise) |
| • Set up Railway.app project linked to monorepo | | | • Test Gemini API: import google.generativeai as genai, configure with GEMINI_API_KEY, call generate_content('Summarise this security event: GetObject called on S3 bucket'), print the response |
| • Add .gitignore: .env, \__pycache_\_, \*.pyc, node_modules, .env.local | | | • Confirm React app starts on localhost:3000 with no console errors |

**⚠️ Day 1 Hard Stops - Do Not Move to Day 2 Until All Are True**

✓ Ritwik: FastAPI runs on localhost:8000. Railway project created. AWS CloudTrail enabled in us-east-1.

✓ Shashank: ForensicEvent schema committed to schema.py. DB table spec written in Notion. 50+ AWS API calls mapped in taxonomy Notion doc.

✓ Yash: SecretBench CSV downloaded and filtered to 200 AWS rows. Pattern written. 20 unit tests written and passing.

✓ Vedant: React runs on localhost:3000. Axios client set up. Schema.py committed. Gemini API call returns a response.

✓ All: .gitignore has .env. No credentials in any committed file. Everyone can git pull and run the app.

## Day 2 (Tuesday) - Webhook Listener, Credential Scanner, DB Working

**Goal:** A real GitHub push containing a fake AWS key is detected within 30 seconds. The incident is written to the DB. GET /incidents returns it. This is the first milestone that proves the pipeline is real.

| **DAY 2 - Webhook + detector + DB write working end-to-end**<br><br>_First live detection of a fake AWS key_ | | | |
| --- | | | | --- | --- | --- |
| **RITWIK** | **SHASHANK** | **YASH** | **VEDANT** |
| • Build POST /webhook/github in main.py | • Implement DB models.py from your table spec - Ritwik will implement the SQLAlchemy code, but you verify it matches your spec exactly after he commits it | • Complete scanner.py logic (Ritwik writes the function signature and return type, you fill in the body): | • Build Dashboard.jsx: on component mount, fetch GET /incidents (useEffect + axios). Display in a table: incident ID (truncated), credential_hint, exposure_start (formatted as local time), overall_severity badge, status. |
| • Validate X-Hub-Signature-256 header: compute HMAC-SHA256 of raw request body using GITHUB_WEBHOOK_SECRET, compare to header value - reject with 401 if mismatch | • Write the revocation check logic as pseudocode: for AWS keys: call boto3.client('sts', aws_access_key_id=EXPERIMENT_KEY_ID, aws_secret_access_key=EXPERIMENT_SECRET).get_caller_identity() - if it succeeds, key is still valid; if it raises ClientError with code 'InvalidClientTokenId', key is revoked | • scan(diff_text: str) → list\[CredentialMatch\]: iterate all lines of diff_text, run the AWS key regex against each line, if match found: check if adjacent lines contain the secret key pattern, create CredentialMatch(type='aws_access_key', access_key_id=matched_key_id, hint='AKIA' + '\*\*\*\*' + last4, line_number=n) | • Build SeverityBadge.jsx: a styled span component that takes severity string as prop and returns: Low=green background, Medium=yellow, High=orange, Critical=red. Use Tailwind classes. |
| • Parse push event payload: extract repository.html_url, head_commit.id, head_commit.timestamp, commits array | • Write the full exposure window pseudocode: start = commit_timestamp. Every 60 seconds in a background loop, call the revocation check. When revoked: set exposure_end = now(). If never revoked: after 10 minutes, set exposure_end = now() (experiment timeout). | • Also implement false-positive reduction: AKIA key must be exactly 20 chars. Secret key (if found) must be exactly 40 chars. Reject if either fails length check. | • Build IncidentDetail.jsx stub: fetches GET /incidents/:id on mount, displays credential_hint, credential_type, exposure_start, exposure_end (if set), status. Leave timeline and events area as 'Loading events...' placeholder. |
| • For each commit: call GitHub REST API to fetch full diff text - use PyGitHub: Github(GITHUB_TOKEN).get_repo(repo_name).get_commit(sha).files - extract each file's .patch string, concatenate all patches into one diff_text string | • Expand the AWS taxonomy to 80+ entries today - focus on ALL S3 actions, ALL EC2 actions, ALL IAM actions. Assign each to one of the 7 categories with severity weights. | • Write test_secretbench.py: load secretbench_aws_200.csv, for each row call scanner.scan(snippet_text), compare result to ground_truth label, compute precision/recall/F1. Run it and record the accuracy numbers. | • Wire React Router: clicking a row in Dashboard navigates to /incident/{id}. |
| • Call scanner.scan(diff_text) → returns list of CredentialMatch objects | • Begin converting the Notion taxonomy table to taxonomy_aws.py Python dict. Use Claude to generate the initial Python code from your table. | • Target accuracy: Precision > 95%, Recall > 90%. If not achieved: identify which false positives are failing and improve the pattern or context logic. | • Empty state: if no incidents, Dashboard shows a styled empty state: 'No incidents detected yet. Connect your GitHub repository to begin monitoring.' |
| • For each CredentialMatch: create IncidentRecord in DB, trigger background collection task | | • Write 20 more unit tests in test_aws_pattern.py - bring total to 40+ | • Ensure frontend compiles clean: npm run build - zero errors. |
| • Build POST /test/simulate: accepts {repo_url, diff_text, credential_hint, access_key_id} - skips GitHub API, goes directly to scanner and then DB - critical for testing without real webhooks | | | |
| • Build GET /incidents and GET /incidents/{id} from Shashank's API spec | | | |
| • Set up PostgreSQL: implement DB models from Shashank's spec in models.py. Run Alembic init + first migration. | | | |
| • Add actual GitHub webhook to the public test repo: Settings → Webhooks → URL = ngrok/Railway URL + /webhook/github. Content type: application/json. Secret = GITHUB_WEBHOOK_SECRET. | | | |
| • LIVE TEST: commit a string 'AKIAIOSFODNN7EXAMPLE secret_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' to the test repo. Watch the webhook fire. Confirm incident appears in DB. | | | |

**📋 Day 2 Verification Test - Run This Manually**

Step 1: Open two terminal windows. Terminal 1: uvicorn main:app --reload. Terminal 2: watch the logs.

Step 2: In a browser, open Postman. Send POST /test/simulate with body: {repo_url: 'github.com/test/repo', diff_text: '+export AWS_KEY=AKIAIOSFODNN7EXAMPLE\\n+export AWS_SECRET=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', access_key_id: 'AKIAIOSFODNN7EXAMPLE'}

Step 3: Check Terminal 2 logs - should see 'AWS key detected: AKIA\*\*\*\*MPLE'

Step 4: In Postman, send GET /incidents. Should return a list with the new incident.

Step 5: Copy the incident_id. Send GET /incidents/{id}. Should return full record with status='collecting'.

If all 5 steps pass: Day 2 is complete.

## Day 3 (Wednesday) - AWS CloudTrail Collector Complete + Integrated

**Goal:** The AWS CloudTrail collector queries real CloudTrail events for the exposure window and returns real ForensicEvent objects. The full pipeline from webhook to events-in-DB is complete.

| **DAY 3 - CloudTrail collector integrated, real events in DB**<br><br>_The most critical engineering day of the week_ | | | |
| --- | | | | --- | --- | --- |
| **RITWIK** | **SHASHANK** | **YASH** | **VEDANT** |
| • Write collectors/base.py: abstract BaseCollector class with abstract method collect(access_key_id: str, exposure_start: datetime, exposure_end: datetime) -> list\[ForensicEvent\] | • Deploy to Railway.app: push the backend to main branch. Railway should auto-deploy. Get the live HTTPS URL. | • Write map_cloudtrail_event(raw_event: dict) -> ForensicEvent in aws.py: | • Build AffectedResources.jsx: accepts a list of ForensicEvent objects, groups them by resource_type ('AWS::S3::Bucket', 'AWS::EC2::Instance', 'AWS::IAM::AccessKey'), displays a card per resource type showing the resource names and event counts. |
| • Write collectors/aws.py - AWSCollector(BaseCollector) - the single most important file this week: | • Update the GitHub webhook on the test repo to point to the Railway URL instead of ngrok. | • raw_event\['EventTime'\] → timestamp (use datetime.fromisoformat or datetime.fromtimestamp) | • Wire IncidentDetail.jsx to real API data: fetch GET /incidents/:id/timeline (ask Ritwik to add this endpoint today - it returns ForensicEvents sorted by timestamp). Display events in a scrollable table: timestamp \| api_action \| event_source \| source_ip \| affected_resource. |
| • boto3.client('cloudtrail', region_name=AWS_REGION, aws_access_key_id=ADMIN_KEY_ID, aws_secret_access_key=ADMIN_SECRET) | • Write the collection_status table migration: per-incident, per-platform record of: platform, status (success/error/no_activity), event_count, error_message, queried_at | • raw_event\['EventName'\] → api_action | • Build ForensicTimeline.jsx skeleton: this component accepts events\[\] prop. For now, render a simple HTML timeline using &lt;div&gt; elements (NOT D3 yet - D3 comes Day 5). Show each event as a horizontal bar with platform colour. |
| • Call lookup_events(LookupAttributes=\[{'AttributeKey':'AccessKeyId','AttributeValue':access_key_id}\], StartTime=exposure_start, EndTime=exposure_end, MaxResults=50) | • Add this status tracking to the GET /incidents/{id} response | • raw_event\['EventSource'\] → event_source (e.g. 's3.amazonaws.com') | • Add status progress indicator to IncidentDetail: show the pipeline status ('detecting → collecting → classifying → reporting → complete') as a horizontal step indicator at the top of the page. |
| • Loop: while True: process events; if 'NextToken' in response: call again with NextToken; else: break | • Verify the DB migration works cleanly on Railway's PostgreSQL (Railway gives free PostgreSQL) | • raw_event\['SourceIPAddress'\] → source_ip | • Deploy the React frontend to Netlify/Vercel: follow the deployment docs, set VITE_API_URL env variable to the Railway backend URL. |
| • For each raw event: call Yash's map_cloudtrail_event(event) → ForensicEvent | • Review Yash's map_cloudtrail_event() implementation - does every field map correctly? Test with a real CloudTrail event dict from the AWS docs. | • raw_event\['UserAgent'\] → user_agent | |
| • Wrap entire function in tenacity @retry(wait=wait_exponential(multiplier=1, min=2, max=30), stop=stop_after_attempt(5)) | • Complete taxonomy_aws.py: minimum 80 entries. Commit to repo. | • raw_event\['Resources'\]\[0\]\['ResourceName'\] → affected_resource (if Resources list is non-empty) | |
| • Implement the parallel orchestrator in main.py: after detection, fire AWSCollector in a FastAPI BackgroundTask - NOT blocking the webhook response | • Write the severity algorithm pseudocode for severity.py: input = list of ForensicEvents with impact_categories filled. Output = 'Low' \| 'Medium' \| 'High' \| 'Critical'. Include all escalation rules. | • raw_event\['Resources'\]\[0\]\['ResourceType'\] → resource_type (if present) | |
| • Implement window/calculator.py: start_exposure(incident_id), check_revocation(access_key_id) → bool, close_window(incident_id) using the pseudocode Shashank wrote | | • raw_event.get('ErrorCode') → error_code; success = (error_code is None) | |
| • LIVE TEST: Use the EXPERIMENT_AWS_ACCESS_KEY_ID. From a second terminal, run: aws s3 ls (using the experiment key). Then trigger a simulated incident with that key_id. Wait 2 minutes. Call GET /incidents/{id}. Confirm events appear in the response. | | • event_id = str(uuid4()) | |
| • If CloudTrail delay is longer than expected: use a wider time window in lookup_events (start - 30 minutes, end + 15 minutes) to catch events with delivery lag. | | • platform = 'aws' | |
| | | • raw_data = raw_event (full dict) | |
| | | • Write 30 unit tests in test_aws_classifier.py using real-format CloudTrail event dicts from AWS docs: copy an S3 GetObject event JSON, test that map_cloudtrail_event returns the right ForensicEvent. Do the same for EC2 RunInstances, IAM CreateAccessKey, etc. | |
| | | • Run pytest tests/test_aws_pattern.py - all must pass. Run test_secretbench.py - record the accuracy numbers. | |

**🔍 CloudTrail Technical Notes for Ritwik - Critical Details**

CloudTrail lookup_events by AccessKeyId: pass the full AKIA... key ID (NOT the secret). boto3 will use your ADMIN credentials to make the lookup query.

Time to event delivery: CloudTrail typically delivers management events within 15 minutes. For the experiment, set EndTime = exposure_end + 20 minutes to catch late-delivered events.

The experiment key (EXPERIMENT_AWS_ACCESS_KEY_ID) is read-only - it can only call S3:List\* and EC2:Describe\*. CloudTrail will still log these calls.

Test immediately: from your second device, run 'aws s3 ls --profile experiment' after setting up a named profile. Check CloudTrail console in 15 minutes to confirm the event appears. Only then will the collector work.

Rate limiting: CloudTrail lookup_events allows 1 request per second per account. The tenacity retry handles this.

EventSource field in CloudTrail: this tells you which AWS service was called. Always include it in the ForensicEvent - it's needed for taxonomy classification (e.g., 's3.amazonaws.com' + 'GetObject' → data_access).

## Day 4 (Thursday) - Classifier, Severity Scorer, Gemini Report

**Goal:** Every CloudTrail event gets classified. The incident gets a severity score. Gemini generates a readable report with a remediation checklist. The full pipeline fires automatically end-to-end within 60 seconds.

| **DAY 4 - Intelligence engine: classify → score → report**<br><br>_The pipeline becomes complete and fully automatic_ | | | |
| --- | | | | --- | --- | --- |
| **RITWIK** | **SHASHANK** | **YASH** | **VEDANT** |
| • Wire the intelligence pipeline into main.py: after AWSCollector.collect() finishes and events are persisted to DB, automatically fire Yash's classify_all_events(incident_id) as a BackgroundTask | • Implement severity.py from your pseudocode spec - this is pure Python, no APIs: | • Build classifier/rules.py - this is your primary contribution this week: | • Build reporter/gemini.py - the generate_report(incident: IncidentRecord) -> str function: |
| • After classification: automatically fire Shashank's score_incident(incident_id) | • def score_incident(events: list\[ForensicEvent\]) -> str: | • classify_event(event: ForensicEvent) -> tuple\[str, int\]: | • Build the prompt using a multi-section string: |
| • After scoring: automatically fire Vedant's generate_report(incident_id) | • Get all distinct categories: categories = {e.impact_category for e in events if e.impact_category} | • Step 1: Look up exact api_action in taxonomy_aws.CATEGORY_RULES\[event.platform\]. Return if found. | • Section 1 (context): credential type, repo URL, exposure start + end, duration in human-readable format (e.g. '4 minutes 23 seconds') |
| • Each step updates the incident status field: collecting → classifying → scoring → reporting → complete | • If any of {'privilege_escalation', 'exfiltration', 'code_compromise'} in categories: return 'Critical' | • Step 2: If not found, apply prefix heuristics: action starts with 'List' or 'Describe' → ('reconnaissance', 1). Starts with 'Get' (single call) → ('data_access', 2). Starts with 'Put' or 'Create' (non-IAM) → ('resource_abuse', 3). Starts with 'Delete' → ('resource_abuse', 3). | • Section 2 (events): list of events as 'TIMESTAMP - EventName from SOURCE_IP on RESOURCE (severity: CATEGORY)' |
| • Implement the GET /incidents/{id}/timeline endpoint: returns all ForensicEvents for an incident sorted by timestamp, with impact_category and severity_weight filled | • max_weight = max(e.severity_weight or 0 for e in events) | • Step 3: Special overrides regardless of lookup: 'CreateAccessKey' or 'AttachUserPolicy' or 'AddUserToGroup' or 'PutRolePolicy' → always ('privilege_escalation', 4). 'RunInstances' or 'CreateCluster' → always ('resource_abuse', 3). | • Section 3 (stats): total events, platforms affected, highest severity category seen |
| • Implement PATCH /incidents/{id}: accepts partial update to store report_text, remediation_steps, gdpr_flag after Gemini generates them | • If 'financial_abuse' in categories and max_weight >= 3: return 'Critical'; elif 'financial_abuse': return 'High' | • Step 4: Fallback → ('reconnaissance', 1) | • Instruction to Gemini: 'Generate a forensic incident report in four sections: (1) Executive Summary (1 paragraph, plain English, no jargon), (2) Chronological Narrative (what the attacker did, step by step), (3) Business Impact Assessment, (4) Remediation Checklist (number each item, start each with ☐, be specific - include exact resource names).' |
| • Time the full pipeline: from POST /test/simulate to status='complete' - must be under 60 seconds. Log timing per stage. | • Map: max_weight 4→'Critical', 3→'High', 2→'Medium', 1→'Low', 0→'Low' | • Write classify_all_events(incident_id: str, db) function: fetches all ForensicEvents, calls classify_event() on each, updates impact_category + severity_weight in DB for each | • Parse the response: extract the numbered/checkbox items from Section 4 as a list of strings → store as remediation_steps |
| • Build the GDPR flag check: after classification, scan affected_resource strings for keywords 'user', 'customer', 'pii', 'email', 'personal', 'private' - if any data_access or exfiltration event hits these, set gdpr_flag=True | • Also implement: def compute_financial_impact(events: list\[ForensicEvent\]) -> str: look for RunInstances events (EC2 cost), GetObject with large resources (data transfer), return a formatted string like 'EC2: 2x t2.micro at \$0.02/hr. Data transfer: estimated \$0.20' | • Implement bulk detection escalation: after classifying all events, check: if same api_action called 5+ times from same source_ip in same incident and current category is 'data_access' → update all those events to ('exfiltration', 4) | • Call PATCH /incidents/{id} to store report_text + remediation_steps + gdpr_flag |
| | • Write 15 tests for severity.py: different category combinations → assert correct output | • Run test_aws_classifier.py - target: all 30+ tests passing | • Build RemediationChecklist.jsx: styled checklist component, each item as a checkbox row with the step text |
| | • Review Yash's classifier output on 3 real incidents - are the categories correct? | • Run the Track A test (SecretBench 200) → record final precision/recall/F1 numbers | • Test generate_report on one real incident where Ritwik's pipeline ran. Print the output and read it - is it clear and useful? Adjust the prompt if not. |
| | • Finalize all 80+ taxonomy entries in taxonomy_aws.py - this is committed to repo today. | | |

**💡 Gemini Prompt Engineering Notes for Vedant - What Makes a Good Report**

Add to the prompt: 'The audience is a developer with no security background. Avoid acronyms like MITRE, TTPs, CVE. Use plain language.'

Add: 'If any resource name contains words like users, customers, email, pii - flag this explicitly as a GDPR notification requirement in the Executive Summary.'

Add: 'Keep the entire report under 400 words. Be specific about resource names - use the exact resource names provided.'

Add: 'In the Remediation Checklist, include the exact AWS CLI command to terminate an EC2 instance or disable an IAM key where applicable.'

Model to use: gemini-1.5-flash (not Pro - Flash is faster and the free tier is more generous).

If Gemini returns an error: build a template-based fallback that generates the report from structured event data without calling Gemini - this ensures the pipeline never fails due to Gemini API issues.

## Day 5 (Friday) - React Dashboard, D3 Timeline, Docker, Full Demonstration

**Goal:** The full pipeline result is visible in a polished React dashboard. The D3 forensic timeline works. Docker brings up the whole stack. The team runs a complete demo for themselves for the first time.

| **DAY 5 - Full frontend, Docker, internal demo**<br><br>_The first time the complete system runs end-to-end with a real UI_ | | | |
| --- | | | | --- | --- | --- |
| **RITWIK** | **SHASHANK** | **YASH** | **VEDANT** |
| • Write Dockerfile.backend: FROM python:3.11-slim, COPY requirements.txt, RUN pip install, COPY . ., CMD uvicorn main:app --host 0.0.0.0 --port 8000 | • Internal demo: watch Ritwik's full pipeline run. Take notes on what works and what is broken. | • Verify the full classifier pipeline on a real incident: open the DB, check every ForensicEvent for the most recent incident - does every event have impact_category and severity_weight filled? | • Build the real D3.js ForensicTimeline.jsx - follow these steps exactly: |
| • Write docker-compose.yml: service 'backend' (uses Dockerfile.backend) + service 'db' (postgres:15-alpine). Backend depends_on db. Environment variables from .env file. | • Review all classified events from the pipeline run: open the DB and check 10 events - are impact_category and severity_weight correct for each? | • Fix any classification bugs found | • Step 1: In the component, import \* as d3 from 'd3'. Use useRef() for the SVG container. Use useEffect() that runs when props.events changes. |
| • Test: docker-compose up - backend starts, DB starts, migrations run, GET /health returns 200 | • If any misclassifications: update taxonomy_aws.py and push a fix | • Begin harness.py implementation (for Day 6): | • Step 2: Inside useEffect: clear any existing SVG children (d3.select(ref.current).selectAll('\*').remove()). Append a new &lt;g&gt; element with margin offsets. |
| • Run the full pipeline E2E: real GitHub push to test repo → webhook fires to Railway URL → AWS key detected → CloudTrail queried → events classified → Gemini report generated → status=complete. Time it. Log each stage time. | • Review the Gemini report: is it readable? Does the remediation checklist make sense? Give Vedant specific feedback. | • Function 1: push_fake_credential(access_key_id, secret_key): uses PyGitHub to create/update a file in the test repo named 'config.env' with content 'AWS_ACCESS_KEY_ID={key}\\nAWS_SECRET_ACCESS_KEY={secret}'. This is the automated push without needing manual git commits. | • Step 3: X-axis = time scale. d3.scaleTime().domain(\[exposure_start, exposure_end \| new Date()\]).range(\[0, innerWidth\]). |
| • Target: < 60 seconds total. If not: identify the slow stage. Likely: CloudTrail delivery lag (fix: widen the time window) or Gemini API (fix: run report generation in background and show partial report). | • Write paper Section 3 first draft (System Design): describe the 8-module architecture, what each module inputs/outputs. Use the architecture diagram from the project document. Target 500 words in Google Docs. | • Function 2: simulate_attacker_activity(access_key_id, secret_key): creates a boto3 session using the experiment key and makes 3 calls: s3.list_buckets(), ec2.describe_instances(), sts.get_caller_identity(). These simulate the 'attacker' actions that CloudTrail will log. | • Step 4: Y-axis = event_source (for AWS: s3.amazonaws.com, ec2.amazonaws.com, iam.amazonaws.com, sts.amazonaws.com). d3.scaleBand().domain(unique_sources).range(\[0, innerHeight\]).padding(0.2). |
| • Add GET /incidents/stats endpoint: total incident count, counts by overall_severity, average exposure_duration_seconds, most common impact_category | • Ensure the DB on Railway has all migrations applied: Railway → your project → Postgres → connect and run 'alembic upgrade head' | • Function 3: delete_credential_from_repo(): deletes the config.env file from the test repo (simulates revocation on the GitHub side) | • Step 5: Draw circles: svg.selectAll('circle').data(events).join('circle').attr('cx', d=>xScale(d.timestamp)).attr('cy', d=>yScale(d.event_source)+bandWidth/2).attr('r',8).attr('fill', d=>severityColor(d.severity_weight)). |
| • Final Railway deployment: confirm auto-deploy on git push is working | • Confirm experiment_runs table exists with all required columns | • Function 4: revoke_iam_key(access_key_id): calls boto3 IAM with admin credentials to delete the experiment key. This closes the exposure window. | • Step 6: Add tooltip: on mouseover show a floating div with: timestamp \| api_action \| source_ip \| affected_resource \| impact_category. |
| | | • These 4 functions are all that Day 6 needs to run 35 experiments. | • Step 7: Draw the X axis (d3.axisBottom) and Y axis (d3.axisLeft with service names abbreviated). |
| | | • Write test_pipeline.py: integration test that calls POST /test/simulate, waits 90 seconds, calls GET /incidents/{id} and asserts status='complete' and events are classified | • Wire to IncidentDetail.jsx: fetch GET /incidents/:id/timeline, pass events array to ForensicTimeline |
| | | | • Build BlastRadiusSummary.jsx: single AWS card showing: total_events, worst_category, severity badge, a small bar showing event counts per category |
| | | | • Full IncidentDetail page final layout: header (credential hint, duration, severity badge) → status bar → Gemini report → ForensicTimeline → BlastRadiusSummary → AffectedResources → RemediationChecklist → GDPR banner (if flagged) |

**✅ Day 5 End-of-Day Internal Demo - Run This With the Full Team**

Scenario: Push a fake AWS key to the test repo. On a second laptop: run 3 AWS CLI commands using the experiment key (aws s3 ls, aws ec2 describe-instances, aws s3 cp). Wait for the pipeline to complete. Open the dashboard.

What you must be able to show:

• Dashboard lists the new incident within 30 seconds of the commit

• IncidentDetail shows the D3 timeline with 3 events plotted

• BlastRadiusSummary shows: Reconnaissance (2 events) + Data Access (1 event)

• Gemini report: readable summary saying 'Your AWS key was exposed. 3 reconnaissance calls were made.'

• Remediation checklist: at least 3 specific steps

• GDPR flag: not triggered (S3 list and EC2 describe do not access personal data)

If this demo works cleanly, you have a complete MVP. Days 6-7 are polish and research data.

## Day 6 (Saturday) - Research Harness: 35+ Experiments + Track A Evaluation

**Goal:** 35+ fully automated forensic pipeline experiments complete with results in the DB. Track A (SecretBench 200) detection accuracy numbers finalised. All research data ready for the evaluators.

| **DAY 6 - Research data sprint**<br><br>_35 automated experiment runs + Track A final numbers_ | | | |
| --- | | | | --- | --- | --- |
| **RITWIK** | **SHASHANK** | **YASH** | **VEDANT** |
| • Help Yash run the research harness - specifically: manage the AWS IAM key rotation | • Write GET /research/export endpoint: returns all rows from experiment_runs as JSON (and optionally CSV via ?format=csv query param). Fields: credential_type, exposure_start, first_external_use_timestamp (null if no external use), time_to_detection_seconds, time_to_report_seconds, impact_categories_seen (JSONB array), overall_severity, source_ips_seen (JSONB array) | • Complete and run harness.py - this is your primary task today. The full experiment loop: | • Build Research.jsx page with real data from /research/export: |
| • Strategy for 35 IAM keys: create 1 IAM user 'experiment-user-1'. For each experiment run: create a new IAM access key for that user (AWS allows up to 2 active keys per user - delete the old one each time). So the sequence is: create key → run experiment → delete key → repeat. | • During the harness runs: manually track which experiments show external (non-team) API calls vs only the team's simulated attacker calls. Flag these in the experiment record. | • Loop 35 times: | • Chart 1 (Bar): pipeline timing - two bars per metric: 'Time to Detection' and 'Time to Report'. Show mean ± stdev. The target lines (30s and 60s) shown as horizontal reference lines. |
| • Write a helper script (research/key_manager.py): create_experiment_key() → returns (access_key_id, secret_access_key). delete_experiment_key(key_id). This is what the harness calls. | • After 35 runs: immediately compute preliminary statistics: mean and median time_to_detection_seconds, mean and median time_to_report_seconds, distribution of overall_severity across 35 runs | • 1. Call key_manager.create_experiment_key() → (key_id, secret) | • Chart 2 (Doughnut): blast radius severity distribution across 35 runs - how many were Low/Medium/High/Critical |
| • Monitor the full harness run: watch for errors, confirm each experiment writes a complete row to experiment_runs table | • Write a research summary in Notion: the headline numbers. This is what you present to evaluators. | • 2. Record experiment_start = datetime.now() | • Chart 3 (Stacked Bar): impact categories seen per experiment group (Group A: single calls, Group B: bulk calls, Group C: minimal) - shows how attacker behaviour affects blast radius |
| • If any run fails: debug immediately. Target: 35 successful complete runs by end of day. | • Begin paper Section 5 (Evaluation): describe the experiment methodology, the experimental setup, the 35-run design, what each field in experiment_runs means | • 3. Call push_fake_credential(key_id, secret) to commit it to the test repo | • Track A Box: a metric card showing 'Detection Accuracy on 200 Public Samples: Precision X% \| Recall X% \| F1 X%' |
| • After 35 runs: verify the data in DB: SELECT \* FROM experiment_runs - confirm all fields populated correctly for each row | | • 4. Wait 60 seconds (time for webhook + CloudTrail to process) | • Track B Box: a metric card showing '35 Full Pipeline Runs: Avg Detection Time X.Xs \| Avg Report Time X.Xs' |
| | | • 5. Call simulate_attacker_activity(key_id, secret) - makes 3 API calls with the experiment key | • Add a 'Download Report' button on IncidentDetail: calls window.print() with a print CSS that hides sidebar/nav and prints only the incident report section cleanly |
| | | • 6. Wait 120 seconds more (time for CloudTrail delivery + pipeline to complete) | • Final polish pass: check that all pages look professional on 1280px wide screen |
| | | • 7. Call GET /incidents?access_key_hint=... to find the incident created by step 3 | |
| | | • 8. Wait for incident status = 'complete' (poll every 10 seconds, max 3 minutes) | |
| | | • 9. Record: time_to_detection (webhook fired - push_fake_credential time), time_to_report (complete - push_fake_credential time), impact_categories, overall_severity | |
| | | • 10. Call key_manager.delete_experiment_key(key_id) - revoke the credential | |
| | | • 11. Call delete_credential_from_repo() - remove from test repo | |
| | | • 12. Wait 30 seconds. Repeat. | |
| | | • Write all results to experiment_runs table via POST /research/record endpoint | |
| | | • Vary the 3 API calls across experiments: Run 1-12: ListBuckets + DescribeInstances + GetCallerIdentity. Run 13-25: ListBuckets (×5) to trigger bulk detection. Run 26-35: DescribeInstances + GetCallerIdentity only (minimal activity). This creates variation in blast radius severity across the 35 runs. | |
| | | • Also: run analysis.py after 35 runs: load experiment data, compute mean/median/stdev for time_to_detection and time_to_report. Run test_secretbench.py one final time and record the accuracy. | |

**📊 Experiment Variation Design - Yash's 35 Runs Breakdown (important for the paper)**

Runs 1-12 (Standard Reconnaissance): simulate_attacker calls: ListBuckets + DescribeInstances + GetCallerIdentity. Expected classification: reconnaissance × 3. Expected severity: Low.

Runs 13-25 (Bulk Data Access Simulation): simulate_attacker calls: ListBuckets + GetObject × 5 (same object). Expected: data_access escalated to exfiltration. Expected severity: Critical. This tests the bulk detection rule.

Runs 26-35 (Minimal Activity): simulate_attacker calls: GetCallerIdentity only. Expected: reconnaissance × 1. Expected severity: Low.

This variation creates 3 distinct blast radius scenarios across 35 runs - making the research data meaningful for the paper's Section 6 (Evaluation) and the evaluators' review.

The distribution you will report: ~34% Low (runs 26-35 + some 1-12), ~34% Medium (runs 1-12 partial), ~33% Critical (runs 13-25).

## Day 7 (Sunday) - Integration Polish, Demo Rehearsal, Evaluator Preparation

**Goal:** The system is demo-ready. The 3-minute demo is rehearsed to perfection. Every page loads. Every number is accurate. Backup slides exist in case of technical failure.

| **DAY 7 - Polish + rehearsal + evaluator prep**<br><br>_Everything ready for the evaluator presentation_ | | | |
| --- | | | | --- | --- | --- |
| **RITWIK** | **SHASHANK** | **YASH** | **VEDANT** |
| • Run the full E2E pipeline 5 times from scratch and log: detection latency and report latency for each. Compute mean. Both must be under their targets (30s and 60s). | • Compile all research numbers into a single summary table: | • Final test run: pytest tests/ - all tests must pass | • Full end-to-end UI test: open the deployed Netlify URL on a different device. Click through every page. Report any bugs. |
| • Fix the 3 most critical bugs found during Day 5/6 | • Track A: 200 SecretBench samples. Precision: X%. Recall: X%. F1: X%. | • Run analysis.py one final time on the 35-experiment dataset. Print the clean results table. | • Ensure all charts on Research.jsx are rendering with real data (not empty or showing errors) |
| • Write the demo setup checklist (Section 6 of this document) - turn it into a runnable script that prepares the environment | • Track B: 35 pipeline runs. Mean time to detection: X seconds. Mean time to report: X seconds. Severity distribution: Low X%, Med X%, High X%, Critical X%. | • Write the Track A summary: 'BreachTrace detected X of 200 real-world AWS key samples correctly. False positives: X. These false positives occurred because \[explain why - e.g., test keys that match the format but are placeholder examples\].' | • Add a 'Last updated' timestamp to the dashboard header - shows evaluators the system is live |
| • Prepare: one pre-loaded incident in the DB from a real pipeline run. This is the 'backup incident' shown if the live demo has issues. | • Classification accuracy on 30 controlled events (from Yash's test_aws_classifier.py): X%. | • Prepare the research narrative for Demo Minute 3 | • Take 10 high-quality screenshots of the system: (1) Dashboard with incident list, (2) IncidentDetail header, (3) D3 timeline with events, (4) Gemini report section, (5) Remediation checklist, (6) Blast radius summary, (7) Affected resources, (8) Research page with charts, (9) Track A metric card, (10) Track B metric card |
| • Ensure the GitHub test repo has the webhook pointing at Railway. Test: commit something, confirm webhook fires. | • BreachTrace time vs manual time: BreachTrace = X seconds. Manual (estimate based on checking CloudTrail console + writing a report) = 45 minutes minimum. | • Code cleanup: remove print() debug statements, remove any hardcoded values, ensure all values come from config.py | • Ensure the print-to-PDF button works cleanly on Chrome |
| • Final Railway health check: GET /health → 200. All endpoints responding. | • Rehearse the guide pitch: 90 seconds, exactly the words from Section 6.3 | | |
| • Record a 90-second screen recording of the dashboard showing a complete incident report - this is the ultimate fallback if the live demo completely fails. | • Rehearse the 'research finding' minute of the demo (Minute 3) | | |
| | • Prepare 5 backup slides: (1) architecture diagram, (2) complete forensic report screenshot, (3) D3 timeline screenshot, (4) research results table, (5) the live demo incident in case the live demo fails | | |

**✅ Week Exit Criteria - All Must Pass Before Evaluator Presentation**

1\. AWS key detected in a real GitHub push within 30 seconds.

2\. CloudTrail events collected and present in DB as ForensicEvent objects with all fields populated.

3\. Every event has impact_category and severity_weight assigned correctly.

4\. Overall incident severity correctly computed using the escalation rules.

5\. Gemini report is readable, specific to the actual events, includes remediation checklist.

6\. D3 timeline renders correctly with real events - tooltips work on hover.

7\. Full pipeline completes in under 60 seconds from detection to status=complete.

8\. Track A: 200 SecretBench samples tested. Precision ≥ 90%. Report ready.

9\. Track B: 35 complete pipeline runs in experiment_runs table. Statistics computed.

10\. Docker-compose up starts the entire system cleanly.

11\. Research.jsx shows real Track A and Track B numbers in charts.

12\. 3-minute demo rehearsed at least 3 times by the presenting member.

# SECTION 5 - TECHNICAL IMPLEMENTATION DETAILS

## 5.1 AWS Taxonomy - taxonomy_aws.py (Shashank designs, Yash implements)

This is the complete specification for taxonomy_aws.py. Every entry maps an AWS API action name to an impact category and severity weight.

| **Wt** | **Category**             | **AWS API Actions → must be in taxonomy**                                                                                                                                                                                                                    | **Notes for classifier**                                                                                                                                                                 |
| ------ | ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **1**  | **reconnaissance**       | ListBuckets, ListObjects, DescribeInstances, DescribeSecurityGroups, DescribeVpcs, ListUsers, ListGroups, ListRoles, ListPolicies, GetCallerIdentity, DescribeRegions, ListFunctions, ListTables, DescribeLoadBalancers, GetAccountSummary, DescribeClusters | Any List\* or Describe\* call. The attacker is mapping the account. Low severity individually, but establishes presence.                                                                 |
| **2**  | **data_access**          | GetObject, GetItem, GetSecretValue, DescribeSecret, HeadObject, GetBucketPolicy, GetBucketAcl, GetRolePolicy, GetUserPolicy, GetGroupPolicy, GetBucketTagging, ListObjectVersions, GetObjectTagging, SelectObjectContent                                     | Single Get\* call on a specific resource. If same GetObject called 5+ times on the same or different keys from the same IP → escalate to exfiltration.                                   |
| **4**  | **exfiltration**         | GetObject (×5+ or file >100MB), SyncObjects, CopyObject (large batch), ExportTableToPointInTime, CreateExportTask, BatchGetItem (large), SelectObjectContent (data scan)                                                                                     | Bulk retrieval. Yash implements: if GetObject appears 5+ times from same source_ip in same incident → reclassify ALL those events to exfiltration.                                       |
| **3**  | **resource_abuse**       | RunInstances, StartInstances, CreateLoadBalancer, AllocateAddress, CreateSnapshot, CreateImage, CreateCluster, CreateFunction, CreateTable, ImportSnapshot, BundleInstance, RequestSpotInstances                                                             | Attacker is using the account's compute. EC2 spin-up is the clearest signal. Note: TerminateInstances by the attacker after their use is also resource_abuse (they're covering tracks).  |
| **4**  | **privilege_escalation** | CreateAccessKey, DeleteAccessKey, AttachUserPolicy, DetachUserPolicy, AttachRolePolicy, PutUserPolicy, PutRolePolicy, AddUserToGroup, CreateRole, CreateUser, UpdateAccessKey, SetDefaultPolicyVersion, AssumeRole (with new principal)                      | The most critical category. Any IAM modification = privilege escalation. Always weight 4. Always triggers Critical severity minimum.                                                     |
| **3**  | **financial_abuse**      | RunInstances (high instance count), CreateCluster (GPU), RequestSpotInstances (bulk), CreateDBInstance (RDS), CreateDomain (ElasticSearch)                                                                                                                   | AWS financial abuse manifests as large compute creation. Different from resource_abuse in scale - use count threshold: 5+ instances = financial_abuse. Single instance = resource_abuse. |
| **2**  | **communication_abuse**  | Publish (SNS), SendMessage (SQS), SendEmail (SES), SendRawEmail, SendBulkTemplatedEmail                                                                                                                                                                      | AWS messaging/email services used to send spam or phishing.                                                                                                                              |

## 5.2 DB Schema (Shashank's specification for Ritwik to implement)

**📦 PostgreSQL Tables - Shashank designs, Ritwik implements in models.py**

TABLE: incident_records

incident_id UUID PRIMARY KEY DEFAULT gen_random_uuid()

credential_type VARCHAR(50) NOT NULL -- 'aws_access_key'

credential_hint VARCHAR(20) NOT NULL -- 'AKIA\*\*\*\*MPLE'

access_key_id VARCHAR(30) -- full AKIA... key ID (not secret)

repo_url TEXT NOT NULL

commit_hash VARCHAR(40)

exposure_start TIMESTAMPTZ NOT NULL

exposure_end TIMESTAMPTZ

status VARCHAR(20) DEFAULT 'detecting'

overall_severity VARCHAR(10)

report_text TEXT

remediation_steps JSONB DEFAULT '\[\]'

gdpr_flag BOOLEAN DEFAULT FALSE

financial_impact TEXT

created_at TIMESTAMPTZ DEFAULT NOW()

INDEX ON: credential_type, exposure_start, status

TABLE: forensic_events

event_id UUID PRIMARY KEY

incident_id UUID REFERENCES incident_records(incident_id) ON DELETE CASCADE

platform VARCHAR(20) DEFAULT 'aws'

timestamp TIMESTAMPTZ NOT NULL

api_action VARCHAR(100) NOT NULL

event_source VARCHAR(100)

source_ip VARCHAR(50)

user_agent TEXT

affected_resource TEXT

resource_type VARCHAR(100)

success BOOLEAN DEFAULT TRUE

error_code VARCHAR(50)

impact_category VARCHAR(50)

severity_weight INTEGER CHECK (severity_weight BETWEEN 1 AND 4)

raw_data JSONB NOT NULL

INDEX ON: incident_id, timestamp, impact_category

TABLE: collection_status

id UUID PRIMARY KEY DEFAULT gen_random_uuid()

incident_id UUID REFERENCES incident_records(incident_id)

platform VARCHAR(20) DEFAULT 'aws'

status VARCHAR(20) -- 'success' | 'no_activity' | 'error'

event_count INTEGER DEFAULT 0

error_message TEXT

queried_at TIMESTAMPTZ DEFAULT NOW()

TABLE: experiment_runs

id UUID PRIMARY KEY DEFAULT gen_random_uuid()

incident_id UUID REFERENCES incident_records(incident_id)

run_number INTEGER

experiment_group VARCHAR(10) -- 'A' (standard) | 'B' (bulk) | 'C' (minimal)

exposure_start TIMESTAMPTZ

attacker_sim_start TIMESTAMPTZ -- when simulate_attacker_activity was called

detection_time_s INTEGER -- seconds from push to webhook detection

report_time_s INTEGER -- seconds from push to status=complete

api_calls_made JSONB -- list of api actions the simulated attacker made

impact_categories JSONB -- list of categories found

overall_severity VARCHAR(10)

external_use_detected BOOLEAN DEFAULT FALSE -- did a non-team IP use the key?

notes TEXT

created_at TIMESTAMPTZ DEFAULT NOW()

## 5.3 Complete API Endpoint Reference

| **Endpoint**                      | **Owner** | **Purpose**                      | **Notes**                                                                                            |
| --------------------------------- | --------- | -------------------------------- | ---------------------------------------------------------------------------------------------------- |
| **POST /webhook/github**          | Ritwik    | Receives GitHub push event       | Validates signature, extracts diff, calls scanner, creates incident, fires background tasks          |
| **POST /test/simulate**           | Ritwik    | Test without real GitHub push    | Body: {repo_url, diff_text, access_key_id}. Bypasses GitHub API. Essential for development.          |
| **GET /incidents**                | Ritwik    | List all incidents               | Returns: \[{incident_id, credential_hint, exposure_start, overall_severity, status, event_count}\]   |
| **GET /incidents/{id}**           | Ritwik    | Full incident with nested events | Returns IncidentRecord including all ForensicEvents, report_text, remediation_steps, gdpr_flag       |
| **GET /incidents/{id}/timeline**  | Ritwik    | Events sorted by timestamp       | Returns list of ForensicEvents sorted by timestamp ASC - used by D3 timeline                         |
| **POST /incidents/{id}/collect**  | Ritwik    | Manually re-trigger collection   | For retry after failure. Re-queries CloudTrail for the window.                                       |
| **POST /incidents/{id}/classify** | Ritwik    | Manually re-run classifier       | Re-classifies all events. Used when taxonomy is updated.                                             |
| **PATCH /incidents/{id}**         | Ritwik    | Update report fields             | Accepts: {report_text, remediation_steps, gdpr_flag, financial_impact, overall_severity}             |
| **GET /incidents/stats**          | Ritwik    | Aggregate statistics             | Returns: {total, by_severity:{...}, avg_detection_time_s, avg_report_time_s, top_categories:\[...\]} |
| **POST /research/record**         | Ritwik    | Save experiment run result       | Body: full ExperimentRun object. Called by harness.py after each run.                                |
| **GET /research/export**          | Ritwik    | Export all experiment runs       | Returns JSON array of all experiment_runs rows. ?format=csv for CSV version.                         |
| **GET /health**                   | Ritwik    | System health check              | Returns: {status:'ok', db:'connected', last_incident_at:..., environment:...}                        |

# SECTION 6 - EVALUATOR PRESENTATION SCRIPT

## 6.1 What the Evaluators Will See - Summary

| **Time**      | **What Happens**                                                                                                                      |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| **0:00-1:00** | Shashank delivers the problem statement and solution pitch. Shows the empty dashboard.                                                |
| **1:00-2:30** | Ritwik commits the fake AWS key. Live pipeline runs. D3 timeline appears. Full report shown.                                          |
| **2:30-3:00** | Shashank presents research findings: Track A accuracy + Track B pipeline timing from Research page.                                   |
| **3:00+**     | Q&A: evaluators examine the dashboard. Shashank answers architecture questions. Yash explains classifier. Vedant explains the report. |

## 6.2 Pre-Demo Setup (15 minutes before evaluators arrive)

- On the demo laptop: open 3 tabs: Tab 1 = BreachTrace Dashboard (Netlify URL), Tab 2 = GitHub test repo, Tab 3 = Research page
- Confirm the Railway backend is alive: open Tab 1, it should show the incident list (or empty state). If blank, check Railway logs.
- On a second laptop: have AWS CLI configured for the experiment profile (aws configure --profile experiment using the experiment key). Run 'aws sts get-caller-identity --profile experiment' - confirm it returns the account ID. If it fails, the key is rotated - create a new one via key_manager.
- In the DB: ensure at least 35 rows in experiment_runs table (for Research page). Ensure at least 1 pre-existing complete incident (the backup incident).
- Open the Research page (Tab 3): confirm all 3 charts are loading with real data. Confirm Track A and Track B metric cards show real numbers.
- Have the backup slides open in the background (in case the live demo fails).

## 6.3 Minute 1 - The Problem (Shashank presents)

**Script - Minute 1: The Problem and Solution (Shashank, stand, speak clearly)**

'Credential leaks are the most common, most costly security mistake in software development.'

'Every day, developers accidentally commit API keys to public GitHub repositories.'

'Automated bots find those keys within minutes - and start using them.'

'Tools like GitGuardian send you an alert: your AWS key was leaked. Rotate it.'

'But they never tell you what actually happened because it leaked.'

'Was your S3 bucket accessed? Were EC2 instances spun up? Was a new root key created?'

'Developers rotate the key and hope for the best. They never actually know.'

'BreachTrace fills that gap. It automatically correlates the GitHub exposure event with AWS CloudTrail'

'and produces a complete forensic impact report in under 60 seconds.'

\[Open the dashboard - show it live\] 'This is BreachTrace. Let us show you how it works.'

## 6.4 Minute 2 - Live Demo (Ritwik drives, second laptop ready)

- \[Ritwik\] 'I am now going to push a fake AWS key to a public GitHub repository.' Open Tab 2. One git push command. Execute it.
- \[All\] Switch to Tab 1 (Dashboard). A new incident appears within ~10 seconds. Show it appearing live.
- Status bar progresses: Detecting → Collecting → Classifying → Reporting → Complete
- \[Second laptop\] While pipeline runs: execute the 3 attacker simulation commands using the experiment key (these were pre-scripted). Show the terminal output. 'This simulates what an attacker would do.'
- \[All\] Click the incident on the dashboard. Full report page opens.
- \[Ritwik or Shashank\] 'The forensic timeline shows 3 events during the exposure window - all from the same IP address.' Point to the D3 timeline. Hover over an event to show the tooltip.
- \[Shashank\] 'AWS: 2 reconnaissance calls and 1 data access. The attacker listed S3 buckets, described EC2 instances, and retrieved one file. Severity: Medium. No privilege escalation. No data exfiltration.'
- \[Shashank\] 'The Gemini report says: ' - read the first sentence of the executive summary aloud.
- \[Ritwik\] Scroll to remediation checklist. 'Three specific steps - including the exact AWS CLI commands.'
- If gdpr_flag is set: point to the GDPR banner. 'The system automatically flags when personal data may have been accessed - relevant for GDPR notification obligations.'

## 6.5 Minute 3 - Research Findings (Shashank presents)

**Script - Minute 3: The Research Results (switch to Research page)**

\[Open Tab 3 - Research page\]

'Beyond the system itself, we ran a systematic evaluation to validate BreachTrace.'

'Track A: we tested our AWS credential detector against 200 real leaked credential samples'

'from the SecretBench public dataset - a benchmark used in academic security research.'

\[Point to Track A metric card\] 'Precision: X%. Recall: X%. F1: X%.'

'The detector correctly identifies real-world leaked AWS keys with high accuracy.'

'Track B: we ran 35 complete forensic pipeline experiments using controlled credential exposures.'

\[Point to timing chart\] 'Mean time to detection: X seconds against our 30-second target.'

'Mean time to complete report: X seconds against our 60-second target.'

\[Point to severity distribution chart\] 'Across 35 runs with different attacker behaviour patterns:'

'minimal activity scenarios produced Low severity, bulk data access scenarios produced Critical.'

'The classifier correctly distinguishes between an attacker doing reconnaissance'

'versus an attacker exfiltrating data - which is exactly what forensic triage requires.'

## 6.6 Backup Plan - If Live Demo Fails

**⚠️ If the live pipeline does not complete in time, switch to the pre-loaded incident immediately**

Do NOT wait more than 90 seconds for the pipeline to complete during the demo.

If 90 seconds pass and status is still not 'complete': say 'Let me show you a completed incident from our earlier test run.'

Click on the pre-loaded backup incident in the dashboard. It should have all events, timeline, and report already complete.

Say: 'This incident ran during our testing - it shows the full output. The live pipeline is working in the background.'

Continue the demo from Step 5 (show the timeline) using the backup incident.

After the demo: stay behind and show the evaluators the live pipeline completing on its own.

The backup slides (screenshots) are the final fallback if both the live and backup incidents fail.

# SECTION 7 - ANTICIPATED EVALUATOR QUESTIONS & ANSWERS

| **Question the Evaluator Will Ask**                           | **How to Answer (who speaks)**                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| ------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Why only AWS CloudTrail this week?**                        | Shashank: 'The evaluators asked for one complete platform this week. AWS CloudTrail gives the richest forensic data: per-call timestamps, source IPs, affected resources, success/failure. We chose the platform that produces the most meaningful forensic output. The architecture is designed so other collectors (GCP, Stripe, GitHub, Twilio) are added as separate modules using the same BaseCollector interface - they are next in our one-month plan.' |
| **How do you validate that 100-200 credentials were tested?** | Yash: 'We used the SecretBench public dataset from Basak et al. 2023 - cited in our project document. It contains 97,000+ manually labelled code snippets from GitHub. We filtered for AWS key samples - 200 rows. We ran our regex detector against all 200 and compared to the ground-truth labels. Our test file is tests/test_secretbench.py and the dataset is in data/secretbench_aws_200.csv.'                                                           |
| **What if someone actually uses the exposed test key?**       | Ritwik: 'The experiment IAM key has only two permissions: S3:ListBuckets and EC2:DescribeInstances - both read-only. Even if an external attacker finds and uses it, they can only list empty bucket names and see EC2 metadata. No data can be read, no resources can be created, no costs can be incurred. CloudTrail logs their access - which actually gives us a legitimate 'external use detected' data point for the research.'                          |
| **How accurate is the classifier?**                           | Yash: 'The rule-based classifier has two layers. First layer: exact lookup against our taxonomy of 80+ AWS API call mappings. Second layer: prefix heuristics for unknown calls. We measured classification accuracy against 30 manually-labelled CloudTrail events from our experiments - the number is on the Research page. The taxonomy itself is the novel research contribution.'                                                                         |
| **Is this only useful for security experts?**                 | Vedant: 'The dashboard is specifically designed for developers with no security background. The Gemini report uses plain English - no MITRE ATT&CK references, no CVE numbers. The remediation checklist includes the exact AWS CLI commands to run. A developer who has never heard of CloudTrail can look at this report and know exactly what happened and what to do.'                                                                                      |
| **Why use Gemini instead of a fine-tuned security model?**    | Shashank: 'We use Gemini for natural language generation only - not for classification. The impact taxonomy and severity rules are our own deterministic system. Gemini takes already-classified, already-structured data and transforms it into a readable report. Fine-tuned models require training data we don't have. Gemini's free tier is sufficient, it runs in under 3 seconds, and the output quality is demonstrably better than template strings.'  |

# SECTION 8 - FINAL NOTES

**🚀 The One-Week Goal in One Sentence**

By the end of Day 7, you must be able to commit a fake AWS key to a public GitHub repo, watch

BreachTrace detect it, collect real CloudTrail events, classify them, generate a Gemini report,

display a D3 timeline - all in under 60 seconds - and show 200 detection accuracy + 35 pipeline

run results to evaluators on a live Research dashboard. Everything else is secondary.

**⚡ To Yash Specifically - The Research Harness Is Your Most Important Day 6 Task**

You have strong algorithmic skills. Building the harness is pure logic: a loop with 4 function calls, a wait, and a DB write. The functions are already designed in this document.

The only part that might feel unfamiliar is the GitHub API push (PyGitHub) and the AWS IAM key creation (boto3 IAM). Ask Ritwik to write those two API calls for you. You fill in the orchestration loop.

35 experiment runs, 3 groups (12 standard + 13 bulk + 10 minimal) = exactly the distribution that makes a meaningful research result. Do not deviate from the groups.

**- END OF ONE-WEEK SPRINT PLAN -**