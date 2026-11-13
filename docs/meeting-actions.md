# Meeting action implementation

Source: `minutes.md`, BreachTrace review, October 13. Implement and verify in order.
The subsequent [logic review](logic-review.md) repairs the migration chain and
preserves legacy research rows during the existing schema transition.

1. AI key detection: implemented and verified. Expanded to [49 AI credential families](ai-detection.md), with bounded static obfuscation recovery. The initial implementation added twelve provider families, plus existing
   Hugging Face tokens. Keys are candidates, never automatically tested against a
   provider. AI keys are detection-only, with no usage-attribution claims.
2. Model settings: implemented and verified.
3. Multi-model benchmark: tooling tested; real four-case/two-model local pilot measured.
   See `research/model-benchmark-pilot.md`. A paper-ready statistical study and
   human accuracy assessment remain outstanding; no general recommendation claimed.
4. Timeline/report retrieval and model disclaimer: implemented; 36 targeted tests
   passed and frontend production build passed.
5. Large open-source stress testing: completed on pinned VS Code and FastAPI
   checkouts, with a separate seeded probe. See `research/repository-stress.md`.
   Targeted detector tests passed; exclusions and unverified candidates disclosed.
6. Whole-repository scan on connection: implemented and tested, including a real
   GitHub archive download and scan of FastAPI at its pinned revision.

## Detection scope and sources

The initial scope below has since expanded to 49 AI credential families and
static obfuscation recovery. Current coverage, limits and verification results
are maintained in [AI credential detection](ai-detection.md).

OpenAI, Anthropic, Gemini, Groq, xAI, OpenRouter, DeepSeek, Mistral, Cohere,
Together AI, Perplexity, Replicate, and existing Hugging Face support. This is an
explicit coverage list, not a promise to detect every future key format.
Ambiguous bare keys require a provider-named assignment. Generic Google keys
are not labelled Gemini without Gemini/Google-AI context. Provider formats can
change; tests are offline synthetic format checks, not real-world precision/recall.

Reviewed primary implementation references on 2026-11-03:

- https://github.com/gitleaks/gitleaks/blob/master/cmd/generate/config/rules/openai.go
- https://github.com/gitleaks/gitleaks/blob/master/cmd/generate/config/rules/anthropic.go
- https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/groq/groq.go
- https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/xai/xai.go
- https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/replicate/replicate.go

Other formats use conservative named assignments; validation against independent
labelled samples remains necessary before claiming measured detector accuracy.

Step 1 validation: full backend suite **782 passed, 2 skipped**; client production
build passed. Existing Pydantic/async-test warnings and bundle-size advisory remain.
No API key was submitted to a provider. AI detections create detection-only
incident rows, not forensic-event/collection-status rows; existing telemetry CHECK
constraints therefore need no widening for this detection-only feature.

## Model configuration

The Settings page supports OpenAI, Anthropic, Gemini, Ollama, explicitly selected
GGUF files, and deterministic reports. No generative model is selected by default.
Ollama endpoints are limited to the backend machine's loopback interface. Cloud
report requests send fact sheets to the selected provider; UI connection tests
send a short prompt and can incur provider usage charges. No live cloud test has
been made by this implementation.

Non-secret preferences are persisted in `data/model-settings.json` (gitignored).
Entered keys live only in the backend process; environment keys are supported.
Use a single backend worker for memory-only keys. The current settings endpoints
are restricted to loopback clients and loopback browser origins; remote deployments
need an authenticated admin layer before exposing configuration. Keys never appear
in successful settings responses or preferences files. Request validation errors
are stripped of submitted input. Optional GGUF runtime installation is separate.

Step 2 validation: **795 backend tests passed, 2 skipped**; frontend production
build passed. Provider HTTP contracts were tested with synthetic responses;
actual model quality and account access are not established by those tests.

API references reviewed:

- https://developers.openai.com/api/docs/quickstart
- https://platform.claude.com/docs/en/api/messages
- https://docs.ollama.com/api/chat

## Timeline retrieval

Incident indexing includes one passage per event: timestamp, action, outcome,
resource, source IP, category, error code, and event ID. Raw payloads are excluded.
Exact ISO timestamp questions use a database time query rather than semantic
ranking; a single timestamp matches its one-second interval. The search API also
accepts aware `timeline_start` / `timeline_end`, with an inclusive explicit end.
Results link to their incident, preserve event IDs, and expose truncation rather
than presenting a limited result as the complete timeline. Model-quality and
missing-evidence disclaimers appear with retrieved results. Report inference may
use a chosen cloud provider; search remains local retrieval rather than an
ungrounded generation step. Existing reports need re-indexing to gain event
passages; exact timestamp queries read event rows directly and work immediately.

## Whole-codebase scan

Connect defaults to starting a snapshot scan after a successful webhook connection.
It can also scan without registering a webhook. The scan downloads GitHub's
default-branch archive pinned to a commit, safely extracts only regular files,
then uses the same scanner as the stress tests. Size, time, entry and findings
limits bound the work. Paths, links, decompression excess and redirects are
validated; GitHub tokens are not forwarded to the archive redirect host. Only
masked candidates are returned/persisted. No repository code is executed.

The live smoke test fetched the FastAPI archive (18,095,190 compressed bytes),
scanned 3,045 text files at revision `5cb6272ed7e3e07eaf6978e1e65b94aca76fa8e0`,
and finished policy traversal with zero candidates. A snapshot cannot establish
the first time a key leaked, so exposure start stays unknown and cloud forensics
is not started automatically. Findings currently appear in Connect scan results,
not as invented exposure incidents on the incident dashboard. Scan jobs and
memory-only model keys require one backend process. Polling state is lost on
restart; completed evidence is retained in `data/repository-scans/`.

Final validation: **821 backend tests passed, 2 skipped**; frontend production
build, ESLint and `git diff --check` passed. Existing backend deprecation/async
test warnings and the frontend bundle-size advisory remain. Browser automation
was unavailable, so UI compilation and HTTP behavior are verified but screenshots
and interactive visual QA are not claimed. Cloud model adapters were contract
tested with synthetic responses; live local inference was measured. The backend
database migrations were neither edited nor applied by this work; the pre-existing
deleted predecessor/new migration state is left untouched.
