# AI credential detection coverage

This implementation detects **candidates**, not proven valid or active keys. There
is no finite exhaustive regex for every current/future key or arbitrary obfuscation.
The scope below is explicit and tested; do not market it as 100% real-world recall.

## Provider coverage

49 credential families are registered. Nine have standalone distinctive-prefix
patterns; the remaining families rely on named credential fields, SDK imports or
constructors, endpoint context, or a structured JSON provider path. Gemini is
attributed only with Google-AI context. A bare `AIza` key is detected as a generic
Google API credential whose AI usage is unconfirmed. GPT/ChatGPT maps to OpenAI;
Claude maps to Anthropic. The model name alone does not identify a hosting service:
an OpenRouter key used for DeepSeek still belongs to OpenRouter.

| Provider / service | Credential type | Coverage kind |
|---|---|---|
| OpenAI / GPT | `openai_api_key` | Distinctive prefix + contextual candidates |
| Anthropic / Claude | `anthropic_api_key` | Distinctive prefix + contextual candidates |
| Google Gemini | `gemini_api_key` | Contextual candidate (opaque format) |
| Google API key (AI usage unconfirmed) | `googleai_api_key` | Distinctive prefix + contextual candidates |
| Groq | `groq_api_key` | Distinctive prefix + contextual candidates |
| xAI / Grok | `xai_api_key` | Distinctive prefix + contextual candidates |
| OpenRouter | `openrouter_api_key` | Distinctive prefix + contextual candidates |
| DeepSeek | `deepseek_api_key` | Contextual candidate (opaque format) |
| Mistral | `mistral_api_key` | Contextual candidate (opaque format) |
| Cohere | `cohere_api_key` | Contextual candidate (opaque format) |
| Together AI | `together_api_key` | Contextual candidate (opaque format) |
| Perplexity | `perplexity_api_key` | Distinctive prefix + contextual candidates |
| Replicate | `replicate_api_key` | Distinctive prefix + contextual candidates |
| Sarvam AI | `sarvam_api_key` | Contextual candidate (opaque format) |
| Cerebras | `cerebras_api_key` | Contextual candidate (opaque format) |
| Fireworks AI | `fireworks_api_key` | Contextual candidate (opaque format) |
| NVIDIA NIM | `nvidia_api_key` | Contextual candidate (opaque format) |
| AI21 | `ai21_api_key` | Contextual candidate (opaque format) |
| DeepInfra | `deepinfra_api_key` | Contextual candidate (opaque format) |
| SambaNova | `sambanova_api_key` | Contextual candidate (opaque format) |
| Anyscale | `anyscale_api_key` | Contextual candidate (opaque format) |
| Lepton AI | `lepton_api_key` | Contextual candidate (opaque format) |
| SiliconFlow | `siliconflow_api_key` | Contextual candidate (opaque format) |
| Moonshot / Kimi | `moonshot_api_key` | Contextual candidate (opaque format) |
| Zhipu / Z.ai | `zhipu_api_key` | Contextual candidate (opaque format) |
| Alibaba DashScope / Qwen | `dashscope_api_key` | Contextual candidate (opaque format) |
| MiniMax | `minimax_api_key` | Contextual candidate (opaque format) |
| Baidu / Qianfan | `baidu_api_key` | Contextual candidate (opaque format) |
| Azure OpenAI / Foundry | `azureopenai_api_key` | Contextual candidate (opaque format) |
| Hugging Face | `huggingface_api_key` | Distinctive prefix + contextual candidates |
| Voyage AI | `voyage_api_key` | Contextual candidate (opaque format) |
| Jina AI | `jina_api_key` | Contextual candidate (opaque format) |
| RunPod | `runpod_api_key` | Contextual candidate (opaque format) |
| fal.ai | `fal_api_key` | Contextual candidate (opaque format) |
| Stability AI | `stability_api_key` | Contextual candidate (opaque format) |
| ElevenLabs | `elevenlabs_api_key` | Contextual candidate (opaque format) |
| AssemblyAI | `assemblyai_api_key` | Contextual candidate (opaque format) |
| Deepgram | `deepgram_api_key` | Contextual candidate (opaque format) |
| Cartesia | `cartesia_api_key` | Contextual candidate (opaque format) |
| Novita AI | `novita_api_key` | Contextual candidate (opaque format) |
| Nebius AI | `nebius_api_key` | Contextual candidate (opaque format) |
| Baseten | `baseten_api_key` | Contextual candidate (opaque format) |
| FriendliAI | `friendli_api_key` | Contextual candidate (opaque format) |
| AI/ML API | `aimlapi_api_key` | Contextual candidate (opaque format) |
| Amazon Bedrock bearer token | `bedrock_api_key` | Contextual candidate (opaque format) |
| Google Vertex AI | `vertexai_api_key` | Contextual candidate (opaque format) |
| Volcengine / Doubao | `volcengine_api_key` | Contextual candidate (opaque format) |
| Tencent Hunyuan | `hunyuan_api_key` | Contextual candidate (opaque format) |
| Ollama cloud | `ollama_api_key` | Contextual candidate (opaque format) |

The registry lives in `backend/detector/ai_keys.py`. Contextual support does not mean
that the vendor's complete key alphabet or every issued version is independently
verified. It means sufficiently random-looking literal credential values in that
provider's explicit configuration can be found even when there is no distinctive
prefix. Such matches carry medium confidence and require review. Current-key
validity, ownership, usage, and billing are never inferred from syntax alone.

## Matching and provenance

- OpenAI legacy, project, service-account and admin prefixes; Anthropic API/admin
  and the configured OAuth access-token prefix; Groq, xAI, OpenRouter, Perplexity,
  Replicate, Google API and Hugging Face prefixes are covered.
- Named assignments work in environment files, Python, JS/TS, JSON and YAML, with
  case, separators, common frontend prefixes, numbered keys and reversed label
  ordering such as `API_KEY_SARVAM`.
- Sarvam `api_subscription_key`, `api-subscription-key` and Bearer-header context
  are supported. Its official authentication docs do not specify a universal
  fixed key length/format, so no invented exact Sarvam format is claimed.
- OpenAI-compatible SDKs use endpoint context to avoid attributing a Sarvam or
  DeepSeek key to OpenAI solely because `OpenAI(...)` appears in the source.
- JSON path/sibling-provider context handles nested, multi-provider objects and
  arrays, preserving duplicate JSON members rather than silently dropping keys.
- Public identifiers, token counts, variable/property references and obvious
  placeholders are excluded by targeted rules. Opaque-key candidates need
  credential semantics and entropy; arbitrary hashes are not AI credentials.
- Diff detection respects added fragments, ignores deleted material and isolates
  unrelated files/hunks. File scans treat +/- characters as literal source.
- Findings carry the original line span, detection method and confidence. Keys
  remain masked; reconstructed plaintext is not stored in a scan result or log.

## Static obfuscation recovery

Supported recovery includes Base64, Base64URL, two encoding layers, hexadecimal
strings, Unicode/hex escapes, URL percent encoding, HTML entities and zero-width
format characters. It also supports static quoted-string concatenation (`+`, PHP
`.` and literal adjacency), literal-only Python/JS empty-separator array joins,
constant reversed literals, and explicitly marked ROT13 literals. Common
`b64decode`, `atob`, `bytes.fromhex` and Node `Buffer.from` wrappers are recognized.
Kubernetes Secret values and whole Base64-encoded JSON configuration are covered.

No code is evaluated or imported from a scanned repository. No detected key is
submitted to a provider. There are no automatic verification requests or charges.

## Limits and gaps

- Encoding depth: 2; encoded token length: 8,192 characters; joined literal length:
  16,384 characters; literal fragments: 256; structured JSON path depth: 64.
- Successful normalized representations are bounded to 4,096 transforms and 1 MiB
  of aggregate decoded text per file. Exhaustion is reported as a scan diagnostic
  and the repository result is marked incomplete; raw scanning continues.
- Opaque contextual values are 20–512 characters with Shannon entropy >= 3 bits
  per character. Outside these bounds, a contextual-only key may be missed.
- SDK/endpoint context is normally within three source lines. JSON uses structural
  context. Generic fields with ambiguous provider context are not guessed.
- Encryption, arbitrary runtime computation, variable/data-flow resolution,
  custom ciphers, compressed archives, image/OCR secrets and cross-file assembly
  are not supported. YAML uses named fields/context, not a complete YAML parser.
- Whole-repository scanning still has file/byte/time limits, excludes binaries and
  dependency/admin directories, and scans the current snapshot, not Git history.
  Current defaults are 10 MiB/file, 1 GiB of scanned text, 200,000 files, 10,000
  findings, a 2 GiB archive limit, and a 10-minute scan timeout. Archive downloads
  are capped at 5 minutes. The scan timeout is checked between files and after
  each file scan; it does not interrupt an in-progress regex.
- Existing AWS/GCP service-account detection remains the path for Bedrock/Vertex
  cloud credentials. The AI bearer/API-key variants are detection-only.

## Validation and research claims

The controlled tests cover each family in five configuration styles, encoded
variants for the principal providers, negative code examples, source attribution,
static decoding safety, masking, and resource limits. All credentials are synthetic.
Passing these tests is conformance evidence, not an empirical precision/recall score
on independently labelled real leaks. The labelled SecretBench dataset remains
unavailable in this workspace, so no high real-world recall percentage is claimed.
Large public checkouts are used for performance and candidate review, not treated
as a known-clean corpus. Public test fixtures and public IDs can legitimately be
flagged as candidates; manual adjudication is necessary.

Verification on 2026-11-03:

- Full backend suite: **1,221 passed, 2 skipped**. Existing deprecation/async-test
  warnings remain. Frontend production build and lint passed; the existing bundle
  size advisory remains.
- The archive-download integration test finds a synthetic Base64 Sarvam key,
  preserves its file/line and method, and returns neither encoded nor decoded key.
- Live API: 13 checks passed, including Base64 Sarvam, escaped Anthropic and split
  DeepSeek detection, detection-only incident classification and response masking.
  Evidence: `data/ai-expanded-live-verification.json` (local, gitignored).
- Live rescan of `shash-17/Notes-App-MERN` at
  `8a27e6ed81e08a79b07a9ab8e59ef7065635d23c`: 38 files, zero candidates,
  traversal complete under the disclosed policy. This does not prove absence of
  unsupported or historical secrets.
- Expanded-detector performance run on VS Code at
  `e2ce8e1b6b05d4522d3a1d4d863665c9cc8e8f02`: 20,392 UTF-8 text files,
  269,445,059 bytes, 126.60 seconds, 39 unverified candidates across all detector
  families (three AI candidates). No normalization limits were exceeded. Excluded
  directories, binaries, oversized/non-UTF-8 files and symlinks remain excluded.
  This run preceded the final literal-reversal/array-join and allocation-hardening
  changes; it is a performance observation, not a benchmark of every final path.
  Evidence: `data/stress-vscode-ai-current.json` (local, gitignored).
- FastAPI with one explicitly seeded synthetic Groq probe: 3,046 files,
  25,009,615 bytes, 8.67 seconds, one candidate (the probe), traversal complete.
  Evidence: `data/stress-fastapi-ai-expanded-final.json` (local, gitignored).

Run:

```sh
PYTHONPATH=backend .venv/bin/python -m pytest backend/tests/test_ai_keys.py backend/tests/test_ai_coverage.py -q
```

## Primary references reviewed

- [OpenAI detector reference](https://github.com/gitleaks/gitleaks/blob/master/cmd/generate/config/rules/openai.go)
- [Anthropic API/admin detector reference](https://github.com/gitleaks/gitleaks/blob/master/cmd/generate/config/rules/anthropic.go)
- [Groq detector reference](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/groq/groq.go)
- [xAI detector reference](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/xai/xai.go)
- [Replicate detector reference](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/replicate/replicate.go)
- [DeepSeek detector reference](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/deepseek/deepseek.go)
- [Sarvam authentication](https://docs.sarvam.ai/api-reference/authentication)
- [Sarvam SDK credential field](https://docs.sarvam.ai/api/getting-started/sdks)

Prefix bounds deliberately include broader candidates for format drift. They are
not vendor-side validators. Other registry entries provide contextual detection;
this document does not present their inferred formats as official specifications.
