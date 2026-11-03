# AI detection UI examples

Open http://127.0.0.1:5173/?platform=ai and select a masked credential.
Six synthetic examples are seeded into the isolated local test database:

| Provider | Demonstration | Detail page |
|---|---|---|
| OpenAI / GPT | Plaintext candidate | `/incident/6d10eb80-e819-594c-b52c-72922dcdb8fd` |
| Anthropic / Claude | Unicode escapes | `/incident/907720a8-a30e-5eba-95b2-10e767472fab` |
| Google Gemini | Provider-named key | `/incident/1d02c9c9-18e8-55b4-a23f-1875a356aca3` |
| DeepSeek | Hexadecimal decoding | `/incident/ad17b5b0-6575-517a-b9b9-3ca2fa8c2860` |
| Sarvam AI | Base64 decoding | `/incident/175add98-ea65-5dfa-a47d-c1f7f3fcbbae` |
| Groq | Split string reconstruction | `/incident/a234e96a-53bb-5ab4-b112-e5421e7ea499` |

The real offline detector generates the masked result for each fabricated source
sample. No full keys appear in the frontend fixtures or incident records, no key
is validated with a provider, and no usage, cost or real breach is represented.
No research experiment rows are created. Other synthetic test incidents from
earlier local checks remain visible too.

The same six examples are included when running the frontend in preview mode
(`VITE_USE_MOCK=true`). Preview mode has a prominent synthetic-data notice.

To reseed the local database or regenerate the shared masked fixtures:

```sh
.venv/bin/python scripts/seed_ai_demos.py
# Regenerate frontend fixtures without a database:
.venv/bin/python scripts/seed_ai_demos.py --export-only
```

Seeding is idempotent and restricted to `breachtrace_local_test` on
`127.0.0.1:55432`. It preserves unrelated incidents and research data.

## UI corrections

- AI details use the correct provider identity; the duplicate AWS fallback badge
  has been removed. Detection-only pages show no provider-log refresh control or
  panels implying that forensic logs are on their way.
- Completion means detection/analysis finished, not remediation completed.
  Unknown closure is labelled “Closure not confirmed,” and no confirmed exposure
  duration is inferred from a missing end timestamp. Demos have explicit labels.
- The AI and Other filters have distinct meanings and counts. All dashboard
  metrics/charts follow the selected filter. The empty Other state renders
  without accessing a nonexistent provider label. Credentials are keyboard links.
- Unknown severity is shown as “Not assessed.” Search can filter the named AI
  providers, including Claude/GPT aliases, and marks synthetic result rows.
- Dark-mode secondary text has higher contrast, narrow layouts wrap navigation
  and scan inputs, and print styles use readable light-theme tokens.
- Research wording no longer claims a completed SecretBench evaluation or 200
  verified real samples. Missing numeric metrics show “Not measured.” Preview
  metrics are explicitly synthetic. Compliance flags request review rather than
  claiming a confirmed legal notification requirement.
- Copy controls report success only after clipboard completion; search failures
  show an error and clear stale results. Checklist controls explain their local,
  unsaved behavior. The browser title now identifies BreachTrace.

## Verification

- Backend: **1,250 passed, 2 skipped**, including fixture masking, stable fixture
  export, idempotent seeding, absence of research measurements and AI query aliases.
- `npm test`: presentation and component checks passed. Production build and lint
  passed. Existing backend warnings and frontend bundle-size advisory remain.
- Live API: all six demo details and four named-provider searches passed.
  Evidence is saved locally in `data/ai-ui-demo-verification.json`.
- Native Chrome: reviewed the desktop dashboard and demo detail layout; exercised
  the AI filter, empty Other filter, Sarvam Base64 detail, and Sarvam search results.
  Mobile layouts and printed output were adjusted in code but not visually reviewed.
