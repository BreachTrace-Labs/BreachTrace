# Local model benchmark pilot

Measured on 2026-11-03 using four identical synthetic incident fact sheets per model. No cloud API calls or model downloads.

Hardware: Darwin arm64, 10 logical CPUs, 16.0 GB RAM. Ollama uses Metal; these are not CPU-only measurements.

| Writer | Cases | Valid JSON | Validator pass | Mean fact coverage | Median seconds | p95 seconds |
|---|---:|---:|---:|---:|---:|---:|
| Deterministic template | 4 | 100% | 100% | 100.0% | 0.000 | 0.000 |
| llama3.2:latest | 4 | 100% | 75% | 62.5% | 18.634 | 29.002 |
| qwen2.5vl:3b | 4 | 100% | 75% | 31.2% | 21.129 | 22.182 |

The deterministic template remains the default on this machine: neither model improved on its fact coverage in this pilot. The sample is too small to rank model families or recommend a model for another machine.

Validator pass rate is not factual accuracy. A rejected expression may be an unsupported claim or a conservative validator rejection. There was no human blind review. Four cases cannot establish a reliable latency percentile; here p95 is the slowest observed case. Latency includes model loading and no retries. Ollama-reported allocation is included in raw results and must not be labelled peak RAM. Shared-memory Metal allocations cannot be treated as independent host and GPU memory totals.

The existing fixed knowledge-base retrieval fixture measured keyword recall@1=0.860, recall@3=0.930, recall@5=0.953. Retrieval recall is independent of the prose model and must not be presented as model accuracy.

Gemma 3 and Qwen 3.5 were not installed and were not tested. No measurements or hardware recommendations for them are claimed.

Reproduce:

```sh
PYTHONPATH=backend EMBED_ENABLED=false .venv/bin/python -m research.model_benchmark --model llama3.2:latest --model qwen2.5vl:3b --cases 4 --out data/model-benchmark-pilot.json
PYTHONPATH=backend DATABASE_URL=sqlite:// EMBED_ENABLED=false .venv/bin/python -m rag.evaluate
```

See model-benchmark-pilot.json for model digests, fixture hash, prompt version, per-case results, and allocation samples. A paper-ready study should increase sample sizes, include empty and adversarial evidence, repeat runs in randomized model order, measure process memory externally, and add blinded human review before making general recommendations.
