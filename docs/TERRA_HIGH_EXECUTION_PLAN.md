# Execution roadmap

The owner supplies the frozen repository and the nine planning files. The principal study can run on inert local evidence. Production deployments, public exposures and offensive scenarios are outside its design. A new research-only driver is needed; the historical harness and `research.run_all` do different jobs and can initiate network operations. Do not use either as the master entry point.

## Order and gates

| Phase | Actions in execution order | Exit condition and recovery |
|---|---|---|
| 0. Freeze | Record branch, tracked state, commit, runtime and library versions, DB engine, OS/CPU/RAM, timezone and monotonic clock precision. Hash historical JSON/Markdown outputs, documentation, PDF and protocol. Inventory allowed inputs, licences, owners and annotation capacity. Do not copy local environment files, database dump or credentials. | A fresh clone will omit ignored `research/evaluation/results.md`, learned weights and other outputs. Obtain redacted copies with hashes where authorized. Mark unavailable artifacts explicitly. |
| 1. Isolate | Use a separate worktree/directory and research-only DB, egress-disabled process and stub transports. Explicitly configure `DATABASE_URL`, `MODEL_SETTINGS_FILE` and `EMBED_ENABLED` for the isolated profile. Check `backend/config.py` and dotenv lookup before importing modules. Ensure import paths distinguish root `research/` from `backend/research/`. Disable notifications, hosted model writers, workers contacting remote providers and automatic downloads. | No inherited provider credentials, wallet entries or production DB. A configuration mismatch blocks that run. Preserve environment names and redacted settings only. |
| 2. Corpus | Build case, action, source and link tables described in master protocol. Assign writer, independent truth custodian and reviewers. Separate native bundles, native examples and synthetic fixtures; derive paired variants only after partitioning. | A legitimate action ledger can disagree with source logs. Preserve missingness. If no such ledger, schedule fixture study plus field-retention audit; mark actual action coverage blocked. |
| 3. Pilot and registration | Use development-only cases to verify joins, scope labels, deduplication, clock boundaries and independent reference query. Compute power and cluster-adjusted target N. Record unit, practical thresholds, exclusion rules, primary hypotheses, case weighting, bootstrap seed, time budget and stopping rule. Register a dated digest prior to held-out evaluation. | If precision is unattainable, predeclare descriptive pilot. No held-out tuning. An amended protocol has a new ID and date. |
| 4. Evidence path | Run EXP-01, then EXP-02 on same sealed cases, then EXP-03 with snapshot of each output surface. Use actual serializer/report paths and mock external acquisition only. Keep experimental projection under its own variant ID. | Native reference and all arms get equal input. Confirm truth table is inaccessible to each method. If a surface cannot express a key decision, record abstain or inapplicable with reason. |
| 5. Mechanisms | EXP-04 grouping/outcome and EXP-05 faults. Reuse sealed data, with transformed instances linked to original cases. Run EXP-07 only after independent raters and a local model are available. EXP-06 timed runs use a separate schedule with real monotonic clocks. | An unavailable model is a missing arm. Timing on an intentionally frozen clock invalidates the run. Never erase the first failed attempt. |
| 6. Optional scope | Run EXP-08 only on an independent authorized corpus and for the occurrence/deduplication question. EXP-09 only with independently graded ranking or approved observer study. | If the additional data are missing, publish the P0 findings with explicit scope. |
| 7. Analyze | Reconcile planned/attempted/completed counts by source and variant. Compute metrics from raw rows, not displayed percentages. Analyze paired primary endpoints, sensitivity to ambiguous joins and missing records, and case-cluster uncertainty. Conduct blind output review before viewing arm names. | Independent reviewer reproduces headline numerators and denominators on a sample plus complete aggregate table. Disagreements are retained and adjudicated. |
| 8. Release and cleanup | Produce figure/table source, results matrix and negative results. Replay from a fresh empty DB with no private files and compare digests of canonical outputs. Preserve immutable source hashes and restricted ledger according to owner agreement. Delete temporary case stores and disposable test state after integrity checks. | Public package opens and regenerates released tables. If sensitive native data cannot be released, provide inert replay examples, field masks and a controlled verification route; disclose what cannot be independently reproduced. |

Dependency graph: 0 → 1 → 2 → 3 → 01 → 02 → 03 → analysis/release. 04 branches after 01, 05 and 07 after 03, 06 after a functioning replay. 08 and 09 are independently gated. Budget core work for data stewardship and blinded annotation first.

## Implementation touchpoints

* **Fixture acquisition.** Feed pre-recorded pages through the mapping functions used by `backend/collectors`. Use `backend/research/gcp_import.py` and `backend/aws_evidence_import.py` for supported offline formats after confirming their contracts. Record adapter exceptions, unexpected field types and incomplete pages. Neither a native example nor a normalized-row injection measures live collection.
* **Attribution.** Evaluate GCP on actual incident serialization in `backend/routers/incidents.py`. Compare structured detection and operator-supplied association, including different keys under one principal. Azure sign-ins are a separate evidence object. Use provider-specific null/inapplicable values rather than implementing a universal key detector silently.
* **Time and state.** Fixture timestamps must be stable and timezone-aware. Test equality at both interval boundaries. Decode status at event, collection, incident and report level. Capture state before and after refresh. Use real elapsed clocks only in operational trials.
* **Measurement adapter.** Emit one row per stage and source/record/join. Capture hashes before normalization and after deterministic canonicalization, selected native evidence fields, identity granularity, source mode, processing status, report version, output source and time. Keep private lookup IDs in a restricted sidecar. Compare actual wording against raw evidence, including conditions where a Low score coexists with unavailable evidence.
* **Historical research contracts.** `backend/research/gcp_ground_truth.py:evaluate` enforces 1 MiB/2,000 rows and optional category/outcome mappings. Its record mode uses insert ID and treats ambiguity separately. Partition by source scope without splitting a case. Its command mode cannot measure coverage. `research/evaluation/runner.py` compares detector-selected rows and `creddata.py` uses selected repositories; route EXP-08 through an independently defined evaluation frame.
* **Minimum additions, in order.** A research ledger/manifest and stable many-to-many joins; an isolated replay wrapper with injectable transport/clock; an output assertion form and reference query; only then a research-only scope-preserving report projection. Avoid changes to scoring, taxonomy, prompts and threshold defaults in the frozen treatment.

## Machine-readable run contract

Use JSON Lines, UTF-8, one immutable record per attempt. The following is a JSON Schema for manifests, not a measured run. Relative artifact paths resolve under the release root. SHA-256 digests identify inputs and label releases.
```json
{
  "type": "object",
  "required": ["experiment_id","rq","git_commit","config","dataset_version","provider","scenario","seed","run_id","attempt","variant","source_mode","cluster_id","start_utc","end_utc","measurements","failure_status","versions","cost","artifacts","validation"],
  "properties": {
    "experiment_id": {"type":"string","pattern":"^EXP-0[1-9]$"},
    "rq": {"type":"array","items":{"type":"string"}},
    "git_commit": {"type":"string","pattern":"^[0-9a-f]{40}$"},
    "config": {"type":"object","required":["protocol_digest","reader_scope","clock_mode","cutoff","db_engine"]},
    "dataset_version": {"type":"string"},
    "provider": {"type":"string"},
    "scenario": {"type":"string"},
    "seed": {"type":"integer"},
    "run_id": {"type":"string"},
    "attempt": {"type":"integer","minimum":1},
    "variant": {"type":"string"},
    "source_mode": {"enum":["fixture","vendor_example","owner_export","operational_measurement"]},
    "cluster_id": {"type":"string"},
    "start_utc": {"type":"string","format":"date-time"},
    "end_utc": {"type":["string","null"],"format":"date-time"},
    "measurements": {"type":"array","items":{"type":"object","required":["metric","value","unit","source"]}},
    "failure_status": {"enum":["none","missing_input","permission","timeout","provider","mapping","storage","invalid_clock","other"]},
    "versions": {"type":"object","required":["runtime","tools","model","prompt","rules"]},
    "cost": {"type":"object","required":["amount","currency","basis"]},
    "artifacts": {"type":"array","items":{"type":"object","required":["path","sha256","access"]}},
    "validation": {"enum":["pending","valid","partial","invalid","blocked"]}
  }
}
```

Additionally validate unique (run_id, attempt), references to registered source units, explicit UTC offsets, end ≥ start, status/reason agreement, nullable missing values with reason, zero secret-bearing inputs in release and reproducible input hashes. Clock errors in provider records are a study variable; do not silently correct them. New attempts link to earlier failures.

## Artifact layout for the subsequent execution

Use a separate experiment root containing `protocols/`, `datasets/{metadata,public,restricted}/`, `baselines/`, `experiments/`, `manifests/`, `results/{raw,processed}/`, `analysis/`, `figures/`, `tables/` and `reproducibility/`. Store frozen source versions, data dictionary, decoding settings, access instructions and a minimal offline reproduction entry point. Case IDs are opaque. Raw source content and private truth belong only in restricted storage. A public empty-string field must never substitute for a missing observation.

**Completion checklist.** Every planned arm has an outcome or blocker, every reported number resolves to a script and manifest, and every scoped claim names its denominator and comparator. A second operator can recreate a synthetic case, exact reference join, metric and figure without credentials. Disclose the precise subset of native results they can reproduce. Deliver the claim matrix with supported, contradicted, inconclusive and blocked conclusions; do not revise the primary question after viewing results.
