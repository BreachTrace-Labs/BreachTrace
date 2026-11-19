# Credential detection research

This directory is separate from BreachTrace detection and provider collection. It does not modify detector thresholds, load trained weights into the app, validate credentials, or generate research results automatically. Commands run from the repository root with the project virtual environment:

```sh
.venv/bin/python -m pip install -r backend/requirements.txt -r research/requirements-research.txt
```

## 1. Collect candidates

Set `GITHUB_TOKEN` in your shell or secret manager without sharing it in chat. Use a token authorized for public GitHub searches. Collection is a deliberate network operation; it searches public code and samples popular repositories, respects a delay between requests, bounds downloads and scans data in memory. It does not use or verify any discovered credentials. Source lines and context are replaced wholesale by `[redacted]`, since masking only a matched token can leave other secrets in context. Candidate file URLs may still lead to sensitive material and should be treated as sensitive.

```sh
.venv/bin/python -m research.dataset.collector
```

The collector appends masked metadata to `research/dataset/corpus/candidates.jsonl`. It does not write downloaded source or archives to disk. Search results and popular repositories are **unlabeled candidates**, not true-positive or true-negative ground truth. Results may stop at GitHub limits or the documented archive, file and size bounds. The corpus is gitignored. `--repos-per-language 0` runs code search only; see `--help` for options.

For descriptive counts on a single pinned repository snapshot, run `.venv/bin/python -m research.evaluation.snapshot_comparison --repo OWNER/REPO --revision COMMIT_SHA`. This streams each eligible text file to the scanners in memory, disables TruffleHog verification, and stores only aggregate counts in gitignored `research/evaluation/snapshot-results.md` and `.json`. The external scanners receive stdin without file paths, so path-dependent rules may behave differently. The counts are not precision or recall and the timings include per-file process startup. Generate the main report afterwards to include the measured snapshot summary.

For an independently reviewed real-world benchmark, run `.venv/bin/python -m research.evaluation.creddata`, then `.venv/bin/python -m research.evaluation.report`. This downloads the pinned [CredData](https://github.com/Samsung/CredData) metadata and five pinned source repositories into memory, scans the source without provider verification, and writes aggregate results only. The deterministic subset consists of the first five sorted repository IDs with at least one reviewed `aws-id` positive, so it is not representative of the full dataset. Reviewed lines cover multiple credential types. A match is any finding on the reviewed line, not necessarily the exact value; conflicting and unknown labels and unreviewed findings are excluded. CredData's own rules can label test credentials as true, and labels do not establish live validity. The subset is not used to train weights or to label unrelated GitHub candidates.

## 2. Label candidates

```sh
.venv/bin/python -m research.dataset.labeler
```

The labeler resumes from `labeled.jsonl`. It displays masked metadata and the source link, not unredacted context. A label reflects the reviewer's assessment, not a live credential-validation request. Keep the corpus private and do not commit it.

## 3. Optional model training

```sh
.venv/bin/python -m research.weights.trainer
```

At least 40 scoreable labels and at least five examples of each class are required. The research adapter computes four normalized heuristic signals from an exact in-memory match, its surrounding source and the fact that the existing detector matched it. These are newly defined research features, not established detector confidence or verified credential validity. A finding for which the exact candidate cannot be recovered safely has no score or signals and cannot be used for this training. Missing features are never filled with guessed values. A trained artifact is research-only; finite normalized weights that sum to one are loaded by `research.scoring` at module startup. Logistic regression coefficients require an intercept, so normalized coefficients alone are not equivalent to the fitted model or a replacement for a production scorer. Cross-validation groups source repositories and synthetic pairs when group identifiers exist. Without them the trainer reports a weaker sample-level validation that may leak related samples. A synthetic-heavy evaluation is not a real-world accuracy estimate.

The opt-in `.venv/bin/python -m research.dataset.synthetic` generates 100 **synthetic** records in a separate file. It stores only assigned labels and heuristic signals, never the generated values. These controlled examples are model-feature probes; they are not independently verified real leaks, detector ground truth or evidence of real-world calibration. Each positive/negative pair shares a group for cross-validation. Synthetic labels do not label public-code candidates.

`.venv/bin/python -m research.evaluation.creddata --features-only` separately rescans the pinned files and records scoreable matches on reviewed lines as numerical research signals. A line association does not establish an exact match to the value reviewed, and matches without safely recoverable signals are excluded. The trainer combines these records with the synthetic pilot and existing manual labels. Ablation uses the logistic coefficients and intercept on training data and is therefore in-sample; calibration buckets use the original default heuristic score, not held-out logistic probabilities.

## 4. Compare scanners on authorized files

TruffleHog and GitLeaks need filesystem access to source text. To avoid writing downloaded credentials, the runner only reads an **already existing, authorized local corpus** organized as `ROOT/owner/repository/revision/path`. It checks each file against the recorded Git blob SHA before running any tool. Supplying this corpus is the operator's responsibility; do not populate it by copying live credentials into the project. Tool output is captured and parsed in memory and never saved. Files that are missing or changed are marked unavailable, not counted as detector misses.

```sh
.venv/bin/python -m research.evaluation.runner --corpus-root /path/to/authorized/corpus
.venv/bin/python -m research.evaluation.report
```

TruffleHog v3 and GitLeaks v8 are used when installed; missing or unsupported versions are skipped. TruffleHog runs with `--no-verification` and updates disabled; the evaluation must not use exposed credentials against provider APIs. Findings are matched conservatively by file and line within two lines; ambiguous matches and unlabeled extras are unknown. Outputs are `research/evaluation/results.json`, `.md` and `.csv`, all gitignored. Reported precision, recall and FPR are conditional on labeled, evaluated candidates. Since BreachTrace generated the candidate pool, the experiment cannot estimate how often all tools miss secrets outside that pool or population-level accuracy.

## 5. Optional ablation and calibration

```sh
.venv/bin/python -m research.evaluation.ablation --threshold 50
.venv/bin/python -m research.weights.calibration
```

Ablation uses the loaded research heuristic weights, not the deployed detector; it requires all four signal values. Pass `--weights PATTERN ENTROPY CONTEXT STRUCTURAL` to compare a different set. Calibration uses the scores recorded when each candidate was collected; changing weights does not retroactively alter those stored scores. A normalized score is not necessarily a predicted probability. If signals or scores are absent, the commands explain why and do not fabricate results. Run ablation before the report if its table is wanted in the report. The calibration plot is saved as `research/weights/calibration.png` when Matplotlib is installed.

To run the available steps with clear messages for missing inputs, use `.venv/bin/python -m research.run_all`. Add `--interactive` for manual labeling in a terminal and `--corpus-root /path/to/authorized/corpus` for scanner comparison. With a `GITHUB_TOKEN` in the shell, this command starts public GitHub collection; without one it skips collection. It does not automatically assign ground-truth labels based on tool agreement.

For the complete public-benchmark and synthetic pilot sequence without interactive labeling, use `.venv/bin/python -m research.run_all --benchmark`. This downloads the pinned public repositories, invokes installed external scanners offline, replaces the previous synthetic pilot, extracts line-associated CredData features, trains, ablates, and writes the report. These measurements and synthetic labels are not evidence of real credential validity.
