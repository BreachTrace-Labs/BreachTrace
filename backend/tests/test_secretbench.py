"""
Track A — detector accuracy against the SecretBench labelled dataset.

BLOCKED ON PROCUREMENT, NOT ON EFFORT. Read this before re-planning Track A.

The sprint plan (and the original Week-1 doc) said: "git clone
https://github.com/setu1421/SecretBench, filter the CSV for secret_type='AWS',
export 200 rows." **That is not possible.** The repository contains no secrets
data — only a regex spreadsheet, metadata folders and a roadmap.

The labelled dataset (97,479 secrets, 15,084 true) lives in Google BigQuery, and
the project README requires:

    1. a Google Cloud account,
    2. contacting the authors, and
    3. signing a data protection agreement,

after which access is granted per email address. Steps 2 and 3 have real lead
time and must be started by a person — they cannot be automated.

Until that lands there is NO external validation of detector accuracy. The
numbers in test_gcp_azure_detection_accuracy.py come from a fixture this team
wrote, and must be quoted with that caveat.

What IS validated externally today: SecretBench's published regular expressions
are MIT-licensed and public, and test_secretbench_pattern_parity.py compares our
patterns against them. That found five real coverage gaps. It validates pattern
DEFINITIONS, not accuracy on real code — it is not a substitute for this file.

Reference: Basak et al., "SecretBench: A Dataset of Software Secrets", MSR 2023.
DOI 10.5281/zenodo.7555981
"""

import csv
import os
import pytest
from detector import scan

DATASET_PATH = os.path.join(os.path.dirname(__file__), "../../data/secretbench_aws_200.csv")


@pytest.mark.skipif(not os.path.exists(DATASET_PATH), reason="SecretBench dataset requires a signed data protection agreement — see module docstring")
def test_secretbench_precision_recall():
    true_positives = 0
    false_negatives = 0
    false_positives = 0

    with open(DATASET_PATH, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            snippet = row.get("snippet", "")
            ground_truth = row.get("ground_truth", "false").lower() == "true"
            matches = scan(snippet)
            detected = len(matches) > 0

            if ground_truth and detected:
                true_positives += 1
            elif ground_truth and not detected:
                false_negatives += 1
            elif not ground_truth and detected:
                false_positives += 1

    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) else 0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0

    print(f"\nPrecision: {precision:.2%}  Recall: {recall:.2%}  F1: {f1:.2%}")
    assert recall >= 0.90, f"Recall {recall:.2%} below 90% target"
