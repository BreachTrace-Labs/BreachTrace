# SecretBench Track A accuracy tests
# TODO (Yash/Day 6): run detector against data/secretbench_aws_200.csv and compute P/R/F1.

import csv
import os
import pytest
from detector import scan

DATASET_PATH = os.path.join(os.path.dirname(__file__), "../../data/secretbench_aws_200.csv")


@pytest.mark.skipif(not os.path.exists(DATASET_PATH), reason="SecretBench dataset not downloaded yet")
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
