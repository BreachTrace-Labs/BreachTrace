"""
GCP / Azure detection accuracy measurement (S3-Y3).

Track A validates the AWS detector against SecretBench. There is no comparable
public dataset for GCP service-account keys or Azure service principals, so this
is a hand-built 60-sample set: 20 GCP positives, 20 Azure positives, 20 near-miss
negatives drawn from things that genuinely appear in real repositories (trace
IDs, git SHAs, ordinary emails, lookalike domains).

The negatives are the point. The Azure client-secret pattern is
`[A-Za-z0-9.\\-_~]{34,}` gated only on a nearby keyword, which is far broader
than the AWS or GCP anchors. That breadth is a known false-positive risk, and
the sprint plan calls for quantifying it rather than guessing at it.

The fixture lives under tests/ rather than data/ because `data/` is gitignored —
a dataset that cannot be committed cannot back a reproducible claim.

Run just this file to print the metrics:
    .venv/bin/python -m pytest backend/tests/test_gcp_azure_detection_accuracy.py -s -q
"""

import csv
import os

import pytest

from detector.patterns import find_azure_credentials, find_gcp_credentials

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "gcp_azure_detection_set.csv")

# Precision floors. Recall is allowed to be lower than precision by design: a
# missed credential produces no incident, while a false positive produces a
# bogus one that wastes responder time and pollutes the research numbers.
MIN_GCP_PRECISION = 0.95
MIN_GCP_RECALL = 0.90
MIN_AZURE_PRECISION = 0.85
MIN_AZURE_RECALL = 0.90


def _load_samples():
    with open(FIXTURE, newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            # Fixture stores newlines as the literal two characters \n so that
            # every sample stays on one CSV line and stays diff-readable.
            row["snippet"] = row["snippet"].replace("\\n", "\n")
            row["ground_truth"] = row["ground_truth"].strip().lower() == "true"
            yield row


SAMPLES = list(_load_samples())


def _score(detector, target_platform):
    """Return (tp, fp, fn, [failing ids]) for one detector over the whole set."""
    tp = fp = fn = 0
    failures = []

    for row in SAMPLES:
        detected = bool(detector(row["snippet"]))
        # A sample is a positive for this detector only if it is its platform.
        expected = row["ground_truth"] and row["platform"] == target_platform

        if expected and detected:
            tp += 1
        elif expected and not detected:
            fn += 1
            failures.append(f"FN {row['id']} ({row['note']})")
        elif not expected and detected:
            fp += 1
            failures.append(f"FP {row['id']} ({row['note']})")

    return tp, fp, fn, failures


def _metrics(tp, fp, fn):
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return precision, recall, f1


# ==========================================================================
# Fixture integrity
# ==========================================================================

def test_fixture_has_expected_composition():
    assert len(SAMPLES) == 68
    gcp = [s for s in SAMPLES if s["platform"] == "gcp" and s["ground_truth"]]
    azure = [s for s in SAMPLES if s["platform"] == "azure" and s["ground_truth"]]
    negatives = [s for s in SAMPLES if not s["ground_truth"]]
    assert len(gcp) == 20
    assert len(azure) == 20
    # 20 ordinary near-misses (N01–N20) plus 8 adversarial ones (N21–N28) that
    # specifically target the Azure client-secret pattern's keyword gate.
    assert len(negatives) == 28


def test_adversarial_negatives_are_present():
    """
    Guard against the negative set being quietly softened. Without N21–N28 the
    Azure detector scores a meaningless 1.000 precision: the earlier 60-sample
    set contained nothing that probed its actual weakness.
    """
    adversarial = [s for s in SAMPLES if s["id"] in {f"N{n}" for n in range(21, 29)}]
    assert len(adversarial) == 8


def test_sample_ids_are_unique():
    ids = [s["id"] for s in SAMPLES]
    assert len(ids) == len(set(ids))


# ==========================================================================
# Measured accuracy
# ==========================================================================

def test_gcp_detection_accuracy():
    tp, fp, fn, failures = _score(find_gcp_credentials, "gcp")
    precision, recall, f1 = _metrics(tp, fp, fn)

    print(
        f"\n[GCP]   TP={tp} FP={fp} FN={fn} | "
        f"Precision={precision:.3f} Recall={recall:.3f} F1={f1:.3f}"
    )
    for failure in failures:
        print(f"        {failure}")

    assert precision >= MIN_GCP_PRECISION, f"GCP precision {precision:.3f}: {failures}"
    assert recall >= MIN_GCP_RECALL, f"GCP recall {recall:.3f}: {failures}"


def test_azure_detection_accuracy():
    tp, fp, fn, failures = _score(find_azure_credentials, "azure")
    precision, recall, f1 = _metrics(tp, fp, fn)

    print(
        f"\n[AZURE] TP={tp} FP={fp} FN={fn} | "
        f"Precision={precision:.3f} Recall={recall:.3f} F1={f1:.3f}"
    )
    for failure in failures:
        print(f"        {failure}")

    assert precision >= MIN_AZURE_PRECISION, f"Azure precision {precision:.3f}: {failures}"
    assert recall >= MIN_AZURE_RECALL, f"Azure recall {recall:.3f}: {failures}"


# ==========================================================================
# Specific false-positive shapes worth pinning individually
# ==========================================================================

@pytest.mark.parametrize("sample_id", ["N01", "N02", "N07", "N10", "N13", "N16", "N19"])
def test_bare_uuid_without_azure_context_is_not_a_credential(sample_id):
    """
    Repositories are full of UUIDs — trace IDs, request IDs, build IDs. The
    keyword-context gate is the only thing separating them from a client ID, so
    it needs direct coverage.
    """
    sample = next(s for s in SAMPLES if s["id"] == sample_id)
    assert find_azure_credentials(sample["snippet"]) == [], f"{sample_id}: {sample['note']}"


@pytest.mark.parametrize("sample_id", ["N03", "N04", "N08", "N14", "N18"])
def test_ordinary_and_lookalike_emails_are_not_gcp_credentials(sample_id):
    """`.iam.example.com` and `.iam.company.internal` must not match."""
    sample = next(s for s in SAMPLES if s["id"] == sample_id)
    assert find_gcp_credentials(sample["snippet"]) == [], f"{sample_id}: {sample['note']}"


def test_connection_string_without_account_key_is_rejected():
    sample = next(s for s in SAMPLES if s["id"] == "N09")
    types = {m.credential_type for m in find_azure_credentials(sample["snippet"])}
    assert "azure_storage_connection" not in types


def test_git_sha_is_not_a_gcp_private_key_id():
    sample = next(s for s in SAMPLES if s["id"] == "N05")
    assert find_gcp_credentials(sample["snippet"]) == []
