"""
Tests for the harness -> /research/record payload mapping (B3).

`harness.py` imports boto3, google.cloud and azure at module scope, so the
module cannot be imported here. `_build_record_payload` is deliberately pure
and free of SDK calls, so it is loaded directly from source instead — this is
the mapping that decides what the research dataset actually contains, and it is
worth testing even though its module is otherwise unreachable.
"""

import pathlib
import types

import pytest

_HARNESS = pathlib.Path(__file__).resolve().parents[1] / "research" / "harness.py"


def _load_payload_builder():
    """
    Extract and exec just `_build_record_payload` from harness.py.

    Importing the module would pull in three cloud SDKs. Parsing out the one
    pure function keeps this test runnable in CI with no credentials and no
    optional dependencies, which is how the rest of the suite works.
    """
    import ast

    tree = ast.parse(_HARNESS.read_text())
    func = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_build_record_payload"
    )
    module = types.ModuleType("harness_fragment")
    exec(compile(ast.Module(body=[func], type_ignores=[]), str(_HARNESS), "exec"), module.__dict__)
    return module._build_record_payload


build_payload = _load_payload_builder()


def _result(**overrides):
    base = {
        "run_number": 3,
        "experiment_group": "B",
        "platform": "gcp",
        "detection_time_s": 14.2,
        "report_time_s": 38.7,
        "first_use_time_s": 9.1,
        "api_calls_made": ["storage.buckets.list"],
        "overall_severity": "HIGH",
        "incident_id": "inc-42",
    }
    base.update(overrides)
    return base


# ==========================================================================
# Straightforward mapping
# ==========================================================================

def test_maps_core_fields():
    payload = build_payload(_result())

    assert payload["incident_id"] == "inc-42"
    assert payload["run_number"] == 3
    assert payload["experiment_group"] == "B"
    assert payload["platform"] == "gcp"
    assert payload["detection_time_s"] == 14.2
    assert payload["report_time_s"] == 38.7
    assert payload["api_calls_made"] == ["storage.buckets.list"]
    assert payload["overall_severity"] == "HIGH"


def test_platform_defaults_to_aws():
    payload = build_payload({"run_number": 1})
    assert payload["platform"] == "aws"


def test_missing_lists_become_empty_not_none():
    """The endpoint types these as list[str]; None would fail validation."""
    payload = build_payload({"run_number": 1})
    assert payload["api_calls_made"] == []
    assert payload["impact_categories"] == []


def test_latency_precision_is_preserved():
    """Sub-second precision is the whole reason the columns became Float."""
    payload = build_payload(_result(detection_time_s=1.4))
    assert payload["detection_time_s"] == 1.4


# ==========================================================================
# first_external_use_s — the metric that must not be polluted
# ==========================================================================

def test_first_external_use_is_omitted_when_no_external_use_detected():
    """
    `first_external_use_s` means "seconds to first NON-TEAM IP usage" and is the
    paper's Contribution 3. The harness's `first_use_time_s` is just how long
    its own scripted calls took. Writing ours into that column would mean the
    published latency figure is measuring the harness, not real attackers.
    """
    payload = build_payload(_result(first_use_time_s=9.1))

    assert "first_external_use_s" not in payload


def test_first_external_use_is_mapped_when_external_use_detected():
    payload = build_payload(_result(first_use_time_s=9.1, external_use_detected=True))

    assert payload["first_external_use_s"] == 9.1
    assert payload["external_use_detected"] is True


def test_external_use_flag_defaults_false():
    assert build_payload({"run_number": 1})["external_use_detected"] is False


# ==========================================================================
# Shape compatibility with the endpoint
# ==========================================================================

def test_payload_validates_against_the_endpoint_model():
    """
    The contract test: whatever the harness builds must be accepted by
    ExperimentRunIn, or every run fails at record time.
    """
    from routers.research import ExperimentRunIn

    run = ExperimentRunIn(**build_payload(_result(external_use_detected=True)))

    assert run.platform == "gcp"
    assert run.detection_time_s == 14.2
    assert run.first_external_use_s == 9.1
    assert run.overall_severity == "HIGH"


@pytest.mark.parametrize("platform", ["aws", "gcp", "azure"])
def test_payload_validates_for_every_runner_platform(platform):
    from routers.research import ExperimentRunIn

    run = ExperimentRunIn(**build_payload(_result(platform=platform)))
    assert run.platform == platform


def test_failed_run_still_produces_a_valid_payload():
    """
    A run that never completed is still data — it drives completion_rate. It
    must record rather than raise.
    """
    from routers.research import ExperimentRunIn

    failed = {
        "run_number": 9,
        "platform": "azure",
        "status": "failed",
        "detection_time_s": None,
        "report_time_s": None,
        "overall_severity": None,
    }
    run = ExperimentRunIn(**build_payload(failed))

    assert run.platform == "azure"
    assert run.detection_time_s is None
    assert run.overall_severity is None
