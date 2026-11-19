"""Research logic checks; no provider requests or audit datasets are created."""
import hashlib
import json
from types import SimpleNamespace

import pytest

from research.dataset import collector
from research.dataset.labeler import _safe_label
from research.evaluation.metrics import evaluate
from research.evaluation.report import render
from research.evaluation.runner import _external, _match, _verified_file
from research.evaluation.snapshot_comparison import _external as snapshot_external
from research.weights.calibration import buckets
from research.weights.trainer import extract


def test_metrics_keep_unknown_and_zero_denominators_unavailable():
    result = evaluate([{'label': 'TP', 'found': True}, {'label': 'TP', 'found': None},
                       {'label': 'FP', 'found': False}])
    assert result['tp'] == 1 and result['tn'] == 1 and result['unavailable'] == 1
    assert result['precision'] == 1 and result['recall'] == 1 and result['fpr'] == 0
    assert evaluate([])['precision'] is None and evaluate([])['f1'] is None


def test_ambiguous_matches_are_unavailable_not_misses():
    rows = [{'line_number': 10}, {'line_number': 11}, {'line_number': 25}]
    assert _match(rows, [10, 30]) == ([None, None, False], 2)
    assert _match(rows, None) == ([None, None, None], 0)


def test_source_hash_and_paths_are_verified(tmp_path):
    base = tmp_path / 'team' / 'repo' / ('a' * 40)
    base.mkdir(parents=True)
    source = base / 'file.txt'
    source.write_bytes(b'ordinary text\n')
    blob = hashlib.sha1(b'blob 14\0ordinary text\n').hexdigest()
    row = {'repository': 'team/repo', 'revision': 'a' * 40, 'path': 'file.txt', 'file_sha': blob}
    assert _verified_file(tmp_path.resolve(), row) == source
    assert _verified_file(tmp_path.resolve(), {**row, 'file_sha': 'b' * 40}) is None
    assert _verified_file(tmp_path.resolve(), {**row, 'path': '../../outside'}) is None


def test_collector_and_labeler_do_not_persist_source_or_extra_fields(monkeypatch):
    match = SimpleNamespace(line_number=1, credential_type='aws_access_key', credential_hint='mask-private-content')
    monkeypatch.setattr(collector, 'scan_text', lambda text, **_kwargs: [] if text == 'settings.env' else [match])
    rows = collector._candidate_rows('team/repo', 'a' * 40, 'settings.env', 'b' * 40, b'private-content')
    assert len(rows) == 1 and 'private-content' not in json.dumps(rows)
    row = {**rows[0], 'raw_line_redacted': 'private-content', 'context_lines_redacted': ['private-content'],
           'extra': 'private-content'}
    assert 'private-content' not in json.dumps(_safe_label(row, 'TP'))


def test_external_scanner_disables_verification(monkeypatch, tmp_path):
    seen = []
    def invoke(command, **kwargs):
        seen.append(command)
        return SimpleNamespace(returncode=0, stdout=b'', stderr=b'')
    monkeypatch.setattr('research.evaluation.runner.subprocess.run', invoke)
    assert _external('TruffleHog', 'trufflehog', tmp_path / 'file') == []
    assert '--no-verification' in seen[0] and '--no-update' in seen[0]


def test_scanner_failure_or_unlocatable_findings_are_not_counted_as_misses(monkeypatch, tmp_path):
    monkeypatch.setattr('research.evaluation.runner.subprocess.run',
                        lambda *_args, **_kwargs: SimpleNamespace(returncode=1, stdout=b'', stderr=b'error'))
    assert _external('GitLeaks', 'gitleaks', tmp_path / 'file') is None
    monkeypatch.setattr('research.evaluation.runner.subprocess.run',
                        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout=b'{}\n', stderr=b''))
    assert _external('TruffleHog', 'trufflehog', tmp_path / 'file') is None


def test_training_rejects_missing_features_and_calibration_never_invents_scores():
    with pytest.raises(ValueError, match='lack four'):
        extract([{'label': 'TP', 'signals': {}}])
    result = buckets([{'label': 'TP', 'score': None}, {'label': 'FP', 'score': 100}])
    assert sum(item['count'] for item in result) == 1
    assert result[-1]['actual_tp_rate'] == 0 and result[0]['actual_tp_rate'] is None


def test_report_marks_missing_measurements_unavailable():
    markdown, rows = render({'tools': {}, 'files': 0}, [], [])
    assert 'N/A' in markdown and 'does not evaluate the deployed detector' in markdown
    assert rows


def test_snapshot_scanners_stream_input_and_do_not_verify(monkeypatch):
    calls = []
    def invoke(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout=b'', stderr=b'')
    monkeypatch.setattr('research.evaluation.snapshot_comparison.subprocess.run', invoke)
    assert snapshot_external('TruffleHog', 'trufflehog', b'ordinary text') == 0
    assert '--no-verification' in calls[0][0] and calls[0][0][-1] == 'stdin'
    assert calls[0][1]['input'] == b'ordinary text'


def test_report_includes_observed_snapshot_separately_from_accuracy():
    snapshot = {'text_files': 1, 'tools': {'BreachTrace': {'available': True, 'findings': 1,
                'files_with_findings': 1, 'files_failed': 0}}}
    markdown, rows = render({'tools': {}, 'files': 0}, [], [], snapshot=snapshot)
    assert '| BreachTrace | 1 | 1 | 0 |' in markdown
    assert 'not accuracy metrics' in markdown
    assert any(row['section'] == 'snapshot_comparison' for row in rows)
