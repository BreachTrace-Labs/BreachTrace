from research.evaluation.creddata import line_labels
from research.evaluation.report import render


def test_conflicting_and_unknown_reviews_are_not_ground_truth():
    rows = [dict(LineStart='1', LineEnd='1', GroundTruth='T'),
            dict(LineStart='2', LineEnd='2', GroundTruth='T'),
            dict(LineStart='2', LineEnd='2', GroundTruth='F'),
            dict(LineStart='3', LineEnd='3', GroundTruth='X'),
            dict(LineStart='4', LineEnd='4', GroundTruth='F')]
    assert line_labels(rows) == {1: 'T', 4: 'F'}


def test_creddata_report_keeps_results_separate_from_other_labels():
    data = {'metrics': {'tp': 2, 'fp': 1, 'tn': 4, 'fn': 3, 'precision': 2 / 3},
            'repositories': [], 'dataset_revision': 'revision'}
    markdown, rows = render({'tools': {}}, [], [], creddata=data)
    assert '| 2 | 1 | 4 | 3 | 0.667 |' in markdown
    assert 'not exact credential-span matches' in markdown
    assert any(row['section'] == 'creddata_reviewed_lines' for row in rows)


def test_trufflehog_stdin_requires_unique_localizable_match(monkeypatch):
    import json
    from types import SimpleNamespace
    from research.evaluation.creddata import external_lines
    value = 'synthetic-demo-value'
    seen = []
    def fake(command, **kwargs):
        seen.append(command)
        return SimpleNamespace(returncode=0, stdout=(json.dumps({'Raw': value}) + '\n').encode())
    monkeypatch.setattr('research.evaluation.creddata.subprocess.run', fake)
    assert external_lines('TruffleHog', 'trufflehog', value.encode(), 'first\n' + value) == [2]
    assert external_lines('TruffleHog', 'trufflehog', value.encode(), value + '\n' + value) is None
    assert '--no-verification' in seen[0]
