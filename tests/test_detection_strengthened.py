"""Exercise the research scoring bridge using an existing detector fixture."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))

from detector.scanner import scan_text  # noqa: E402
from research.dataset.scoring_bridge import score_match  # noqa: E402
from research.scoring import canonical_signals, load_weights, score_finding  # noqa: E402


def test_existing_fixture_yields_research_signals():
    source = (ROOT / 'backend/tests/test_aws_pattern.py').read_text(encoding='utf-8')
    findings = [score_match(match, source) for match in scan_text(source)]
    assert any(finding.score > 0 and set(finding.signals) == {'pattern', 'entropy', 'context', 'structural'}
               for finding in findings)


def test_scoring_shape_and_weight_validation(tmp_path):
    result = score_finding('pattern-value', 'api key', 'key = "pattern-value"')
    assert isinstance(result['score'], int) and 0 <= result['score'] <= 100
    assert all(isinstance(value, float) for value in result['signals'].values())
    path = tmp_path / 'weights.json'
    path.write_text('{"pattern_specificity":0.4,"entropy":0.2,"context":0.2,"structural":0.2,"trained_on":80}')
    weights, count = load_weights(path)
    assert weights['pattern'] == 0.4 and count == 80
    path.write_text('{"pattern_specificity":-1,"entropy":1,"context":1,"structural":0,"trained_on":80}')
    assert load_weights(path)[0]['pattern'] == -1
    path.write_text('{"pattern_specificity":-1,"entropy":1,"context":1,"structural":0}')
    assert load_weights(path)[1] is None
    assert canonical_signals({'pattern_specificity': 1, 'entropy_norm': .5, 'context_norm': .5, 'structural_norm': 0})['pattern'] == 1


def test_trainer_accepts_scoreable_labels_and_outputs_loadable_weights(tmp_path, monkeypatch):
    from research.evaluation.ablation import run
    from research.weights import trainer
    rows = [{'label': 'TP' if index % 2 else 'FP', 'signals': {
        'pattern': 1.0, 'entropy': .9 if index % 2 else .2,
        'context': .75 if index % 2 else .25, 'structural': .5}}
        for index in range(80)]
    output = tmp_path / 'weights.json'
    monkeypatch.setattr(trainer, 'read_jsonl', lambda _path: rows)
    monkeypatch.setattr(trainer, 'OUTPUT', output)
    trainer.main()
    weights, count = load_weights(output)
    assert count == 80 and abs(sum(weights.values()) - 1) < 1e-6
    assert len(run(rows, [weights[key] for key in trainer.FEATURES], 50)['ablations']) == 4
