"""Synthetic independent labels; none are the user's historical CSV files."""
import pytest

from research.gcp_ground_truth import GroundTruthError, MAX_CSV_BYTES, evaluate


def event(insert_id, *, category='data_access', success=True, error_code=None):
    return {'impact_category': category, 'success': success, 'error_code': error_code,
            'raw_data': {'_gcp_log_entry': {'insert_id': insert_id}}}


def mapping(**values):
    return {'unit':'audit_records', 'command_column':None, 'record_id_column':'insert_id',
            'category_column':'expected_category', 'outcome_column':'expected_outcome', **values}


def test_matches_only_unique_insert_ids_and_measures_label_agreement():
    evidence = {'events': [event('a'), event('b', category=None, success=False, error_code='7'),
                           event('ambiguous'), event('ambiguous')]}
    csv = (b'insert_id,expected_category,expected_outcome\n'
           b'a,data_access,success\nb,privilege_escalation,denied\n'
           b'missing,data_access,failed\nambiguous,data_access,success\n')
    result = evaluate(csv, evidence, mapping())
    assert (result['matched_record_count'], result['missing_record_count'], result['ambiguous_record_count']) == (2, 1, 1)
    assert result['classification']['accuracy'] == 0.5
    assert result['outcome']['accuracy'] == 1.0
    assert {'expected':'privilege_escalation', 'actual':'unclassified', 'count':1} in result['classification']['confusion']
    assert result['command_count'] is None
    assert 'insert_id' not in str(result)


def test_failed_label_accepts_denied_and_not_found_without_calling_either_success():
    evidence = {'events':[event('a', success=False, error_code='7'), event('b', success=False, error_code='5')]}
    data = b'insert_id,expected_outcome\na,failed\nb,failed\n'
    result = evaluate(data, evidence, mapping(category_column=None))
    assert result['outcome']['correct'] == 2 and result['outcome']['compared'] == 2
    assert result['classification']['accuracy'] is None


def test_command_rows_do_not_invent_record_matches_or_detection_latency():
    data = b'command\nread-one\nread-two\n'
    result = evaluate(data, {'events':[event('x')]}, {'unit':'commands', 'command_column':'command'})
    assert result['command_count'] == 2 and result['matched_record_count'] is None
    assert result['classification'] is None and result['outcome'] is None
    assert 'read-one' not in str(result)
    assert any('latency' in value for value in result['limitations'])


@pytest.mark.parametrize('content', [b'', b'x,y\n1\n', b'insert_id,expected_category,expected_outcome\na,other,success\n',
                                     b'insert_id,expected_category,expected_outcome\na,data_access,success\na,data_access,success\n'])
def test_malformed_unsupported_or_repeated_labels_are_rejected(content):
    with pytest.raises(GroundTruthError):
        evaluate(content, {'events':[]}, mapping())


def test_limits_and_missing_columns_are_explicit():
    with pytest.raises(GroundTruthError, match='1 MB'):
        evaluate(b'x' * (MAX_CSV_BYTES + 1), {'events':[]}, mapping())
    with pytest.raises(GroundTruthError, match='column'):
        evaluate(b'different\nvalue\n', {'events':[]}, mapping())
