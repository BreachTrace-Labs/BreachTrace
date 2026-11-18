"""Synthetic fixtures only; these are not the operator's historical evidence."""
import json

import pytest

from research.gcp_import import ImportErrorSafe, MAX_FILE_BYTES, import_export

PAYLOAD = {'project_id':'bt-project', 'gcp_project_id':'demo-project',
           'principal_email':'svc@demo-project.iam.gserviceaccount.com', 'scenario_id':'GCP-DATA-01',
           'start_utc':'2026-01-01T00:00:00Z', 'end_utc':'2026-01-01T01:00:00Z'}


def row(insert='record-1'):
    return {'insertId': insert, 'logName':'projects/demo-project/logs/cloudaudit.googleapis.com%2Fdata_access',
            'timestamp':'2026-01-01T00:10:00.123456789Z', 'receiveTimestamp':'2026-01-01T00:10:01Z',
            'resource':{'type':'gcs_bucket'},
            'protoPayload':{'@type':'type.googleapis.com/google.cloud.audit.AuditLog',
                            'authenticationInfo':{'principalEmail': PAYLOAD['principal_email']},
                            'serviceName':'storage.googleapis.com', 'methodName':'storage.objects.get',
                            'requestMetadata':{'callerIp':'192.0.2.1', 'callerSuppliedUserAgent':'gcloud'},
                            'resourceName':'projects/_/buckets/test/objects/example.txt',
                            'request':{'arbitrary':'SENSITIVE_UPLOAD_CONTENT'}}}


def test_import_reuses_normalizer_classifier_and_preserves_provider_precision():
    content = json.dumps([row(), row(), row('record-2')]).encode()
    result = import_export(content, PAYLOAD)
    assert result['evidence_source'] == 'imported_json'
    assert (result['input_record_count'], result['record_count'], result['duplicate_record_count']) == (3, 2, 1)
    assert result['categories'] == {'data_access':2}
    assert result['events'][0]['raw_data']['_gcp_log_entry']['timestamp_precise'].endswith('.123456789Z')
    assert 'SENSITIVE_UPLOAD_CONTENT' not in str(result)
    assert len(result['source_sha256']) == 64


@pytest.mark.parametrize('change', ['project', 'principal', 'window', 'status', 'shape'])
def test_invalid_or_out_of_scope_records_fail_closed(change):
    data = row()
    if change == 'project': data['logName'] = 'projects/other/logs/cloudaudit.googleapis.com%2Fdata_access'
    if change == 'principal': data['protoPayload']['authenticationInfo']['principalEmail'] = 'other@example.test'
    if change == 'window': data['timestamp'] = '2026-01-01T02:00:00Z'
    if change == 'status': data['protoPayload']['status'] = {'code':'not-a-number'}
    if change == 'shape': data.pop('protoPayload')
    with pytest.raises(ImportErrorSafe) as exc:
        import_export(json.dumps([data]).encode(), PAYLOAD)
    assert 'SENSITIVE_UPLOAD_CONTENT' not in str(exc.value)


def test_same_provider_identity_with_different_content_is_rejected():
    first, second = row(), row()
    second['protoPayload']['methodName'] = 'storage.objects.create'
    with pytest.raises(ImportErrorSafe, match='conflicts'):
        import_export(json.dumps([first, second]).encode(), PAYLOAD)


def test_import_limits_and_missing_ids_do_not_fabricate_deduplication():
    with pytest.raises(ImportErrorSafe, match='5 MB'):
        import_export(b'x' * (MAX_FILE_BYTES + 1), PAYLOAD)
    with pytest.raises(ImportErrorSafe, match='2,000'):
        import_export(json.dumps([{}] * 2001).encode(), PAYLOAD)
    no_id = row(); no_id.pop('insertId')
    result = import_export(json.dumps([no_id, no_id]).encode(), PAYLOAD)
    assert result['record_count'] == 2 and result['duplicate_record_count'] == 0


def test_import_preserves_failed_outcomes_and_nanosecond_window_boundary():
    missing, denied = row('missing'), row('denied')
    missing['protoPayload']['status'] = {'code':5}
    denied['protoPayload']['status'] = {'code':7}
    result = import_export(json.dumps([missing, denied]).encode(), PAYLOAD)
    assert result['failed_count'] == 2
    assert [event['error_code'] for event in result['events']] == ['5', '7']
    boundary = {**PAYLOAD, 'end_utc':'2026-01-01T00:10:00.123456Z'}
    with pytest.raises(ImportErrorSafe, match='outside'):
        import_export(json.dumps([missing]).encode(), boundary)
