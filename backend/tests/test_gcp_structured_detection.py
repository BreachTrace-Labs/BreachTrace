import json

from detector.match_resolver import resolve_match
from detector.scanner import scan, scan_text


def key(email='worker@demo-project.iam.gserviceaccount.com', key_id='a' * 40):
    return {'type': 'service_account', 'project_id': 'demo-project',
            'private_key_id': key_id, 'client_email': email,
            'private_key': '-----BEGIN PRIVATE KEY-----\nSYNTHETIC\n-----END PRIVATE KEY-----\n',
            'token_uri': 'https://oauth2.googleapis.com/token'}


def test_complete_json_is_collectable_without_exposing_private_material():
    source = json.dumps(key(), indent=2)
    match, = scan_text(source)
    assert match.structured_key and match.project_id == 'demo-project'
    assert match.private_key_id == 'a' * 40
    assert resolve_match(match).is_collectable
    assert 'SYNTHETIC' not in repr(match)


def test_incomplete_json_is_only_an_identifier_observation():
    incomplete = key()
    del incomplete['private_key']
    match, = scan_text(json.dumps(incomplete))
    assert not resolve_match(match).is_collectable
    assert match.private_key_id is None


def test_added_private_key_with_unchanged_identity_is_detected():
    lines = json.dumps(key(), indent=2).splitlines()
    diff = '\n'.join(('+' if '"private_key":' in line else ' ') + line for line in lines)
    match, = scan(diff)
    assert match.structured_key and resolve_match(match).is_collectable
    assert match.line_number == next(i for i, line in enumerate(diff.splitlines(), 1) if line.startswith('+'))


def test_removing_key_does_not_create_a_detection():
    lines = json.dumps(key(), indent=2).splitlines()
    diff = '\n'.join(('-' if '"private_key":' in line else ' ') + line for line in lines)
    assert scan(diff) == []


def test_two_keys_for_one_account_are_not_confused():
    source = json.dumps([key(key_id='a' * 40), key(key_id='b' * 40)], indent=2)
    matches = scan_text(source)
    assert {m.private_key_id for m in matches} == {'a' * 40, 'b' * 40}


def test_key_id_from_neighbouring_object_is_not_associated():
    first = key(); del first['private_key']
    second = key(email='other@demo-project.iam.gserviceaccount.com', key_id='b' * 40)
    matches = scan_text(json.dumps([first, second], indent=2))
    first_match = next(m for m in matches if m.client_email.startswith('worker@'))
    assert first_match.private_key_id is None
    assert not resolve_match(first_match).is_collectable


def test_json_encoded_key_string_is_detected_without_exposing_private_material():
    value = json.dumps(json.dumps(key()))
    match, = scan_text('const credentials = ' + value + ';')
    assert match.structured_key and match.project_id == 'demo-project'
    assert match.private_key_id == 'a' * 40 and resolve_match(match).is_collectable
    assert 'SYNTHETIC' not in repr(match) and 'PRIVATE KEY' not in repr(match)


def test_encoded_key_in_diff_must_be_added_and_reports_original_line():
    encoded = json.dumps(json.dumps(key()))
    assert scan('@@ -1 +1 @@\n-' + encoded) == []
    match, = scan('@@ -1 +1 @@\n context\n+' + encoded)
    assert match.line_number == 3 and match.structured_key


def test_incomplete_encoded_key_is_not_collectable():
    incomplete = key()
    del incomplete['private_key']
    matches = scan_text('const credentials = ' + json.dumps(json.dumps(incomplete)))
    assert not any(resolve_match(match).is_collectable for match in matches)


def test_encoded_json_with_multiple_keys_does_not_mix_fields():
    incomplete = key()
    del incomplete['private_key']
    encoded = json.dumps(json.dumps([incomplete, key(email='other@demo-project.iam.gserviceaccount.com')]))
    matches = scan_text('const credentials = ' + encoded)
    assert not any(match.structured_key for match in matches)
