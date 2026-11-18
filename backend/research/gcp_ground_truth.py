"""Compare independently supplied labels with existing historical evidence."""
import csv
import hashlib
import io
from collections import Counter, defaultdict

MAX_CSV_BYTES = 1024 * 1024
MAX_ROWS = 2000
_CATEGORIES = {'reconnaissance', 'data_access', 'exfiltration', 'resource_abuse',
               'privilege_escalation', 'financial_abuse', 'communication_abuse', 'code_compromise', 'unclassified'}
_OUTCOMES = {'success', 'failed', 'denied', 'not_found'}


class GroundTruthError(ValueError):
    """A safe validation message that does not reveal CSV contents."""


def evaluate(data: bytes, evidence: dict, mapping: dict) -> dict:
    if len(data) > MAX_CSV_BYTES:
        raise GroundTruthError('The CSV file exceeds the 1 MB limit.')
    try:
        reader = csv.DictReader(io.StringIO(data.decode('utf-8-sig'), newline=''), strict=True)
        headers = reader.fieldnames
        if not headers or len(headers) > 50 or any(not name or len(name) > 100 for name in headers) or len(set(headers)) != len(headers):
            raise GroundTruthError('The CSV needs unique, non-empty column names (up to 50 columns).')
        required = ([mapping.get('command_column')] if mapping['unit'] == 'commands' else
                    [mapping.get('record_id_column'), mapping.get('category_column'), mapping.get('outcome_column')])
        required = [name for name in required if name]
        if any(name not in headers for name in required):
            raise GroundTruthError('A selected column was not found in the CSV header.')
        rows = []
        for row in reader:
            if len(rows) >= MAX_ROWS:
                raise GroundTruthError('The CSV exceeds the 2,000-row limit.')
            if None in row or any(value is None for value in row.values()):
                raise GroundTruthError('A CSV row has a different number of fields from the header.')
            rows.append(row)
    except (UnicodeDecodeError, csv.Error, RecursionError):
        raise GroundTruthError('The file must be valid UTF-8 CSV.') from None
    if not rows:
        raise GroundTruthError('The CSV must contain at least one data row.')
    digest = hashlib.sha256(data).hexdigest()
    result = {'unit': mapping['unit'], 'source_sha256': digest, 'csv_row_count': len(rows),
              'evidence_record_count': len(evidence.get('events', [])),
              'limitations': ['CSV labels are operator supplied and not independently verified.',
                              'Historical evidence does not measure live detection latency.']}
    if mapping['unit'] == 'commands':
        if any(not row[mapping['command_column']].strip() for row in rows):
            raise GroundTruthError('Every command row must have a value in the selected column.')
        result.update({'command_count': len(rows), 'matched_record_count': None,
                       'classification': None, 'outcome': None})
        result['limitations'].append('One row represents one operator-labelled command; command-to-record matches and completeness were not evaluated.')
        return result

    by_id = defaultdict(list)
    for event in evidence.get('events', []):
        raw = event.get('raw_data') if isinstance(event, dict) else None
        meta = raw.get('_gcp_log_entry') if isinstance(raw, dict) else None
        insert_id = meta.get('insert_id') if isinstance(meta, dict) else None
        if isinstance(insert_id, str) and insert_id:
            by_id[insert_id].append(event)

    seen = set()
    matched = missing = ambiguous = 0
    classifications = Counter()
    outcomes = Counter()
    for index, row in enumerate(rows, start=1):
        insert_id = row[mapping['record_id_column']].strip()
        if not insert_id or insert_id in seen:
            raise GroundTruthError(f'CSV row {index} has a missing or repeated record ID.')
        seen.add(insert_id)
        category = row[mapping['category_column']].strip().lower() if mapping.get('category_column') else ''
        outcome = row[mapping['outcome_column']].strip().lower() if mapping.get('outcome_column') else ''
        if category and category not in _CATEGORIES:
            raise GroundTruthError(f'CSV row {index} has an unsupported expected category.')
        if outcome and outcome not in _OUTCOMES:
            raise GroundTruthError(f'CSV row {index} has an unsupported expected outcome.')
        if not category and not outcome:
            raise GroundTruthError(f'CSV row {index} has no expected category or outcome.')
        candidates = by_id.get(insert_id, [])
        if not candidates:
            missing += 1
            continue
        if len(candidates) != 1:
            ambiguous += 1
            continue
        matched += 1
        event = candidates[0]
        if category:
            classifications[(category, event.get('impact_category') or 'unclassified')] += 1
        if outcome:
            actual = ('success' if event.get('success') is True else 'denied' if event.get('error_code') == '7'
                      else 'not_found' if event.get('error_code') == '5' else 'failed')
            outcomes[(outcome, actual)] += 1

    classified_total = sum(classifications.values())
    classified_correct = sum(n for (expected, actual), n in classifications.items() if expected == actual)
    outcome_total = sum(outcomes.values())
    outcome_correct = sum(n for (expected, actual), n in outcomes.items()
                          if expected == actual or (expected == 'failed' and actual in {'denied', 'not_found'}))
    result.update({
        'command_count': None, 'matched_record_count': matched, 'missing_record_count': missing,
        'ambiguous_record_count': ambiguous,
        'classification': {'compared': classified_total, 'correct': classified_correct,
                           'accuracy': classified_correct / classified_total if classified_total else None,
                           'confusion': [{'expected': e, 'actual': a, 'count': n} for (e, a), n in sorted(classifications.items())]},
        'outcome': {'compared': outcome_total, 'correct': outcome_correct,
                    'accuracy': outcome_correct / outcome_total if outcome_total else None,
                    'confusion': [{'expected': e, 'actual': a, 'count': n} for (e, a), n in sorted(outcomes.items())]},
    })
    result['limitations'].append('Accuracy covers uniquely matched, labelled audit records only; it is not end-to-end recall or collection completeness.')
    return result
