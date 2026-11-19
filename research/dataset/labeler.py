"""Manually adjudicate redacted candidates; resume from previous labels."""
from .schema import CORPUS, append_jsonl, read_jsonl


def _safe_label(row, label):
    # Never copy arbitrary source text or extra fields into the labeled corpus.
    import math
    import re
    from urllib.parse import quote
    repo, revision, path = row.get('repository'), row.get('revision'), row.get('path')
    if (not isinstance(repo, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9_.-]{1,100}', repo)
            or '..' in repo or re.search(r'[A-Za-z0-9_+-]{40,}', repo)
            or not isinstance(revision, str) or not re.fullmatch(r'[a-f0-9]{40,64}', revision)
            or not isinstance(path, str) or not path or any(part in ('', '.', '..') for part in path.split('/'))
            or re.search(r'[A-Za-z0-9_+-]{40,}', path)
            or re.search(r'(?:AKIA|ASIA)[A-Z0-9]{16}|(?:sk|rk)_(?:live|test)_[A-Za-z0-9]+|github_pat_|ghp_', path)
            or not re.fullmatch(r'[a-f0-9]{64}', str(row.get('candidate_id', '')))
            or not re.fullmatch(r'[a-f0-9]{40,64}', str(row.get('file_sha', '')))
            or not re.fullmatch(r'[a-zA-Z0-9_]{1,80}', str(row.get('service', '')))
            or not isinstance(row.get('line_number'), int) or isinstance(row['line_number'], bool) or row['line_number'] < 1):
        raise ValueError('Candidate metadata is invalid or may contain a credential.')
    allowed = ('candidate_id', 'file_url', 'file_sha', 'repository', 'revision', 'path', 'line_number', 'service')
    item = {key: row[key] for key in allowed}
    item['file_url'] = f'https://github.com/{repo}/blob/{revision}/{quote(path, safe="/")}'
    hint = row.get('match_redacted')
    item['match_redacted'] = (str(hint)[:4] + '***') if hint else '[redacted]'
    item['raw_line_redacted'] = '[redacted]'
    item['context_lines_redacted'] = ['[redacted]'] * 6
    score = row.get('score')
    item['score'] = score if isinstance(score, (int, float)) and not isinstance(score, bool) and math.isfinite(score) else None
    signals = row.get('signals') if isinstance(row.get('signals'), dict) else {}
    from research.scoring import canonical_signals
    item['signals'] = canonical_signals(signals) or {}
    item['label'] = label
    return item


def main():
    candidates = read_jsonl(CORPUS / 'candidates.jsonl')
    labeled = read_jsonl(CORPUS / 'labeled.jsonl')
    if not candidates:
        print('No candidates found. Run the collector first.')
        return
    done = {row['candidate_id'] for row in labeled}
    tp = sum(row.get('label') == 'TP' for row in labeled)
    fp = sum(row.get('label') == 'FP' for row in labeled)
    for row in candidates:
        if row['candidate_id'] in done:
            continue
        try:
            safe = _safe_label(row, 'TP')
        except (KeyError, TypeError, ValueError):
            print('Skipping a candidate with invalid or potentially sensitive metadata.')
            continue
        print(f"\n{safe['service']} · {safe['match_redacted']} · {safe['file_url']}:{safe['line_number']}")
        print(f"Line: {safe['raw_line_redacted']}\nContext: {safe['context_lines_redacted']}")
        print(f"Score: {safe['score']} · Signals: {safe['signals']}")
        while True:
            choice = input('[T]rue positive / [F]alse positive / [S]kip / [Q]uit: ').strip().lower()
            if choice in ('t', 'f', 's', 'q'):
                break
        if choice == 'q':
            break
        if choice == 's':
            continue
        label = 'TP' if choice == 't' else 'FP'
        append_jsonl(CORPUS / 'labeled.jsonl', _safe_label(row, label))
        done.add(row['candidate_id'])
        tp += label == 'TP'
        fp += label == 'FP'
        print(f'{len(done)} labeled ({tp} TP, {fp} FP), {len({r["candidate_id"] for r in candidates} - done)} remaining')


if __name__ == '__main__':
    main()
