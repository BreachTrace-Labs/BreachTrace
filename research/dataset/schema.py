"""Serializable candidate metadata. Source text and credentials are never saved."""
from dataclasses import asdict, dataclass, field
from pathlib import Path
import json

CORPUS = Path(__file__).parent / 'corpus'


@dataclass(frozen=True)
class LabeledFinding:
    candidate_id: str
    file_url: str
    file_sha: str
    repository: str
    revision: str
    path: str
    line_number: int
    match_redacted: str
    service: str
    score: float | None = None
    signals: dict[str, float] = field(default_factory=dict)
    raw_line_redacted: str = '[redacted]'
    context_lines_redacted: list[str] = field(default_factory=list)
    label: str | None = None

    def to_dict(self):
        return asdict(self)


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    with path.open(encoding='utf-8') as stream:
        for number, line in enumerate(stream, 1):
            if line.strip():
                try:
                    row = json.loads(line)
                    if not isinstance(row, dict):
                        raise ValueError('Expected object')
                    rows.append(row)
                except (ValueError, TypeError) as exc:
                    raise ValueError(f'Invalid JSONL at {path}:{number}') from exc
    return rows


def append_jsonl(path: Path, row: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    import os
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    with os.fdopen(fd, 'a', encoding='utf-8') as out:
        out.write(json.dumps(row, ensure_ascii=True) + '\n')
