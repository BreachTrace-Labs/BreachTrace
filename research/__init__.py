"""Offline, opt-in research tools; not part of the detection pipeline."""
from pathlib import Path

# The application already has research modules under backend/research. Keep
# both entry points importable when either project root or backend is first.
_existing = Path(__file__).resolve().parents[1] / 'backend' / 'research'
if _existing.is_dir():
    __path__.append(str(_existing))
