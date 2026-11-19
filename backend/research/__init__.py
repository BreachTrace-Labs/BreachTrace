"""Existing application research modules and optional root research tools."""
from pathlib import Path

_tools = Path(__file__).resolve().parents[2] / 'research'
if _tools.is_dir():
    __path__.append(str(_tools))
