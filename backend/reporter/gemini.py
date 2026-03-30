import google.generativeai as genai

import config
from normalizer.schema import ForensicEvent

genai.configure(api_key=config.GEMINI_API_KEY)
_model = genai.GenerativeModel("gemini-2.5-flash")


def generate_report(
    events: list[ForensicEvent],
    overall_severity: str,
    exposure_duration_seconds: int,
    affected_resources: list[str],
    source_ips: list[str],
) -> str:
    """
    Call Gemini API to generate a plain-English forensic incident report.
    TODO (Vedant/Day 4): implement full prompt construction and response parsing.
    """
    raise NotImplementedError("Gemini reporter — implement on Day 4")
