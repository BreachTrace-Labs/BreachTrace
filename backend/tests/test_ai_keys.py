"""Synthetic, offline AI credential detection and routing regressions."""
import pytest

from detector.ai_keys import PROVIDERS
from detector.scanner import scan
from detector.match_resolver import resolve_match
from db.models import IncidentRecord

BODY = "Q7vNm2Lp9Rt4Xs6Hd8Jk3Bc5Wz1Fg0EaU"
HEX = "d7a39c5e0b482f619e63a7d20c8b5f14"
SAMPLES = {
    "openai": "sk-proj-" + (BODY * 3)[:90],
    "anthropic": "sk-ant-api03-" + (BODY * 3)[:93] + "AA",
    "gemini": "AIza" + (BODY * 2)[:35],
    "groq": "gsk_" + (BODY * 2)[:52],
    "xai": "xai-" + (BODY * 3)[:80],
    "openrouter": "sk-or-v1-" + HEX * 2,
    "deepseek": "sk-" + HEX,
    "mistral": BODY[:32],
    "cohere": (BODY * 2)[:40],
    "together": HEX * 2,
    "perplexity": "pplx-" + (BODY * 2)[:48],
    "replicate": "r8_" + (BODY * 2)[:37],
}


@pytest.mark.parametrize("provider", tuple(SAMPLES))
def test_ai_key_detection_routes_to_detection_only(provider):
    value = SAMPLES[provider]
    matches = scan(f'+{provider.upper()}_API_KEY="{value}"', include_saas=True)
    assert len(matches) == 1
    match = matches[0]
    assert match.platform == provider
    assert match.credential_type == f"{provider}_api_key"
    assert value not in match.credential_hint and value not in match.raw_match
    resolved = resolve_match(match)
    assert not resolved.is_collectable and resolved.principal_id is None
    assert resolved.unavailable_reason
    assert IncidentRecord(credential_type=match.credential_type).platform == provider


@pytest.mark.parametrize("provider", tuple(SAMPLES))
def test_ai_key_deletion_and_context_do_not_create_incidents(provider):
    line = f'{provider.upper()}_API_KEY="{SAMPLES[provider]}"'
    assert scan(f"-{line}\n OTHER=1", include_saas=True) == []
    assert scan(f" {line}\n+OTHER=1", include_saas=True) == []
    assert len(scan(f"+{line}\n+{line}", include_saas=True)) == 1


@pytest.mark.parametrize("provider", ["deepseek", "mistral", "cohere", "together"])
def test_ambiguous_tokens_need_named_assignment(provider):
    assert scan(f'+HASH="{SAMPLES[provider]}"', include_saas=True) == []


def test_google_key_is_not_automatically_attributed_to_gemini():
    matches = scan(f'+GOOGLE_API_KEY="{SAMPLES["gemini"]}"', include_saas=True)
    assert len(matches) == 1 and matches[0].platform == "googleai"
    assert scan(f'+GOOGLE_AI_API_KEY="{SAMPLES["gemini"]}"', include_saas=True)


@pytest.mark.parametrize("provider", tuple(SAMPLES))
def test_short_tokens_rejected(provider):
    assert scan(f'+{provider.upper()}_API_KEY="{SAMPLES[provider][:15]}"', include_saas=True) == []


def test_legacy_openai_and_admin_anthropic():
    legacy = "sk-" + BODY[:20] + "T3BlbkFJ" + BODY[:20]
    admin = SAMPLES["anthropic"].replace("api03", "admin01")
    assert {m.platform for m in scan(f'+A="{legacy}"\n+B="{admin}"', include_saas=True)} == {"openai", "anthropic"}


def test_placeholder_and_embedded_token_rejected():
    assert scan('+OPENAI_API_KEY="sk-proj-' + 'x' * 60 + '"', include_saas=True) == []
    assert scan('+VALUE="prefix' + SAMPLES["groq"] + 'suffix"', include_saas=True) == []


@pytest.mark.parametrize("name", ["mistralApiKey", "MISTRAL_API_KEY", "mistral-key"])
def test_named_assignments_accept_common_code_styles(name):
    assert len(scan(f'+"{name}": "{SAMPLES["mistral"]}"', include_saas=True)) == 1
