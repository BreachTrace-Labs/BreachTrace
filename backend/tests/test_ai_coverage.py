"""Synthetic coverage matrix; it measures supported cases, not wild-key recall."""
import base64
from dataclasses import asdict
import json
import random
import string
import time

import pytest

from detector.ai_keys import RULES, find_candidates
from detector.scanner import scan, scan_text
from detector.match_resolver import resolve_match


def opaque(provider, length=48):
    rng = random.Random("ai-coverage-" + provider)
    return "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(length))


CANONICAL = {
    "openai": "sk-proj-" + opaque("openai", 90),
    "anthropic": "sk-ant-api03-" + opaque("anthropic", 93) + "AA",
    "gemini": "AIza" + opaque("gemini", 35),
    "googleai": "AIza" + opaque("googleai", 35),
    "groq": "gsk_" + opaque("groq", 52),
    "xai": "xai-" + opaque("xai", 80),
    "openrouter": "sk-or-v1-" + "9d7a52b1c6e38f40" * 4,
    "perplexity": "pplx-" + opaque("perplexity", 48),
    "replicate": "r8_" + opaque("replicate", 37),
    "huggingface": "hf_" + opaque("huggingface", 60),
    "sarvam": "sk_" + opaque("sarvam"),
    "deepseek": "sk-" + opaque("deepseek", 32),
}


def sample(provider):
    return CANONICAL.get(provider, opaque(provider))


@pytest.mark.parametrize("rule", RULES, ids=lambda rule: rule.provider)
@pytest.mark.parametrize("style", ["env", "json", "yaml", "camel", "frontend"])
def test_all_provider_named_assignments(rule, style):
    value = sample(rule.provider)
    name = rule.provider.upper() + "_API_KEY"
    if rule.provider == "googleai":
        name = "GOOGLE_API_KEY"
    source = {
        "env": f"{name}={value}",
        "json": json.dumps({name: value}),
        "yaml": f"{name}: '{value}'",
        "camel": f'const {"google" if rule.provider == "googleai" else rule.provider}ApiKey = "{value}";',
        "frontend": f'NEXT_PUBLIC_{name}="{value}"',
    }[style]
    matches = scan_text(source)
    assert len(matches) == 1, [(m.platform, m.detection_method) for m in matches]
    assert matches[0].platform == rule.provider
    assert not resolve_match(matches[0]).is_collectable
    assert value not in matches[0].credential_hint and value not in matches[0].raw_match


def transform(kind, value):
    if kind == "base64": return base64.b64encode(value.encode()).decode()
    if kind == "base64url": return base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
    if kind == "double-base64": return transform("base64", transform("base64", value))
    if kind == "hex": return value.encode().hex()
    if kind == "unicode": return "".join(f"\\u{ord(c):04x}" for c in value)
    if kind == "hex-escapes": return "".join(f"\\x{ord(c):02x}" for c in value)
    if kind == "percent": return "".join(f"%{ord(c):02X}" for c in value)
    if kind == "html": return "".join(f"&#{ord(c)};" for c in value)
    if kind == "zero-width": return "\u200b".join(value)
    raise AssertionError(kind)


@pytest.mark.parametrize("provider", ["openai", "anthropic", "gemini", "deepseek", "sarvam", "groq", "mistral"])
@pytest.mark.parametrize("kind", ["base64", "base64url", "double-base64", "hex", "unicode", "hex-escapes", "percent", "html", "zero-width"])
def test_obfuscation_recovery(provider, kind):
    value = sample(provider)
    name = provider.upper() + "_API_KEY_" + kind.replace("-", "_").upper()
    matches = scan_text(f'{name}="{transform(kind, value)}"')
    assert len(matches) == 1, [(m.platform, m.detection_method) for m in matches]
    assert matches[0].platform == provider
    assert matches[0].detection_method != "plaintext"
    assert value not in str(matches)


@pytest.mark.parametrize("provider", ["openai", "sarvam", "deepseek", "gemini"])
@pytest.mark.parametrize("separator", [" + ", " ", " +\n", "\n", " . "])
def test_static_fragment_reassembly(provider, separator):
    value = sample(provider)
    split = max(20, len(value) // 2)
    source = f'{provider.upper()}_API_KEY = (\n"{value[:split]}"{separator}"{value[split:]}"\n)'
    matches = scan_text(source)
    assert len(matches) == 1
    assert matches[0].platform == provider and "concatenation" in matches[0].detection_method
    assert matches[0].line_number == 2
    assert matches[0].line_end in {2, 3}


def test_sarvam_sdk_and_header_and_compatible_openai_client():
    value = sample("sarvam")
    sources = [
        f'from sarvamai import SarvamAI\nclient = SarvamAI(api_subscription_key="{value}")',
        f'POST https://api.sarvam.ai/translate\napi-subscription-key: {value}',
        f'from openai import OpenAI\nclient=OpenAI(base_url="https://api.sarvam.ai/v1", api_key="{value}")',
        f'curl https://api.sarvam.ai/v1 -H "Authorization: Bearer {value}"',
    ]
    for source in sources:
        matches = scan_text(source)
        assert len(matches) == 1 and matches[0].platform == "sarvam"


@pytest.mark.parametrize("wrapper", [
    'base64.b64decode("{value}")', 'atob("{value}")',
    'Buffer.from("{value}", "base64").toString("utf8")',
])
def test_static_decoder_wrappers(wrapper):
    value = sample("sarvam")
    source = 'SARVAM_API_KEY = ' + wrapper.format(value=transform("base64", value))
    matches = scan_text(source)
    assert len(matches) == 1 and matches[0].platform == "sarvam"
    assert "base64" in matches[0].detection_method


def test_diff_provenance_and_no_cross_file_context_or_deleted_reconstruction():
    value = sample("sarvam")
    encoded = transform("base64", value)
    diff = 'diff --git a/.env b/.env\n@@ -1 +1,2 @@\n EXISTING=1\n+SARVAM_API_KEY_B64="' + encoded + '"\n'
    match = scan(diff, include_saas=True)[0]
    assert match.line_number == 4 and match.line_end == 4
    deleted = '-SARVAM_API_KEY_B64="' + encoded + '"\n+OTHER=1'
    assert scan(deleted, include_saas=True) == []
    other_file = 'diff --git a/a b/a\n@@ -1 +1 @@\n+import sarvamai\ndiff --git a/b b/b\n@@ -1 +1 @@\n+api_key="' + value + '"'
    assert scan(other_file, include_saas=True) == []


def test_literal_values_never_execute_and_dynamic_expressions_are_not_resolved(tmp_path):
    marker = tmp_path / "must-not-exist"
    text = f'__import__("pathlib").Path({str(marker)!r}).touch()\nSARVAM_API_KEY = prefix + suffix'
    assert scan_text(text) == [] and not marker.exists()


def test_dense_encoded_line_stops_allocating_at_decode_budget(monkeypatch):
    import tracemalloc
    from detector import ai_obfuscation

    monkeypatch.setattr(ai_obfuscation, "MAX_DECODED_BYTES", 1024)
    encoded = transform("base64", sample("sarvam"))
    source = " ".join(encoded for _ in range(1000))
    diagnostics = []
    tracemalloc.start()
    try:
        list(ai_obfuscation.views(source, diagnostics=diagnostics))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert diagnostics == ["ai_obfuscation_budget_exceeded"]
    assert peak < 8 * 1024 * 1024


def test_full_encoded_configuration_and_kubernetes_secret():
    value = sample("sarvam")
    encoded = transform("base64", json.dumps({"SARVAM_API_KEY": value}))
    assert scan_text(f'CONFIG_B64="{encoded}"')[0].platform == "sarvam"
    source = 'apiVersion: v1\nkind: Secret\ndata:\n  SARVAM_API_KEY: ' + transform("base64", value)
    matches = scan_text(source)
    assert len(matches) == 1 and matches[0].line_number == 4


def test_opaque_jwt_is_not_reported_as_decoded_partial_key():
    value = transform("base64url", '{"alg":"HS256","typ":"JWT"}') + '.' + transform("base64url", '{"sub":"synthetic-user","role":"tester"}') + '.' + opaque("jwt-signature")
    matches = scan_text(f'SARVAM_API_KEY="{value}"')
    assert len(matches) == 1 and matches[0].detection_method == "plaintext"


def test_fragment_limit_is_reported_without_silent_partial_reconstruction():
    from detector.ai_obfuscation import MAX_FRAGMENTS
    source = 'SARVAM_API_KEY = ' + ' + '.join('"a"' for _ in range(MAX_FRAGMENTS + 1))
    diagnostics = []
    assert scan_text(source, diagnostics=diagnostics) == []
    assert "ai_literal_join_limit_exceeded" in diagnostics


def test_sdk_aliases_do_not_attribute_a_compatible_endpoint_to_openai():
    value = sample("deepseek")
    source = f'from openai import OpenAI\nclient=OpenAI(api_key="{value}",base_url="https://api.deepseek.com/v1")'
    matches = scan_text(source)
    assert len(matches) == 1 and matches[0].platform == "deepseek"


def test_nested_multi_provider_json_and_duplicate_members_keep_source_lines():
    sarvam = sample("sarvam"); deepseek = sample("deepseek")
    source = json.dumps({"providers": {"sarvam": {"api_key": sarvam}, "deepseek": {"api_key": deepseek}}}, indent=2)
    matches = scan_text(source)
    assert {m.platform for m in matches} == {"sarvam", "deepseek"}
    assert all(m.detection_method == "structured-config" for m in matches)
    for match in matches:
        assert '"api_key"' in source.splitlines()[match.line_number - 1]
    duplicate = '{"sarvam":{"api_key":"' + sarvam + '","api_key":"' + opaque("second") + '"}}'
    assert len(scan_text(duplicate)) == 2


def test_json_provider_arrays_and_encoded_nested_key():
    config = {"providers": [{"provider": "sarvam", "api_key": transform("base64", sample("sarvam"))},
                            {"provider": "deepseek", "api_key": sample("deepseek")}]}
    matches = scan_text(json.dumps(config))
    assert len(matches) == 2 and {m.platform for m in matches} == {"sarvam", "deepseek"}


def test_existing_json_secret_does_not_refire_when_an_unrelated_line_is_added():
    value = sample("sarvam")
    diff = ' {\n   "sarvam": {\n     "api_key": "' + value + '"\n   },\n+  "enabled": true\n }'
    assert scan(diff, include_saas=True) == []


@pytest.mark.parametrize("source", [
    'import anthropic\nmax_tokens: model.maxOutputTokens',
    'import anthropic\nconst tokenCount = usage.input_tokens + usage.output_tokens',
    'OPENAI_API_KEY = config.readKeySettings(\"my-key\")',
    'OPENAI_API_KEY = \"COPILOT_CHAT_OPENAI_API_KEY_SETTING\"',
    'fallbackAuthToken = \"Q7vNm2Lp9Rt4Xs6Hd8Jk3Bc5Wz1Fg0EaU\"',
    'The tokens fit together in this text.\ntoken = \"Q7vNm2Lp9Rt4Xs6Hd8Jk3Bc5Wz1Fg0EaU\"',
])
def test_real_code_negative_patterns_do_not_become_ai_secrets(source):
    assert scan_text(source) == []


@pytest.mark.parametrize("name,provider", [
    ("API_KEY_SARVAM", "sarvam"), ("TOKEN_DEEPSEEK", "deepseek"),
    ("AWS_BEARER_TOKEN_BEDROCK", "bedrock"), ("SARVAM_API_KEY_2", "sarvam"),
])
def test_alternative_credential_field_ordering(name, provider):
    matches = scan_text(f'{name}="{opaque(provider)}"')
    assert len(matches) == 1 and matches[0].platform == provider


def test_high_entropy_alphabetic_opaque_keys_are_not_rejected_for_missing_digits():
    value = "qWErTyUiOpASdFgHjKlZxCvBnMaQwErTy"
    assert scan_text('SARVAM_API_KEY="' + value + '"')[0].platform == "sarvam"


@pytest.mark.parametrize("provider", ["openai", "sarvam", "deepseek"])
def test_reversed_and_rot13_literals(provider):
    import codecs
    value = sample(provider)
    for expression, method in [(repr(value[::-1]) + "[::-1]", "reversed-literal"),
                               ('codecs.decode(' + repr(codecs.encode(value, 'rot_13')) + ', "rot_13")', "rot13")]:
        matches = scan_text(provider.upper() + "_API_KEY=" + expression)
        assert len(matches) == 1 and matches[0].platform == provider
        assert method in matches[0].detection_method


@pytest.mark.parametrize("style", ["python", "javascript"])
def test_static_literal_array_join(style):
    value = sample("sarvam")
    array = json.dumps([value[i:i + 4] for i in range(0, len(value), 4)])
    expression = '"".join(' + array + ')' if style == "python" else array + '.join("")'
    matches = scan_text('SARVAM_API_KEY=' + expression)
    assert len(matches) == 1 and matches[0].detection_method == "literal-array-join"


def test_generic_hashes_references_placeholders_and_encrypted_data_do_not_trigger():
    for source in [
        'HASH="' + opaque("hash") + '"',
        'SARVAM_API_KEY=os.environ["SARVAM_API_KEY"]',
        'SARVAM_API_KEY="your_api_key_here_replace_me"',
        'SARVAM_API_KEY="' + 'a' * 64 + '"',
        'MISTRAL_API_KEY=process.env.MISTRAL_API_KEY',
        'api_key="' + opaque("unattributed") + '"',
    ]:
        assert scan_text(source) == []


def test_strict_key_boundaries_and_no_remote_validation(monkeypatch):
    import requests
    def forbidden(*args, **kwargs): raise AssertionError("Detector must be offline")
    monkeypatch.setattr(requests, "get", forbidden)
    monkeypatch.setattr(requests, "post", forbidden)
    assert scan_text('GROQ_API_KEY="' + sample("groq") + '"')
    assert scan_text('arbitrary="prefix' + sample("groq") + 'suffix"') == []


def test_normalization_is_bounded_and_reports_exhaustion(monkeypatch):
    from detector import ai_obfuscation
    monkeypatch.setattr(ai_obfuscation, "MAX_TRANSFORMS", 1)
    encoded = transform("double-base64", sample("groq"))
    diagnostics = []
    list(find_candidates('GROQ_API_KEY_B64="' + encoded + '"', diagnostics=diagnostics))
    assert "ai_obfuscation_budget_exceeded" in diagnostics
    start = time.perf_counter()
    assert scan_text("z" * 200_000) == []
    assert time.perf_counter() - start < 3
