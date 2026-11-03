"""Offline AI credential candidates; no execution or provider validation.

Distinctive prefixes and contextual opaque keys carry different confidence.
Bounded normalization recovers common static obfuscations with source spans.
See docs/ai-detection.md for coverage, provenance and limits.
"""
from __future__ import annotations

from collections import Counter
from bisect import bisect_left
from dataclasses import dataclass, field, replace
import math
import re
from typing import Iterator


@dataclass(frozen=True)
class ProviderRule:
    provider: str
    label: str
    aliases: tuple[str, ...]
    hosts: tuple[str, ...] = ()
    prefixes: tuple[str, ...] = ()


RULES = (
    ProviderRule("openai", "OpenAI / GPT", ("openai", "chatgpt", "gpt"), ("api.openai.com",),
                 (r"sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,256}", r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}")),
    ProviderRule("anthropic", "Anthropic / Claude", ("anthropic", "claude"), ("api.anthropic.com",),
                 (r"sk-ant-(?:api03|admin01)-[A-Za-z0-9_-]{93}AA", r"sk-ant-oat01-[A-Za-z0-9_-]{64,256}")),
    ProviderRule("gemini", "Google Gemini", ("gemini", "googleai", "googlegenai", "googlegenerativeai", "aistudio"), ("generativelanguage.googleapis.com",)),
    ProviderRule("googleai", "Google API key (AI usage unconfirmed)", ("googleapi",), (), (r"AIza[A-Za-z0-9_-]{35}",)),
    ProviderRule("groq", "Groq", ("groq",), ("api.groq.com",), (r"gsk_[A-Za-z0-9]{52}",)),
    ProviderRule("xai", "xAI / Grok", ("xai", "grok"), ("api.x.ai",), (r"xai-[A-Za-z0-9_]{80}",)),
    ProviderRule("openrouter", "OpenRouter", ("openrouter",), ("openrouter.ai",), (r"sk-or-v1-[A-Fa-f0-9]{64}",)),
    ProviderRule("deepseek", "DeepSeek", ("deepseek",), ("api.deepseek.com",)),
    ProviderRule("mistral", "Mistral", ("mistral",), ("api.mistral.ai",)),
    ProviderRule("cohere", "Cohere", ("cohere",), ("api.cohere.com", "api.cohere.ai")),
    ProviderRule("together", "Together AI", ("together",), ("api.together.ai", "api.together.xyz")),
    ProviderRule("perplexity", "Perplexity", ("perplexity",), ("api.perplexity.ai",), (r"pplx-[A-Za-z0-9]{48}",)),
    ProviderRule("replicate", "Replicate", ("replicate",), ("api.replicate.com",), (r"r8_[A-Za-z0-9_-]{37}",)),
    ProviderRule("sarvam", "Sarvam AI", ("sarvam", "sarvamai"), ("api.sarvam.ai",)),
    ProviderRule("cerebras", "Cerebras", ("cerebras",), ("api.cerebras.ai",)),
    ProviderRule("fireworks", "Fireworks AI", ("fireworks",), ("api.fireworks.ai",)),
    ProviderRule("nvidia", "NVIDIA NIM", ("nvidia", "nvidianim", "nvapi"), ("integrate.api.nvidia.com", "ai.api.nvidia.com")),
    ProviderRule("ai21", "AI21", ("ai21",), ("api.ai21.com",)),
    ProviderRule("deepinfra", "DeepInfra", ("deepinfra",), ("api.deepinfra.com",)),
    ProviderRule("sambanova", "SambaNova", ("sambanova",), ("api.sambanova.ai",)),
    ProviderRule("anyscale", "Anyscale", ("anyscale",), ("api.endpoints.anyscale.com",)),
    ProviderRule("lepton", "Lepton AI", ("lepton",), ("lepton.run",)),
    ProviderRule("siliconflow", "SiliconFlow", ("siliconflow",), ("api.siliconflow.cn", "api.siliconflow.com")),
    ProviderRule("moonshot", "Moonshot / Kimi", ("moonshot", "kimi"), ("api.moonshot.cn", "api.moonshot.ai")),
    ProviderRule("zhipu", "Zhipu / Z.ai", ("zhipu", "zhipuai", "zai", "bigmodel"), ("open.bigmodel.cn", "api.z.ai")),
    ProviderRule("dashscope", "Alibaba DashScope / Qwen", ("dashscope", "qwen", "bailian"), ("dashscope.aliyuncs.com", "dashscope-intl.aliyuncs.com")),
    ProviderRule("minimax", "MiniMax", ("minimax",), ("api.minimax.io", "api.minimax.chat")),
    ProviderRule("baidu", "Baidu / Qianfan", ("baidu", "qianfan", "ernie"), ("qianfan.baidubce.com",)),
    ProviderRule("azureopenai", "Azure OpenAI / Foundry", ("azureopenai", "azureaifoundry", "azureai"), ("openai.azure.com", "services.ai.azure.com")),
    ProviderRule("huggingface", "Hugging Face", ("huggingface", "hftoken", "hfapi"), ("huggingface.co",), (r"hf_[A-Za-z0-9]{34,128}",)),
    ProviderRule("voyage", "Voyage AI", ("voyage",), ("api.voyageai.com",)),
    ProviderRule("jina", "Jina AI", ("jina",), ("api.jina.ai",)),
    ProviderRule("runpod", "RunPod", ("runpod",), ("api.runpod.ai", "api.runpod.io")),
    ProviderRule("fal", "fal.ai", ("fal",), ("fal.run", "api.fal.ai")),
    ProviderRule("stability", "Stability AI", ("stability",), ("api.stability.ai",)),
    ProviderRule("elevenlabs", "ElevenLabs", ("elevenlabs",), ("api.elevenlabs.io",)),
    ProviderRule("assemblyai", "AssemblyAI", ("assemblyai",), ("api.assemblyai.com",)),
    ProviderRule("deepgram", "Deepgram", ("deepgram",), ("api.deepgram.com",)),
    ProviderRule("cartesia", "Cartesia", ("cartesia",), ("api.cartesia.ai",)),
    ProviderRule("novita", "Novita AI", ("novita",), ("api.novita.ai",)),
    ProviderRule("nebius", "Nebius AI", ("nebius",), ("api.studio.nebius.ai",)),
    ProviderRule("baseten", "Baseten", ("baseten",), ("api.baseten.co",)),
    ProviderRule("friendli", "FriendliAI", ("friendli",), ("api.friendli.ai",)),
    ProviderRule("aimlapi", "AI/ML API", ("aimlapi",), ("api.aimlapi.com",)),
    ProviderRule("bedrock", "Amazon Bedrock bearer token", ("bedrock",), ("bedrock-runtime.",)),
    ProviderRule("vertexai", "Google Vertex AI", ("vertexai", "googlevertex", "vertex"), ("aiplatform.googleapis.com",)),
    ProviderRule("volcengine", "Volcengine / Doubao", ("volcengine", "doubao", "bytedanceark"), ("ark.cn-beijing.volces.com",)),
    ProviderRule("hunyuan", "Tencent Hunyuan", ("hunyuan", "tencenthunyuan"), ("hunyuan.tencentcloudapi.com",)),
    ProviderRule("ollama", "Ollama cloud", ("ollama",), ("ollama.com",)),
)
PROVIDERS = tuple(rule.provider for rule in RULES)
_BY_PROVIDER = {rule.provider: rule for rule in RULES}
_PREFIX = re.compile(r"(?<![A-Za-z0-9_-])(" + "|".join(pattern for rule in RULES for pattern in rule.prefixes) + r")(?![A-Za-z0-9_-])")
_FULL = {rule.provider: tuple(re.compile(pattern + r"\Z") for pattern in rule.prefixes) for rule in RULES}
_MARKERS = ("sk-", "AIza", "gsk_", "xai-", "pplx-", "r8_", "hf_")
_VALUE = r"[A-Za-z0-9_./+=:-]{20,512}"
_ASSIGNMENT = re.compile(r'''(?<![A-Za-z0-9_.-])(?P<label>[A-Za-z_][A-Za-z0-9_.-]{0,100})['"]?\s*[:=]\s*['"`]?(?P<value>''' + _VALUE + r''')(?![A-Za-z0-9_./+=:-])''')
_BEARER = re.compile(r'''(?i)(?:authorization['"]?\s*:\s*['"]?(?:bearer|token)\s+|(?:api[-_]subscription[-_]key|xi[-_]api[-_]key|x[-_]api[-_]key)['"]?\s*[:=]\s*['"]?)(?P<value>''' + _VALUE + r''')(?![A-Za-z0-9_./+=:-])''')
_CREDENTIAL_LABEL = re.compile(r"key|token|secret|credential", re.I)
_AUTH_SUFFIX = re.compile(r"(?:apikey|apitoken|accesskey|accesstoken|authtoken|bearertoken|subscriptionkey|apisecret|secretkey|clientsecret|token|key|secret|credentials?)(?:base64url|doublebase64|base64|b64|hexescapes|hex|unicode|percent|html|zerowidth|encoded)?[0-9]{0,2}\Z")


@dataclass(frozen=True)
class AICandidate:
    provider: str
    value: str = field(repr=False)
    start_line: int = 1
    end_line: int = 1
    method: str = "plaintext"
    confidence: str = "medium"


def _normal(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _named_provider(name: str) -> str | None:
    # Match identifier components, not arbitrary substrings (fallback != fal).
    split = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", name)
    parts = re.findall(r"[a-z0-9]+", split.lower())
    components = {"".join(parts[i:i + count]) for i in range(len(parts)) for count in (1, 2, 3)}
    choices = [(len(alias), rule.provider) for rule in RULES for alias in rule.aliases if any(
        part in {alias, alias + "ai", alias + "client"} or
        (part.startswith(alias) and _AUTH_SUFFIX.fullmatch(part[len(alias):]))
        for part in components)]
    return max(choices)[1] if choices else None


def _context_provider(context: str) -> str | None:
    lower = context.lower()
    hosts = {rule.provider for rule in RULES if any(host in lower for host in rule.hosts)}
    if len(hosts) == 1:
        return next(iter(hosts))
    if hosts:
        return None
    aliases = {rule.provider for rule in RULES if any(re.search(
        r"(?:\b(?:from|import)\s+[^\n]{0,60}\b" + re.escape(alias) + r"\b|\b" + re.escape(alias) +
        r"(?:ai|client)?\s*\(|\bprovider\s*[:=]\s*['\"]?" + re.escape(alias) + r"\b)", lower)
        for alias in rule.aliases if alias not in {"gpt", "grok", "kimi", "qwen", "ernie", "zai"})}
    if re.search(r"google\.(?:genai|generativeai)|from google import genai", lower):
        aliases.add("gemini")
    return next(iter(aliases)) if len(aliases) == 1 else None


def _auth_label(name: str) -> bool:
    normalized = _normal(name)
    if _AUTH_SUFFIX.search(normalized):
        return True
    provider = _named_provider(name)
    if provider:
        return any(normalized.endswith(alias) and _AUTH_SUFFIX.search(normalized[:-len(alias)])
                   for alias in _BY_PROVIDER[provider].aliases)
    return False


def is_placeholder(value: str) -> bool:
    normalized = _normal(value)
    if any(marker in normalized for marker in ("yourapikey", "yourtokenhere", "replaceme", "changeme", "placeholder", "redacted")):
        return True
    body = re.sub(r"^(?:sk-(?:proj-|svcacct-|admin-|ant-(?:api03-|admin01-|oat01-))?|gsk_|xai-|pplx-|r8_|hf_|AIza)", "", value)
    return len(body) >= 8 and len(set(body)) <= 2


def _opaque(value: str) -> bool:
    if is_placeholder(value) or len(value) < 20 or value.startswith(("http:", "https:", "file:", "process.env", "os.environ")):
        return False
    if re.fullmatch(r"[A-Z][A-Z0-9_]+", value) and re.search(r"API_KEY|AUTH_TOKEN|ACCESS_TOKEN|SETTING|PLACEHOLDER", value):
        return False
    counts = Counter(value)
    entropy = -sum((n / len(value)) * math.log2(n / len(value)) for n in counts.values())
    return entropy >= 3.0


def _direct(line: str, context: str) -> Iterator[tuple[str, str, str]]:
    found = set()
    if any(marker in line for marker in _MARKERS):
        for match in _PREFIX.finditer(line):
            value = match.group(1)
            provider = next(p for p, patterns in _FULL.items() if any(pat.fullmatch(value) for pat in patterns))
            if provider == "googleai":
                contextual = _named_provider(line.split(value, 1)[0]) or _context_provider(context)
                provider = contextual if contextual in {"gemini", "googleai"} else "googleai"
            if not is_placeholder(value):
                found.add((provider, value))
                yield provider, value, "high"
    lower = line.lower()
    if not any(word in lower for word in ("key", "token", "secret", "credential", "authorization")):
        return
    for match in _ASSIGNMENT.finditer(line):
        name, value = match.group("label", "value")
        if not _auth_label(name) or not _opaque(value):
            continue
        quoted = match.start("value") > 0 and line[match.start("value") - 1] in "\"'`"
        if not quoted and "." in value and not re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", value):
            continue
        provider = _named_provider(name) or _context_provider(line) or _context_provider(context)
        if provider == "googleai" and _context_provider(context) == "gemini":
            provider = "gemini"
        if provider and (provider, value) not in found:
            found.add((provider, value))
            yield provider, value, "medium"
    for match in _BEARER.finditer(line):
        value = match.group("value")
        provider = _context_provider(context)
        if provider and (provider, value) not in found and _opaque(value):
            yield provider, value, "medium"


def find_candidates(text: str, candidate_lines: set[int] | None = None,
                    diagnostics: list[str] | None = None) -> Iterator[AICandidate]:
    from detector.ai_obfuscation import views
    lines = text.splitlines()
    seen = set()
    suppressed = set()
    eligible_lines = sorted(candidate_lines) if candidate_lines is not None else None

    def source_views():
        # Parse JSON and recover literals separately in each source fragment;
        # barriers must never become part of an unrelated file's config tree.
        start = 0
        ends = [i for i, line in enumerate(lines) if line == "\x00"] + [len(lines)]
        for end in ends:
            eligible = (None if eligible_lines is None else
                        {i - start for i in eligible_lines[bisect_left(eligible_lines, start):bisect_left(eligible_lines, end)]})
            if eligible is None or eligible:
                for view in views("\n".join(lines[start:end]), eligible, diagnostics):
                    yield replace(view, start_line=view.start_line + start, end_line=view.end_line + start)
            start = end + 1

    for view in source_views():
        lower = view.text.lower()
        if not any(marker in view.text for marker in _MARKERS) and not any(word in lower for word in ("key", "token", "secret", "credential", "authorization")):
            continue
        lo, hi = view.start_line - 1, view.end_line
        left, right = max(0, lo - 3), min(len(lines), hi + 3)
        for index in range(left, lo + 1):
            if lines[index].startswith("\x00"):
                left = index
        for index in range(hi, right):
            if lines[index].startswith("\x00"):
                right = index
                break
        context = "\n".join(lines[left:right]) + "\n" + view.text
        for provider, value, confidence in _direct(view.text, context):
            if any(i in range(lo, hi) and value in token for i, token in suppressed):
                continue
            identity = (provider, value)
            if identity in seen:
                continue
            seen.add(identity)
            if view.method != "plaintext":
                suppressed.update((i, token) for i in range(lo, hi) for token in view.source_values)
            yield AICandidate(provider, value, view.start_line, view.end_line, view.method, confidence)


def candidates(line: str):
    for match in find_candidates(line):
        yield match.provider, match.value
