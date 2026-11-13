"""Small provider adapters. Endpoint hosts are fixed; no downloads or tool calls."""
from __future__ import annotations

import requests

from model_settings import ModelSettings, key_for


def generate(settings: ModelSettings, messages: list[dict], *, json_output: bool = False) -> str:
    provider = settings.provider
    key = key_for(settings)
    if provider in {"openai", "anthropic", "gemini"} and not key:
        raise ValueError("The selected provider has no API key configured")
    if provider == "openai":
        url = "https://api.openai.com/v1/responses"
        headers = {"Authorization": f"Bearer {key}"}
        body = {"model": settings.model, "input": messages, "store": False, "max_output_tokens": 1600}
        if json_output:
            body["text"] = {"format": {"type": "json_object"}}
    elif provider == "anthropic":
        url = "https://api.anthropic.com/v1/messages"
        headers = {"x-api-key": key, "anthropic-version": "2023-06-01"}
        body = {"model": settings.model, "max_tokens": 1600,
                "system": "\n".join(m["content"] for m in messages if m["role"] == "system"),
                "messages": [m for m in messages if m["role"] != "system"]}
    elif provider == "ollama":
        url = settings.ollama_url + "/api/chat"
        headers = {}
        body = {"model": settings.model, "messages": messages, "stream": False,
                "options": {"num_predict": 1600}}
        if json_output:
            body["format"] = "json"
    elif provider == "gemini":
        from google import genai
        client = genai.Client(api_key=key)
        response = client.models.generate_content(
            model=settings.model,
            contents="\n".join(m["content"] for m in messages if m["role"] != "system"),
            config={"system_instruction": "\n".join(m["content"] for m in messages if m["role"] == "system"),
                    **({"response_mime_type": "application/json"} if json_output else {})},
        )
        return response.text or ""
    else:
        raise ValueError("This provider does not expose a chat endpoint")
    # Do not log request/response bodies or surface upstream error text (may contain secrets).
    response = requests.post(url, headers=headers, json=body, timeout=settings.timeout_s, allow_redirects=False)
    if response.status_code != 200:
        raise ValueError(f"Model request failed (HTTP {response.status_code})")
    data = response.json()
    if provider == "openai":
        return "\n".join(part["text"] for item in data.get("output", [])
                         for part in item.get("content", []) if part.get("type") == "output_text")
    if provider == "anthropic":
        return "\n".join(part["text"] for part in data.get("content", []) if part.get("type") == "text")
    return data.get("message", {}).get("content", "")
