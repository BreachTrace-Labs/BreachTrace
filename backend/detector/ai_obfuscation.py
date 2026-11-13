"""Bounded static string recovery. No eval, imports from scanned code, or I/O."""
from __future__ import annotations

import base64
import codecs
from bisect import bisect_right
from collections import deque
from dataclasses import dataclass, field
import html
import json
import re
from urllib.parse import unquote

MAX_TRANSFORMS = 4096
MAX_DECODED_BYTES = 1024 * 1024
MAX_TOKEN_CHARS = 8192
MAX_DEPTH = 2
MAX_FRAGMENTS = 256
MAX_JOIN_CHARS = 16384
MAX_CONFIG_DEPTH = 64

_LITERAL = re.compile(r'''"(?:\\.|[^"\\\r\n]){0,8192}"|'(?:\\.|[^'\\\r\n]){0,8192}'|`(?:\\.|[^`\\\r\n]){0,8192}`''')
_BASE64 = re.compile(r"([A-Za-z0-9+/_-]{24,}={0,2})")
_HEX = re.compile(r"(?<![A-Fa-f0-9])([A-Fa-f0-9]{40,8192})(?![A-Fa-f0-9])")
_ESCAPE = re.compile(r"\\(?:u([0-9A-Fa-f]{4})|x([0-9A-Fa-f]{2})|U([0-9A-Fa-f]{8}))")
_ZERO_WIDTH = str.maketrans("", "", "\u200b\u200c\u200d\u2060\ufeff")
_JOIN = re.compile(r"\s*(?:[+.]\s*|\\\r?\n\s*)?\Z")
_WRAPPER = re.compile(r'''(?:(?:base64|bytes|binascii)\.)?(?:b64decode|urlsafe_b64decode|atob|fromhex|unhexlify)\(\s*(["'])([^"'\r\n]+)\1\s*\)''')
_BUFFER = re.compile(r'''Buffer\.from\(\s*(["'])([^"'\r\n]+)\1\s*,\s*["'](?:base64|hex)["']\s*\)(?:\.toString\(\s*["'](?:utf8|utf-8)["']\s*\))?''')
_ROT13 = re.compile(r'''(?:codecs\.)?decode\(\s*(["'])([^"'\r\n]{1,8192})\1\s*,\s*["']rot_?13["']\s*\)''')
_ARRAY_JOIN = re.compile(r'''(?:["']["']\.join\(\s*\[(?P<py>[^\[\]\x00]{1,16384})\]\s*\)|\[(?P<js>[^\[\]\x00]{1,16384})\]\s*\.join\(\s*["']["']\s*\))''')


@dataclass(frozen=True)
class View:
    text: str = field(repr=False)
    start_line: int
    end_line: int
    method: str = "plaintext"
    source_values: tuple[str, ...] = field(default=(), repr=False)


def _printable(data: bytes) -> str | None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if text and all(c.isprintable() or c in "\r\n\t" for c in text):
        return text
    return None


def _escape(match):
    try:
        return chr(int(next(g for g in match.groups() if g is not None), 16))
    except (ValueError, OverflowError):
        return match.group()


def views(text: str, eligible: set[int] | None = None, diagnostics: list[str] | None = None):
    """Normalized views precede raw views so encoded opaque strings can be suppressed."""
    lines = text.splitlines()
    starts = [0]
    for match in re.finditer("\n", text):
        starts.append(match.end())
    transformed = decoded_bytes = 0
    exhausted = False

    def allowed(lo, hi):
        return eligible is None or any(i in eligible for i in range(lo - 1, hi))

    def budget(value):
        nonlocal transformed, decoded_bytes, exhausted
        transformed += 1
        decoded_bytes += len(value.encode("utf-8", errors="replace"))
        if transformed > MAX_TRANSFORMS or decoded_bytes > MAX_DECODED_BYTES:
            if not exhausted and diagnostics is not None:
                diagnostics.append("ai_obfuscation_budget_exceeded")
            exhausted = True
            return False
        return True

    def expand(view):
        if exhausted or len(view.text) < 24:
            return
        queue = deque([(view, 0)])
        seen = {view.text}
        recovered = []
        while queue and not exhausted:
            current, depth = queue.popleft()
            if depth >= MAX_DEPTH:
                continue
            value = current.text
            text_encoding = any(c in value for c in ("\\", "%", "&", "\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"))
            originals = tuple(m.group()[1:-1] for m in _LITERAL.finditer(value)) if text_encoding else ()
            def variants():
                if "\\" in value:
                    decoded = _ESCAPE.sub(_escape, value).replace("\\\r\n", "").replace("\\\n", "")
                    yield decoded, "literal-escapes", originals
                if any(c in value for c in "\u200b\u200c\u200d\u2060\ufeff"):
                    yield value.translate(_ZERO_WIDTH), "zero-width", originals
                if "%" in value:
                    yield unquote(value), "url-encoding", originals
                if "&" in value:
                    yield html.unescape(value), "html-entities", originals
                if "[::-1]" in value:
                    for literal in _LITERAL.finditer(value):
                        tail = re.match(r"\s*\[::-1\]", value[literal.end():])
                        if tail:
                            original = literal.group()[1:-1]
                            replacement = value[:literal.start()] + '"' + original[::-1] + '"' + value[literal.end() + tail.end():]
                            yield replacement, "reversed-literal", (original,)
                if "rot13" in value or "rot_13" in value:
                    for match in _ROT13.finditer(value):
                        original = match.group(2)
                        replacement = value[:match.start()] + '"' + codecs.decode(original, "rot_13") + '"' + value[match.end():]
                        yield replacement, "rot13", (original,)
                for match in _BASE64.finditer(value):
                    token = match.group(1)
                    if len(token) > MAX_TOKEN_CHARS or (match.start() > 0 and value[match.start() - 1] == ".") or (match.end() < len(value) and value[match.end()] == "."):
                        continue
                    try:
                        data = base64.b64decode(token + "=" * (-len(token) % 4), altchars=b"-_", validate=True)
                    except (ValueError, base64.binascii.Error):
                        continue
                    decoded = _printable(data)
                    if decoded and decoded != token:
                        replacement = value[:match.start(1)] + decoded + value[match.end(1):]
                        replacement = _WRAPPER.sub(lambda m: '"' + m.group(2) + '"', replacement)
                        replacement = _BUFFER.sub(lambda m: '"' + m.group(2) + '"', replacement)
                        yield replacement, "base64", (token,)
                if re.search(r"(?:hex|fromhex|base16)", value, re.I) or any(p in value for p in ("736b", "41497a61", "67736b", "68665f")):
                    for match in _HEX.finditer(value):
                        token = match.group(1)
                        if len(token) % 2:
                            continue
                        decoded = _printable(bytes.fromhex(token))
                        if decoded:
                            replacement = value[:match.start(1)] + decoded + value[match.end(1):]
                            replacement = _WRAPPER.sub(lambda m: '"' + m.group(2) + '"', replacement)
                            replacement = _BUFFER.sub(lambda m: '"' + m.group(2) + '"', replacement)
                            yield replacement, "hex", (token,)
            for decoded, method, tokens in variants():
                if decoded in seen:
                    continue
                if not budget(decoded):
                    break
                seen.add(decoded)
                method = method if current.method == "plaintext" else current.method + "+" + method
                child = View(decoded, view.start_line, view.end_line, method, current.source_values + tokens)
                recovered.append(child)
                queue.append((child, depth + 1))
        # Deepest representations first. MAX_DEPTH deliberately limits work.
        yield from reversed(recovered)

    # JSON path context disambiguates multi-provider config objects. Preserve
    # duplicate object members and map each value to its original literal span.
    # Parsing JSON data is safe; no source expressions are evaluated.
    class JSONObject(list):
        pass

    if text.lstrip("\x00 \t\r\n").startswith(("{", "[")) and any(word in text.lower() for word in ("key", "token", "secret", "credential")):
        clean = text.lstrip("\x00")
        try:
            tree = json.loads(clean, object_pairs_hook=JSONObject)
        except (ValueError, RecursionError):
            tree = None
        if tree is not None:
            positions = {}
            for literal in _LITERAL.finditer(text):
                if not literal.group().startswith('"') or text[literal.end():literal.end() + 32].lstrip().startswith(":"):
                    continue
                try:
                    value = json.loads(literal.group())
                except ValueError:
                    continue
                positions.setdefault(value, deque()).append(literal)

            def leaves(value, path=(), hints="", depth=0):
                if depth > MAX_CONFIG_DEPTH:
                    if diagnostics is not None and "ai_config_depth_limit_exceeded" not in diagnostics:
                        diagnostics.append("ai_config_depth_limit_exceeded")
                    return
                if isinstance(value, JSONObject):
                    local_hint = " ".join(f"{k}={v}" for k, v in value if k.lower() in {"provider", "name", "base_url", "endpoint"} and isinstance(v, str))
                    for key, child in value:
                        yield from leaves(child, path + (key,), local_hint or hints, depth + 1)
                elif isinstance(value, list):
                    for index, child in enumerate(value):
                        yield from leaves(child, path + (str(index),), hints, depth + 1)
                elif isinstance(value, str):
                    slots = positions.get(value)
                    if not slots:
                        return
                    literal = slots.popleft()
                    if not path or not re.search(r"key|token|secret|credential", path[-1], re.I):
                        return
                    lo = bisect_right(starts, literal.start())
                    hi = bisect_right(starts, literal.end() - 1)
                    if allowed(lo, hi) and 20 <= len(value) <= MAX_TOKEN_CHARS:
                        view = View(".".join(path) + "=" + json.dumps(value) + "\n" + hints, lo, hi, "structured-config", (literal.group()[1:-1],))
                        if budget(view.text):
                            yield from expand(view)
                            yield view
            yield from leaves(tree)

    for match in (_ARRAY_JOIN.finditer(text) if ".join" in text else ()):
        items = match.group("py") or match.group("js")
        fragments = list(_LITERAL.finditer(items))
        if not fragments or len(fragments) > MAX_FRAGMENTS:
            continue
        # Only comma-separated static literals; no names, calls or interpolation.
        tail = _LITERAL.sub("", items)
        if re.fullmatch(r"[\s,]*", tail) is None:
            continue
        pieces = tuple(fragment.group()[1:-1] for fragment in fragments)
        lo = bisect_right(starts, match.start())
        hi = bisect_right(starts, match.end() - 1)
        if not allowed(lo, hi):
            continue
        prefix = text[starts[lo - 1]:match.start()]
        view = View(prefix + '"' + "".join(pieces) + '"', lo, hi, "literal-array-join", pieces)
        if budget(view.text):
            yield from expand(view)
            yield view

    # Only join literal fragments separated by +, line continuation or literal
    # adjacency. Never resolve variables, f-strings, calls, operators or files.
    literals = iter(_LITERAL.finditer(text))
    group = []
    last_literal = None
    overflow = False

    def emit_group(items):
        if len(items) < 2:
            return
        lo = bisect_right(starts, items[0].start())
        hi = bisect_right(starts, items[-1].end() - 1)
        if not allowed(lo, hi):
            return
        pieces = tuple(item.group()[1:-1] for item in items)
        joined = "".join(pieces)
        if len(joined) > MAX_JOIN_CHARS:
            if diagnostics is not None:
                diagnostics.append("ai_literal_join_limit_exceeded")
            return
        prefix = text[starts[lo - 1]:items[0].start()]
        # A parenthesized multiline assignment may put the name on the line
        # before its first fragment. Carry that static label, never its code.
        before = text[max(0, items[0].start() - 256):items[0].start()]
        assignment = re.search(r'''([A-Za-z_][A-Za-z0-9_.-]{0,100})['"]?\s*[:=]\s*\(?\s*\Z''', before)
        if assignment:
            prefix = assignment.group(1) + "="
        view = View(prefix + '"' + joined + '"', lo, hi, "literal-concatenation", pieces)
        if budget(view.text):
            yield from expand(view)
            yield view

    for literal in literals:
        if group and _JOIN.fullmatch(text[last_literal.end():literal.start()]) is None:
            if not overflow:
                yield from emit_group(group)
            group = []
            overflow = False
        if len(group) >= MAX_FRAGMENTS:
            if not overflow and diagnostics is not None:
                diagnostics.append("ai_literal_join_limit_exceeded")
            overflow = True
        else:
            group.append(literal)
        last_literal = literal
    if not overflow:
        yield from emit_group(group)

    for index, line in enumerate(lines, start=1):
        if not allowed(index, index):
            continue
        view = View(line, index, index)
        yield from expand(view)
        yield view
