"""Strict JSON parsing and minimal top-level value edits."""
import codecs
from decimal import Decimal
import json
import math
from typing import Any

Settings = dict[str, str | int | bool]


def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build an object while rejecting duplicate JSON keys."""
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError("Duplicate JSON keys are not supported")
        result[key] = value
    return result


def number(value: str) -> float:
    """Parse a finite JSON floating-point token."""
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("Non-finite JSON numbers are not supported")
    return parsed


def invalid_constant(value: str) -> None:
    """Reject JSON constants that are outside the JSON standard."""
    raise ValueError("Nonstandard JSON constants are not supported")


DECODER = json.JSONDecoder(object_pairs_hook=pairs, parse_float=number, parse_constant=invalid_constant)


def decode(raw: bytes) -> Any:
    """Decode one strict UTF-8 JSON document."""
    try:
        text = raw.decode("utf-8-sig")
        value, end = DECODER.raw_decode(text, len(text) - len(text.lstrip(" \t\r\n")))
        if text[end:].strip(" \t\r\n"):
            raise ValueError("Unexpected content after JSON document")
        return value
    except (UnicodeError, RecursionError) as exc:
        raise ValueError("Use UTF-8 JSON with supported nesting") from exc


def render(
    raw: bytes,
    config: dict[str, Any],
    settings: Settings,
    allow_reformat: bool = False,
) -> bytes:
    """Render policy changes while preserving unmanaged bytes by default."""
    if any(key not in config for key in settings) and not allow_reformat:
        raise ValueError("Policy adds missing keys; review and opt in with --allow-reformat")
    if allow_reformat:
        def exact_number(token: str) -> float:
            """Parse a float only when reformatting preserves its numeric value."""
            parsed = number(token)
            if Decimal(token) != Decimal(str(parsed)):
                raise ValueError("Full reformat would lose numeric precision; use existing-key edits or revise the config")
            return parsed
        json.loads(raw.decode("utf-8-sig"), object_pairs_hook=pairs,
                   parse_float=exact_number, parse_constant=invalid_constant)
        updated = dict(config, **settings)
        return (json.dumps(updated, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode("utf-8")
    text = raw.decode("utf-8-sig")
    edits: list[tuple[int, int, str]] = []

    def skip_space(position: int) -> int:
        """Advance over JSON whitespace without consuming structural bytes."""
        while position < len(text) and text[position] in " \t\r\n":
            position += 1
        return position

    pos = skip_space(0)
    if pos >= len(text) or text[pos] != "{":
        raise ValueError("config must be a JSON object")
    pos += 1
    # Fast path for empty object: no top-level values to edit.
    # Missing-key check above already enforced the policy.
    if skip_space(pos) < len(text) and text[skip_space(pos)] == "}":
        return (codecs.BOM_UTF8 if raw.startswith(codecs.BOM_UTF8) else b"") + text.encode("utf-8")

    index = pos
    while True:
        s = skip_space(index)
        if s >= len(text):
            raise ValueError("invalid JSON object")
        if text[s] == "}":
            break
        index = s
        key, index = DECODER.raw_decode(text, index)
        index = skip_space(index)
        if index >= len(text) or text[index] != ":":
            raise ValueError("invalid JSON object")
        index += 1  # colon
        start = skip_space(index)
        _, end = DECODER.raw_decode(text, start)
        if key in settings and (type(config[key]) is not type(settings[key]) or config[key] != settings[key]):
            edits.append((start, end, json.dumps(settings[key], ensure_ascii=True, allow_nan=False)))
        index = skip_space(end)
        if index >= len(text):
            raise ValueError("invalid JSON object")
        if text[index] == "}":
            break
        if text[index] != ",":
            raise ValueError("invalid JSON object")
        index += 1  # comma
    for start, end, replacement in reversed(edits):
        text = text[:start] + replacement + text[end:]
    return (codecs.BOM_UTF8 if raw.startswith(codecs.BOM_UTF8) else b"") + text.encode("utf-8")
