"""Strict JSON parsing and minimal top-level value edits."""
import codecs
from decimal import Decimal
import json
import math


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("Duplicate JSON keys are not supported")
        result[key] = value
    return result


def number(value):
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("Non-finite JSON numbers are not supported")
    return parsed


def invalid_constant(value):
    raise ValueError("Nonstandard JSON constants are not supported")


DECODER = json.JSONDecoder(object_pairs_hook=pairs, parse_float=number, parse_constant=invalid_constant)


def decode(raw):
    try:
        text = raw.decode("utf-8-sig")
        value, end = DECODER.raw_decode(text, len(text) - len(text.lstrip(" \t\r\n")))
        if text[end:].strip(" \t\r\n"):
            raise ValueError("Unexpected content after JSON document")
        return value
    except (UnicodeError, RecursionError) as exc:
        raise ValueError("Use UTF-8 JSON with supported nesting") from exc


def render(raw, config, settings, allow_reformat=False):
    if any(key not in config for key in settings) and not allow_reformat:
        raise ValueError("Policy adds missing keys; review and opt in with --allow-reformat")
    if allow_reformat:
        def exact_number(token):
            parsed = number(token)
            if Decimal(token) != Decimal(str(parsed)):
                raise ValueError("Full reformat would lose numeric precision; use existing-key edits or revise the config")
            return parsed
        json.loads(raw.decode("utf-8-sig"), object_pairs_hook=pairs,
                   parse_float=exact_number, parse_constant=invalid_constant)
        updated = dict(config, **settings)
        return (json.dumps(updated, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode("utf-8")
    text = raw.decode("utf-8-sig")
    index = 0
    edits = []

    def skip_space(position):
        while position < len(text) and text[position] in " \t\r\n":
            position += 1
        return position

    index = skip_space(index) + 1  # opening object already validated by caller
    while text[skip_space(index)] != "}":
        index = skip_space(index)
        key, index = DECODER.raw_decode(text, index)
        index = skip_space(index) + 1  # colon
        start = skip_space(index)
        _, end = DECODER.raw_decode(text, start)
        if key in settings and (type(config[key]) is not type(settings[key]) or config[key] != settings[key]):
            edits.append((start, end, json.dumps(settings[key], ensure_ascii=True, allow_nan=False)))
        index = skip_space(end)
        if text[index] == "}":
            break
        index += 1  # comma
    for start, end, replacement in reversed(edits):
        text = text[:start] + replacement + text[end:]
    return (codecs.BOM_UTF8 if raw.startswith(codecs.BOM_UTF8) else b"") + text.encode("utf-8")
