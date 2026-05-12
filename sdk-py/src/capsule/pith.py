"""Pith — context-style discipline for capsule narrative fields.

Direct port of sdk/src/pith.js.
"""

from __future__ import annotations

import copy
import re
from typing import Any

PITH_VERSION = "0.6"
_DEFAULT_MAX_CHARS = 280
_DEFAULT_MAX_SENTENCES = 3
_ELLIPSIS = "…"

_WS_RE = re.compile(r"[\t ]+")
_LINEEND_RE = re.compile(r"\r\n?")
_SENTENCE_RE = re.compile(r"[^.!?]+(?:[.!?]+|$)")
_TRAIL_PUNCT_RE = re.compile(r"[\s,;:.!?\-]+$")


def compress_text(
    input: str, *, max_chars: int | None = None, max_sentences: int | None = None
) -> dict:
    """Compress narrative text by whitespace normalization, sentence limiting, and truncation.

    Returns dict with keys: text, changed, version.
    """
    if not isinstance(input, str):
        raise TypeError("compress_text: input must be a string")
    mc = max_chars if isinstance(max_chars, int) and max_chars > 0 else _DEFAULT_MAX_CHARS
    ms = (
        max_sentences
        if isinstance(max_sentences, int) and max_sentences > 0
        else _DEFAULT_MAX_SENTENCES
    )
    normalized = _normalize_whitespace(input)
    trimmed = _first_sentences(normalized, ms)
    text = _truncate_at_word_boundary(trimmed, mc)
    return {"text": text, "changed": text != input, "version": PITH_VERSION}


def compress_event_payload(payload: Any, **opts: Any) -> Any:
    """Deep-clone payload and normalize known narrative fields.

    Normalizes: summary, statement, note, open_items[].item,
    decisions[].text, milestones[].text.
    Non-dict inputs pass through unchanged.
    """
    copy_ = copy.deepcopy(payload)
    if not isinstance(copy_, dict):
        return copy_
    _compress_field(copy_, "summary", opts)
    _compress_field(copy_, "statement", opts)
    _compress_field(copy_, "note", opts)
    _compress_list_field(copy_, "open_items", "item", opts)
    _compress_list_field(copy_, "decisions", "text", opts)
    _compress_list_field(copy_, "milestones", "text", opts)
    return copy_


def _normalize_whitespace(s: str) -> str:
    """Collapse \\r\\n? → \\n, split lines, collapse [\\t ]+ → space, strip, join."""
    s = _LINEEND_RE.sub("\n", s)
    lines = [_WS_RE.sub(" ", line).strip() for line in s.split("\n")]
    return " ".join(line for line in lines if line)


def _first_sentences(s: str, max_sentences: int) -> str:
    """Return the first N sentences, or original if fewer than N exist."""
    if not s:
        return s
    matches = _SENTENCE_RE.findall(s)
    if not matches:
        return s
    sentences = [m.strip() for m in matches if m.strip()]
    if len(sentences) <= max_sentences:
        return s
    return " ".join(sentences[:max_sentences])


def _truncate_at_word_boundary(s: str, max_chars: int) -> str:
    """Truncate at word boundary with ellipsis, respecting max_chars total length."""
    if len(s) <= max_chars:
        return s
    if max_chars <= len(_ELLIPSIS):
        return _ELLIPSIS[:max_chars]
    limit = max_chars - len(_ELLIPSIS)
    prefix = s[:limit]
    trimmed_prefix = prefix.rstrip()
    last_space = trimmed_prefix.rfind(" ")
    minimum_useful = limit * 6 // 10
    if len(prefix) != len(trimmed_prefix):
        # Prefix had trailing whitespace before rstrip; use rstripped version.
        bounded = trimmed_prefix
    elif last_space >= minimum_useful:
        # Last space is at >= 60% of limit; cut there.
        bounded = trimmed_prefix[:last_space]
    else:
        # Last space is < 60%; use rstripped prefix.
        bounded = trimmed_prefix
    cleaned = _TRAIL_PUNCT_RE.sub("", bounded)
    base = cleaned if cleaned else trimmed_prefix
    return base + _ELLIPSIS


def _compress_field(record: dict, key: str, opts: dict) -> None:
    """Compress a single string field in-place if it exists."""
    if not isinstance(record.get(key), str):
        return
    record[key] = compress_text(record[key], **opts)["text"]


def _compress_list_field(record: dict, list_key: str, text_key: str, opts: dict) -> None:
    """Compress a text field within list entries in-place."""
    lst = record.get(list_key)
    if not isinstance(lst, list):
        return
    for entry in lst:
        if isinstance(entry, dict):
            _compress_field(entry, text_key, opts)
