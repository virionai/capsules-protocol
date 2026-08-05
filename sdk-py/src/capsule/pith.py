"""Pith — authoring-layer normalizer for capsule narrative fields.

Direct port of sdk-js/src/pith.js.

Pith is OPT-IN at the builder: pass ``pith=True`` to ``CapsuleBuilder``
(or per event) to have ``append_event`` normalize the narrative payload
fields. An author who writes prose gets their prose — lossy
normalization is never a default, because the rewrite lands inside the
hash chain where the original is not preserved. When normalization DID
change a field, the builder records it in the event's
``pith_normalized_fields`` member (spec/chain.md).

MEANING PRESERVATION. The v0.6 splitter treated every ``[.!?]`` as a
sentence boundary, so a dot inside an identifier (``ledger.entry_audit``)
or a decimal (``12.4k``) fragmented the sentence, burned the sentence
budget, and silently deleted trailing sentences. The scanner below only
ends a sentence at a terminator followed by whitespace (or end of
input), never mid-token, and errs toward keeping text. Selection cuts
the original string at sentence ends — kept text is byte-identical to
the input.
"""

from __future__ import annotations

import copy
import re
import unicodedata
from typing import Any

from .versions import CURRENT_VERSION

# Pith is versioned with the spec (never a separate literal — a second
# copy is exactly how a bump leaves a stale era behind).
PITH_VERSION = CURRENT_VERSION
_DEFAULT_MAX_CHARS = 280
_DEFAULT_MAX_SENTENCES = 3
_ELLIPSIS = "…"

_WS_RE = re.compile(r"[\t ]+")
_LINEEND_RE = re.compile(r"\r\n?")
_TRAIL_PUNCT_RE = re.compile(r"[\s,;:.!?\-]+$")

# Fullwidth terminators end a sentence unconditionally: they never
# appear inside identifiers, decimals, or abbreviations.
_CJK_TERMINATORS = frozenset("。！？｡")
# Closing quotes/brackets that stay attached to the sentence they close.
_SENTENCE_CLOSERS = frozenset("\"')]}»’”")
# Opening punctuation stripped from a token before the abbreviation check.
_TOKEN_OPENERS = frozenset("\"'([{«‘“")
# Common abbreviations whose trailing dot is not a sentence boundary.
# Kept deliberately small and technical-prose-oriented; a miss merely
# merges two sentences (keeps more text), never deletes content.
_ABBREVIATIONS = frozenset(
    [
        "e.g", "i.e", "eg", "ie", "etc", "vs", "cf", "ca", "al", "approx",
        "no", "nr", "fig", "figs", "eq", "sec", "ver", "rev", "resp",
        "dr", "mr", "mrs", "ms", "prof", "st", "jr", "sr", "dept", "inc", "ltd", "co",
    ]
)

_SINGLE_INITIAL_RE = re.compile(r"^[A-Z]$")


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


def normalize_event_payload(payload: Any, **opts: Any) -> dict:
    """Deep-clone payload, normalize known narrative fields, report changes.

    Returns ``{"payload": ..., "normalized_fields": [...]}`` where
    ``normalized_fields`` lists paths in the spec/chain.md payload-path
    grammar ("payload.summary", "payload.open_items", ...) naming exactly
    the members whose text the normalizer rewrote. Non-narrative fields
    are preserved verbatim and never reported.
    """
    copy_ = copy.deepcopy(payload)
    normalized_fields: list[str] = []
    if not isinstance(copy_, dict):
        return {"payload": copy_, "normalized_fields": normalized_fields}
    for key in ("summary", "statement", "note"):
        if _compress_field(copy_, key, opts):
            normalized_fields.append(f"payload.{key}")
    for list_key, text_key in (
        ("open_items", "item"),
        ("decisions", "text"),
        ("milestones", "text"),
    ):
        if _compress_list_field(copy_, list_key, text_key, opts):
            normalized_fields.append(f"payload.{list_key}")
    return {"payload": copy_, "normalized_fields": normalized_fields}


def compress_event_payload(payload: Any, **opts: Any) -> Any:
    """Deep-clone payload and normalize known narrative fields.

    Normalizes: summary, statement, note, open_items[].item,
    decisions[].text, milestones[].text.
    Non-dict inputs pass through unchanged.
    (normalize_event_payload without the change report.)
    """
    return normalize_event_payload(payload, **opts)["payload"]


def _normalize_whitespace(s: str) -> str:
    """Collapse \\r\\n? → \\n, split lines, collapse [\\t ]+ → space, strip, join."""
    s = _LINEEND_RE.sub("\n", s)
    lines = [_WS_RE.sub(" ", line).strip() for line in s.split("\n")]
    return " ".join(line for line in lines if line)


def _is_lowercase_letter(ch: str) -> bool:
    return unicodedata.category(ch) == "Ll"


def _sentence_end_offsets(s: str) -> list[int]:
    """Exclusive end offsets of each sentence in whitespace-normalized text.

    A sentence ends at:
      - a fullwidth CJK terminator (plus attached closers), always; or
      - an ASCII ``[.!?]+`` run (plus attached closers) followed by
        whitespace or end of input, where the next non-space character is
        not a lowercase letter, and — for a single '.' — the preceding
        token is neither a known abbreviation nor a single-letter initial.

    A dot inside a token (identifier, decimal, version, URL) is never
    followed by whitespace, so it can never end a sentence.
    """
    offsets: list[int] = []
    n = len(s)
    i = 0
    while i < n:
        ch = s[i]
        if ch in _CJK_TERMINATORS:
            j = i + 1
            while j < n and (s[j] in _CJK_TERMINATORS or s[j] in _SENTENCE_CLOSERS):
                j += 1
            offsets.append(j)
            i = j
            continue
        if ch in ".!?":
            j = i + 1
            while j < n and s[j] in ".!?":
                j += 1
            run_length = j - i
            k = j
            while k < n and s[k] in _SENTENCE_CLOSERS:
                k += 1
            if k < n and not s[k].isspace():
                i = j  # mid-token dot (a.b, 12.4, v0.7, example.com)
                continue
            m = k
            while m < n and s[m].isspace():
                m += 1
            if m < n and _is_lowercase_letter(s[m]):
                i = j  # lowercase continuation — keep one sentence
                continue
            if run_length == 1 and ch == "." and _preceding_token_blocks_boundary(s, i):
                i = j  # abbreviation ("e.g.", "etc.") or initial ("J.")
                continue
            offsets.append(k)
            i = k
            continue
        i += 1
    if not offsets or offsets[-1] < n:
        offsets.append(n)  # trailing unterminated text is the final sentence
    return offsets


def _preceding_token_blocks_boundary(s: str, dot_index: int) -> bool:
    """True when the token ending at dot_index is an abbreviation or initial."""
    start = dot_index
    while start > 0 and not s[start - 1].isspace():
        start -= 1
    token = s[start:dot_index]
    while token and token[0] in _TOKEN_OPENERS:
        token = token[1:]
    if not token:
        return False
    if _SINGLE_INITIAL_RE.match(token):
        return True  # "J." in "J. Smith"
    return token.lower() in _ABBREVIATIONS


def _first_sentences(s: str, max_sentences: int) -> str:
    """Return the input cut at the Nth sentence end, or unchanged if fewer."""
    if not s:
        return s
    ends = _sentence_end_offsets(s)
    if len(ends) <= max_sentences:
        return s
    # Cut the ORIGINAL string at the Nth sentence end: kept text is
    # identical to the input (no re-joining, no inserted spaces).
    return s[: ends[max_sentences - 1]].rstrip()


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


def _compress_field(record: dict, key: str, opts: dict) -> bool:
    """Compress a single string field in-place; True when the text changed."""
    if not isinstance(record.get(key), str):
        return False
    before = record[key]
    record[key] = compress_text(before, **opts)["text"]
    return record[key] != before


def _compress_list_field(record: dict, list_key: str, text_key: str, opts: dict) -> bool:
    """Compress a text field within list entries in-place; True on any change."""
    lst = record.get(list_key)
    if not isinstance(lst, list):
        return False
    changed = False
    for entry in lst:
        if isinstance(entry, dict) and _compress_field(entry, text_key, opts):
            changed = True
    return changed
