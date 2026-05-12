import pytest

from capsule.pith import PITH_VERSION, compress_event_payload, compress_text


def test_compress_text_short_input_unchanged():
    r = compress_text("hello world")
    assert r["text"] == "hello world"
    assert r["changed"] is False
    assert r["version"] == PITH_VERSION


def test_compress_text_collapses_whitespace():
    r = compress_text("  hello\n\n  world  \t  ")
    assert r["text"] == "hello world"
    assert r["changed"] is True


def test_compress_text_keeps_first_n_sentences():
    r = compress_text("One. Two. Three. Four. Five.", max_sentences=3)
    assert r["text"].startswith("One. Two. Three.")
    assert "Four" not in r["text"]


def test_compress_text_truncates_at_word_boundary():
    long = "word " * 200
    r = compress_text(long, max_chars=50)
    assert len(r["text"]) <= 50
    assert r["text"].endswith("…")


def test_compress_text_rejects_non_string():
    with pytest.raises(TypeError):
        compress_text(123)  # type: ignore[arg-type]


def test_compress_event_payload_normalizes_named_fields():
    inp = {
        "severity": 7,
        "summary": "  hello   world  ",
        "open_items": [{"item": "  fix   bug  "}],
        "decisions": [{"text": "  approved   "}],
        "milestones": [{"text": "  shipped   "}],
    }
    out = compress_event_payload(inp)
    assert out["severity"] == 7  # untouched
    assert out["summary"] == "hello world"
    assert out["open_items"][0]["item"] == "fix bug"
    assert out["decisions"][0]["text"] == "approved"
    assert out["milestones"][0]["text"] == "shipped"


def test_compress_event_payload_does_not_mutate_input():
    inp = {"summary": "  hello   world  "}
    _ = compress_event_payload(inp)
    assert inp == {"summary": "  hello   world  "}


def test_compress_event_payload_passes_non_dict_through():
    assert compress_event_payload("not-a-dict") == "not-a-dict"  # type: ignore[arg-type]
    assert compress_event_payload([1, 2, 3]) == [1, 2, 3]  # type: ignore[arg-type]


def test_compress_event_payload_skips_unknown_field_shapes():
    inp = {"open_items": "not a list"}
    out = compress_event_payload(inp)
    assert out["open_items"] == "not a list"  # untouched
