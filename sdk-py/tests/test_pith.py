import pytest

from capsule import CapsuleBuilder, CapsuleReader, generate_ed25519
from capsule.pith import (
    PITH_VERSION,
    compress_event_payload,
    compress_text,
    normalize_event_payload,
)

TS = "2026-05-07T12:00:00Z"

# The P1 reproduction: ordinary technical prose. Three sentences, dots
# inside an identifier (ledger.entry_audit) and a decimal (12.4k). The
# v0.6 splitter treated both dots as sentence boundaries, burned the
# three-sentence budget on fragments, and silently deleted the last two
# sentences.
WAL_PROSE = (
    "ledger.entry_audit is 88% of decoded WAL volume at 610 GB and roughly "
    "12.4k inserts per second during the settlement batch. The apply worker "
    "is pinned at 99% of one core. This is a throughput ceiling, not a "
    "tuning problem."
)


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


# ---------- sentence-boundary fidelity (the P1 defect) ----------


def test_dots_inside_identifiers_and_decimals_are_not_boundaries():
    r = compress_text(WAL_PROSE)
    assert r["text"] == WAL_PROSE
    assert r["changed"] is False


def test_sentence_selection_never_shortens_a_decimal():
    r = compress_text(
        "Pin the minor release at 14.11 or 16.4 before the batch. Then bump the fleet.",
        max_sentences=1,
    )
    assert r["text"] == "Pin the minor release at 14.11 or 16.4 before the batch."


def test_decimal_at_true_sentence_end_still_ends_the_sentence():
    r = compress_text(
        "Latency rose to 16.4. Then it fell back. Then it held. Then flat.",
        max_sentences=1,
    )
    assert r["text"] == "Latency rose to 16.4."


def test_versions_urls_and_code_fragments_survive_sentence_selection():
    inp = (
        "Deploy v0.7.1 from https://example.com/pkg.tar.gz using pkg.install(). "
        "Restart the worker. Verify the ledger. Close the ticket."
    )
    r = compress_text(inp, max_sentences=2)
    assert r["text"] == (
        "Deploy v0.7.1 from https://example.com/pkg.tar.gz using pkg.install(). "
        "Restart the worker."
    )


def test_abbreviations_do_not_end_sentences():
    r = compress_text(
        "Cache invalidation is hard, e.g. Redis and Memcached disagree. "
        "Pick one store. Document it. Move on.",
        max_sentences=1,
    )
    assert r["text"] == "Cache invalidation is hard, e.g. Redis and Memcached disagree."


def test_single_letter_initial_does_not_end_a_sentence():
    r = compress_text(
        "Reviewed by J. Smith on Tuesday. Approved for merge. Shipped. Done.",
        max_sentences=1,
    )
    assert r["text"] == "Reviewed by J. Smith on Tuesday."


def test_lowercase_continuation_is_not_a_new_sentence():
    r = compress_text(
        "restarted the daemon. systemd reported ok. Then we rotated the logs. Then we left.",
        max_sentences=2,
    )
    assert r["text"] == "restarted the daemon. systemd reported ok. Then we rotated the logs."


def test_ellipsis_run_does_not_burn_the_sentence_budget():
    r = compress_text(
        "The import stalled... retried twice more. Second attempt cleared the queue. "
        "Backlog empty. All good.",
        max_sentences=2,
    )
    assert r["text"] == (
        "The import stalled... retried twice more. Second attempt cleared the queue."
    )


def test_closing_quote_after_terminator_stays_with_its_sentence():
    r = compress_text(
        'He said "ship it." Then we shipped. Then we slept. Then coffee.',
        max_sentences=1,
    )
    assert r["text"] == 'He said "ship it."'


def test_cjk_terminators_split_without_inserting_spaces():
    inp = "一件目を確認した。二件目も確認した。三件目は保留。四件目は明日。"
    r = compress_text(inp, max_sentences=2)
    assert r["text"] == "一件目を確認した。二件目も確認した。"
    assert r["changed"] is True


def test_truncation_is_surrogate_safe_for_astral_text():
    # Parity with the JS lane's code-point-boundary guarantee.
    r = compress_text("\U0001F642" * 400)
    assert r["text"].endswith("…")
    assert r["text"].encode("utf-8")  # must be encodable, no lone surrogate


# ---------- normalize_event_payload: the change report ----------


def test_normalize_event_payload_reports_exactly_the_changed_fields():
    result = normalize_event_payload(
        {
            "summary": "Alice   submitted.",
            "statement": "Approved.",
            "note": "First. Second. Third. Fourth.",
            "open_items": [{"item": "Fix  bug."}],
            "decisions": [{"text": "Proceed."}],
        }
    )
    payload = result["payload"]
    assert payload["summary"] == "Alice submitted."
    assert payload["statement"] == "Approved."
    assert payload["note"] == "First. Second. Third."
    assert payload["open_items"][0]["item"] == "Fix bug."
    assert result["normalized_fields"] == [
        "payload.summary",
        "payload.note",
        "payload.open_items",
    ]


def test_normalize_event_payload_reports_nothing_when_nothing_changed():
    inp = {"summary": "Alice submitted.", "raw_id": "evt_001"}
    result = normalize_event_payload(inp)
    assert result["payload"] == inp
    assert result["normalized_fields"] == []


# ---------- CapsuleBuilder: Pith is opt-in authoring, not a default ----------


def _builder(ed, **kwargs):
    b = CapsuleBuilder(
        originator=ed,
        participants=[{"actor_id": "human:alice", "role": "originator"}],
        created_at=TS,
        **kwargs,
    )
    b.set_program("# X")
    return b


def _seal_and_read(builder, ed):
    data = builder.seal(
        signers=[{"role": "originator", "public_key": ed.public_key, "private_key": ed.private_key}],
        signed_at=TS,
    )
    return CapsuleReader.from_bytes(data).events()


def test_builder_narrative_payloads_pass_through_verbatim_by_default():
    ed = generate_ed25519()
    messy = "Alice\n\n  submitted   the   application.\nWith\n\n  multiple   spaces."
    b = _builder(ed)
    b.append_event(
        {
            "actor": "human:alice",
            "kind": "decision",
            "action": "submit",
            "target": "x",
            "timestamp": TS,
            "payload": {"summary": messy, "note": WAL_PROSE, "raw_id": "evt_001"},
        }
    )
    events = _seal_and_read(b, ed)
    assert events[0]["payload"]["summary"] == messy
    assert events[0]["payload"]["note"] == WAL_PROSE
    assert events[0]["payload"]["raw_id"] == "evt_001"
    assert "pith_normalized_fields" not in events[0]


def test_builder_pith_true_opts_in_and_records_changed_fields():
    ed = generate_ed25519()
    b = _builder(ed, pith=True)
    b.append_event(
        {
            "actor": "human:alice",
            "kind": "decision",
            "action": "submit",
            "target": "x",
            "timestamp": TS,
            "payload": {
                "summary": "Alice\n\n  submitted   the   application.",
                "statement": "Approved.",
            },
        }
    )
    events = _seal_and_read(b, ed)
    assert events[0]["payload"]["summary"] == "Alice submitted the application."
    assert events[0]["payload"]["statement"] == "Approved."
    assert events[0]["pith_normalized_fields"] == ["payload.summary"]


def test_builder_pith_event_with_no_change_carries_no_marker():
    ed = generate_ed25519()
    b = _builder(ed, pith=True)
    b.append_event(
        {
            "actor": "human:alice",
            "kind": "decision",
            "action": "submit",
            "target": "x",
            "timestamp": TS,
            "payload": {"summary": "Alice submitted the application."},
        }
    )
    events = _seal_and_read(b, ed)
    assert events[0]["payload"]["summary"] == "Alice submitted the application."
    assert "pith_normalized_fields" not in events[0]


def test_builder_per_event_pith_true_enables_on_default_builder():
    ed = generate_ed25519()
    b = _builder(ed)
    b.append_event(
        {
            "actor": "human:alice",
            "kind": "decision",
            "action": "a",
            "target": "x",
            "timestamp": TS,
            "payload": {"summary": "Alice\n\nsubmitted."},
        },
        pith=True,
    )
    b.append_event(
        {
            "actor": "human:alice",
            "kind": "decision",
            "action": "b",
            "target": "x",
            "timestamp": TS,
            "payload": {"summary": "Bob\n\napproved."},
        }
    )
    events = _seal_and_read(b, ed)
    assert events[0]["payload"]["summary"] == "Alice submitted."
    assert events[0]["pith_normalized_fields"] == ["payload.summary"]
    assert events[1]["payload"]["summary"] == "Bob\n\napproved."
    assert "pith_normalized_fields" not in events[1]


def test_builder_per_event_pith_false_wins_over_enabled_builder():
    ed = generate_ed25519()
    b = _builder(ed, pith=True)
    b.append_event(
        {
            "actor": "human:alice",
            "kind": "decision",
            "action": "a",
            "target": "x",
            "timestamp": TS,
            "payload": {"summary": "Alice\n\nsubmitted."},
        },
        pith=False,
    )
    events = _seal_and_read(b, ed)
    assert events[0]["payload"]["summary"] == "Alice\n\nsubmitted."
    assert "pith_normalized_fields" not in events[0]


def test_builder_caller_declared_marker_passes_through_and_merges():
    ed = generate_ed25519()
    b = _builder(ed, pith=True)
    b.append_event(
        {
            "actor": "human:alice",
            "kind": "decision",
            "action": "submit",
            "target": "x",
            "timestamp": TS,
            "payload": {"summary": "Alice\n\nsubmitted.", "statement": "Rewritten by hand."},
            "pith_normalized_fields": ["payload.statement"],
        }
    )
    events = _seal_and_read(b, ed)
    assert events[0]["pith_normalized_fields"] == ["payload.statement", "payload.summary"]


def test_builder_rejects_out_of_grammar_marker_entry():
    ed = generate_ed25519()
    b = _builder(ed)
    with pytest.raises(ValueError, match="pith_normalized_fields"):
        b.append_event(
            {
                "actor": "human:alice",
                "kind": "decision",
                "action": "submit",
                "target": "x",
                "timestamp": TS,
                "payload": {"summary": "x"},
                "pith_normalized_fields": ["not-payload.summary"],
            }
        )
