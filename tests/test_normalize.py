from __future__ import annotations

import string

from hypothesis import given, settings
from hypothesis import strategies as st

from toollint.normalize import (
    decode_tag_chars,
    find_encoded_blobs,
    find_hidden_chars,
    find_mixed_script_words,
    normalize_for_matching,
    safe_display,
    shannon_entropy,
    skeleton,
    split_identifier,
    strip_invisible,
)

ANY_TEXT = st.text(alphabet=st.characters(codec="utf-8", exclude_categories=["Cs"]), max_size=200)
SMUGGLE = st.sampled_from(
    ["\u200b", "\u200d", "\u2060", "\ufeff", "\u202e", "\u2066", "\U000e0041", "\U000e0101", "\u00ad"]
)


@given(ANY_TEXT)
def test_normalizer_is_total(text: str) -> None:
    # Never raises, always returns lowercase single-spaced text without invisibles.
    out = normalize_for_matching(text)
    assert out == out.strip()
    assert "  " not in out
    assert not find_hidden_chars(out)


@given(ANY_TEXT)
def test_normalizer_is_idempotent(text: str) -> None:
    once = normalize_for_matching(text)
    assert normalize_for_matching(once) == once


@given(
    st.text(alphabet=string.ascii_letters + " ", min_size=1, max_size=60),
    st.lists(st.tuples(st.integers(0, 60), SMUGGLE), max_size=8),
)
def test_invisible_characters_do_not_change_matching(text: str, inserts: list[tuple[int, str]]) -> None:
    smuggled = text
    for pos, ch in sorted(inserts, reverse=True):
        if ch in "\U000e0041":
            continue  # tag characters decode to visible ASCII on purpose
        smuggled = smuggled[:pos] + ch + smuggled[pos:]
    assert normalize_for_matching(smuggled) == normalize_for_matching(text)


@given(ANY_TEXT)
def test_strip_invisible_removes_every_hidden_char(text: str) -> None:
    assert not find_hidden_chars(strip_invisible(text))


@given(ANY_TEXT)
@settings(max_examples=200)
def test_safe_display_has_no_control_characters(text: str) -> None:
    out = safe_display(text, limit=10_000)
    assert "\x1b" not in out
    assert all(c.isprintable() for c in out)


@given(ANY_TEXT)
def test_helpers_never_raise(text: str) -> None:
    find_encoded_blobs(text)
    find_mixed_script_words(text)
    split_identifier(text)
    assert shannon_entropy(text) >= 0


def test_tag_characters_decode() -> None:
    hidden = "".join(chr(0xE0000 + ord(c)) for c in "hi there")
    assert decode_tag_chars("x" + hidden) == "hi there"
    assert "hi there" in normalize_for_matching("x" + hidden)


def test_ansi_escape_is_neutralized() -> None:
    assert safe_display("\x1b[2Jboom") == "\\u{001B}[2Jboom"


def test_confusable_skeleton() -> None:
    assert skeleton("раураl") == "paypal"
    words = find_mixed_script_words("Use the gіthub tool")
    assert words and words[0].skeleton == "github"


def test_full_width_folds() -> None:
    assert normalize_for_matching("ＩＧＮＯＲＥ") == "ignore"


def test_split_identifier() -> None:
    assert split_identifier("sendEmail") == ["send", "email"]
    assert split_identifier("delete-repo_now") == ["delete", "repo", "now"]


def test_entropy() -> None:
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("abcd") == 2
