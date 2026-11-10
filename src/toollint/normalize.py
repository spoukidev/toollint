"""Unicode normalization and decoding helpers.

Everything here is pure and total: functions accept any ``str`` and never raise,
which matters because the input is attacker-controlled. ``tests/test_normalize.py``
fuzzes these with hypothesis.
"""

from __future__ import annotations

import base64
import binascii
import math
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass

# --------------------------------------------------------------------------------------
# Invisible / deceptive characters
# --------------------------------------------------------------------------------------

ZERO_WIDTH = {
    "\u200b": "ZERO WIDTH SPACE",
    "\u200c": "ZERO WIDTH NON-JOINER",
    "\u200d": "ZERO WIDTH JOINER",
    "\u2060": "WORD JOINER",
    "\u2061": "FUNCTION APPLICATION",
    "\u2062": "INVISIBLE TIMES",
    "\u2063": "INVISIBLE SEPARATOR",
    "\u2064": "INVISIBLE PLUS",
    "\ufeff": "ZERO WIDTH NO-BREAK SPACE (BOM)",
    "\u180e": "MONGOLIAN VOWEL SEPARATOR",
    "\u00ad": "SOFT HYPHEN",
}

BIDI_CONTROLS = {
    "\u202a": "LEFT-TO-RIGHT EMBEDDING",
    "\u202b": "RIGHT-TO-LEFT EMBEDDING",
    "\u202c": "POP DIRECTIONAL FORMATTING",
    "\u202d": "LEFT-TO-RIGHT OVERRIDE",
    "\u202e": "RIGHT-TO-LEFT OVERRIDE",
    "\u2066": "LEFT-TO-RIGHT ISOLATE",
    "\u2067": "RIGHT-TO-LEFT ISOLATE",
    "\u2068": "FIRST STRONG ISOLATE",
    "\u2069": "POP DIRECTIONAL ISOLATE",
}

#: Directional marks are legitimate in right-to-left text, so they are only
#: suspicious when the string contains no RTL script at all.
BIDI_MARKS = {
    "\u200e": "LEFT-TO-RIGHT MARK",
    "\u200f": "RIGHT-TO-LEFT MARK",
    "\u061c": "ARABIC LETTER MARK",
}

TAG_BLACK_FLAG = "\U0001f3f4"
TAG_CANCEL = "\U000e007f"

_RTL_RE = re.compile("[\u0590-\u08ff\ufb1d-\ufdff\ufe70-\ufeff]")
#: Scripts where ZWNJ/ZWJ are part of normal orthography (Arabic, Persian, Indic...).
_JOINER_SCRIPT_RE = re.compile("[\u0600-\u06ff\u0750-\u077f\u0900-\u0dff\u1780-\u17ff]")


def is_tag_char(ch: str) -> bool:
    return 0xE0000 <= ord(ch) <= 0xE007F


def is_variation_selector_supplement(ch: str) -> bool:
    return 0xE0100 <= ord(ch) <= 0xE01EF


def _is_emojiish(ch: str) -> bool:
    if not ch:
        return False
    cp = ord(ch)
    return (
        unicodedata.category(ch) == "So"
        or 0x1F000 <= cp <= 0x1FAFF
        or 0x2600 <= cp <= 0x27BF
        or 0x1F3FB <= cp <= 0x1F3FF
        or ch == "\ufe0f"
    )


@dataclass(frozen=True)
class HiddenChar:
    index: int
    char: str
    kind: str  # "zero-width" | "bidi" | "tag" | "variation-selector" | "format"
    name: str
    severity_hint: str  # "high" | "medium"

    @property
    def codepoint(self) -> str:
        return f"U+{ord(self.char):04X}"


def find_hidden_chars(text: str) -> list[HiddenChar]:
    """Return invisible or deceptive code points in ``text``, skipping benign uses.

    Benign uses that are *not* reported: ZWJ inside emoji sequences, ZWNJ/ZWJ in
    scripts that need them, directional marks in RTL text, and tag characters that
    form a subdivision flag (for example the flag of Scotland).
    """
    out: list[HiddenChar] = []
    has_rtl = bool(_RTL_RE.search(text))
    has_joiner_script = bool(_JOINER_SCRIPT_RE.search(text))
    in_flag = False
    for i, ch in enumerate(text):
        if is_tag_char(ch):
            if ch == TAG_CANCEL and in_flag:
                in_flag = False
                continue
            if in_flag:
                continue
            if i > 0 and text[i - 1] == TAG_BLACK_FLAG and _flag_sequence_ok(text, i):
                in_flag = True
                continue
            out.append(HiddenChar(i, ch, "tag", "TAG CHARACTER", "high"))
            continue
        in_flag = False
        if ch in BIDI_CONTROLS:
            out.append(HiddenChar(i, ch, "bidi", BIDI_CONTROLS[ch], "high"))
        elif ch in BIDI_MARKS:
            if not has_rtl:
                out.append(HiddenChar(i, ch, "bidi", BIDI_MARKS[ch], "medium"))
        elif ch in ZERO_WIDTH:
            if ch == "\u200d":
                prev = text[i - 1] if i > 0 else ""
                nxt = text[i + 1] if i + 1 < len(text) else ""
                if (_is_emojiish(prev) and _is_emojiish(nxt)) or has_joiner_script:
                    continue
            if ch == "\u200c" and has_joiner_script:
                continue
            sev = "medium" if ch == "\u00ad" else "high"
            out.append(HiddenChar(i, ch, "zero-width", ZERO_WIDTH[ch], sev))
        elif is_variation_selector_supplement(ch):
            out.append(HiddenChar(i, ch, "variation-selector", "VARIATION SELECTOR SUPPLEMENT", "high"))
        elif unicodedata.category(ch) == "Cf" and ch not in ("\ufe0f",):
            name = unicodedata.name(ch, "FORMAT CHARACTER")
            out.append(HiddenChar(i, ch, "format", name, "medium"))
    return out


def _flag_sequence_ok(text: str, start: int) -> bool:
    """True when text[start:] is ``tag letters... CANCEL TAG`` (a subdivision flag)."""
    j = start
    while j < len(text) and is_tag_char(text[j]) and text[j] != TAG_CANCEL:
        if not (0xE0061 <= ord(text[j]) <= 0xE007A or 0xE0030 <= ord(text[j]) <= 0xE0039):
            return False
        j += 1
    return j < len(text) and text[j] == TAG_CANCEL and j - start <= 6


def decode_tag_chars(text: str) -> str:
    """Decode Unicode tag characters (``U+E0020..U+E007E``) back to the ASCII they shadow."""
    return "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E)


def strip_invisible(text: str) -> str:
    """Remove every format (Cf) character and tag character."""
    return "".join(
        c
        for c in text
        if unicodedata.category(c) != "Cf" and not is_tag_char(c) and not is_variation_selector_supplement(c)
    )


# --------------------------------------------------------------------------------------
# Homoglyphs
# --------------------------------------------------------------------------------------

#: Cyrillic and Greek letters that render (near-)identically to Latin ones.
CONFUSABLES: dict[str, str] = {
    # Cyrillic lowercase
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
    "ј": "j", "ѕ": "s", "һ": "h", "ԁ": "d", "ԛ": "q", "ԝ": "w", "ӏ": "l", "ɡ": "g",
    # Cyrillic uppercase
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P",
    "С": "C", "Т": "T", "У": "Y", "Х": "X", "І": "I", "Ј": "J", "Ѕ": "S",
    # Greek
    "α": "a", "ο": "o", "ν": "v", "ρ": "p", "τ": "t", "υ": "u", "ι": "i", "κ": "k",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M",
    "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
}  # fmt: skip

_WORD_RE = re.compile(r"[^\W\d_]+", re.UNICODE)


def _script_of(ch: str) -> str:
    name = unicodedata.name(ch, "")
    for script in ("LATIN", "CYRILLIC", "GREEK"):
        if name.startswith(script):
            return script
    return "OTHER"


@dataclass(frozen=True)
class MixedScriptWord:
    word: str
    index: int
    scripts: tuple[str, ...]
    skeleton: str


def find_mixed_script_words(text: str) -> list[MixedScriptWord]:
    """Words mixing Latin with Cyrillic/Greek letters, the classic homoglyph trick.

    Purely Cyrillic or Greek words are fine (that is just another language).
    """
    out: list[MixedScriptWord] = []
    for m in _WORD_RE.finditer(text):
        word = m.group(0)
        scripts = {_script_of(c) for c in word} - {"OTHER"}
        if "LATIN" in scripts and len(scripts) > 1:
            out.append(MixedScriptWord(word, m.start(), tuple(sorted(scripts)), skeleton(word)))
    return out


def skeleton(text: str) -> str:
    """Map confusable characters to their Latin look-alikes."""
    return "".join(CONFUSABLES.get(c, c) for c in text)


# --------------------------------------------------------------------------------------
# Normalization for matching
# --------------------------------------------------------------------------------------

_WS_RE = re.compile(r"\s+")


def normalize_for_matching(text: str) -> str:
    """Canonical lowercase form used by detection regexes.

    NFKC folds full-width and other compatibility forms, tag characters are decoded
    to the ASCII they hide, invisible characters are removed (so ``ign\u200bore``
    becomes ``ignore``), confusables are mapped to Latin, and whitespace collapses.
    """
    hidden_ascii = decode_tag_chars(text)
    text = unicodedata.normalize("NFKC", text)
    text = strip_invisible(text)
    if hidden_ascii:
        text = f"{text} {hidden_ascii}"
    text = skeleton(text)
    return _WS_RE.sub(" ", text).strip().lower()


# --------------------------------------------------------------------------------------
# Encoded blobs and entropy
# --------------------------------------------------------------------------------------

_B64_RE = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{32,}={0,2}(?![A-Za-z0-9+/=_-])")
_HEX_RE = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){16,}(?![0-9A-Fa-f])")


@dataclass(frozen=True)
class EncodedBlob:
    encoding: str  # "base64" | "hex"
    raw: str
    decoded: str
    index: int


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    ok = sum(1 for c in s if c.isprintable() or c in "\n\r\t")
    return ok / len(s)


def _looks_like_text(decoded: str) -> bool:
    letters = sum(1 for c in decoded if c.isalpha())
    return (
        len(decoded) >= 12
        and _printable_ratio(decoded) >= 0.95
        and letters / max(len(decoded), 1) >= 0.5
        and (" " in decoded or len(decoded) >= 24)
    )


def find_encoded_blobs(text: str) -> list[EncodedBlob]:
    """Base64 / hex runs that decode to readable text (a hash or random token does not)."""
    out: list[EncodedBlob] = []
    for m in _HEX_RE.finditer(text):
        try:
            decoded = bytes.fromhex(m.group(0)).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if _looks_like_text(decoded):
            out.append(EncodedBlob("hex", m.group(0), decoded, m.start()))
    for m in _B64_RE.finditer(text):
        raw = m.group(0)
        if any(b.index <= m.start() < b.index + len(b.raw) for b in out):
            continue
        if raw.isalpha() and (raw.islower() or raw.isupper()):
            continue  # a long plain word / identifier, not base64
        decoded_s = _try_b64(raw)
        if decoded_s is not None and _looks_like_text(decoded_s):
            out.append(EncodedBlob("base64", raw, decoded_s, m.start()))
    return out


def _try_b64(raw: str) -> str | None:
    candidate = raw.replace("-", "+").replace("_", "/")
    candidate += "=" * (-len(candidate) % 4)
    try:
        return base64.b64decode(candidate, validate=True).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None


def shannon_entropy(s: str) -> float:
    """Bits of entropy per character."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# --------------------------------------------------------------------------------------
# Safe display
# --------------------------------------------------------------------------------------


def safe_display(text: str, limit: int = 160) -> str:
    """Make attacker-controlled text safe to print in a terminal or log.

    Control characters (including ANSI escape sequences) and invisible characters
    are rendered as ``\\u{XXXX}`` escapes so they cannot rewrite the terminal or hide
    themselves in the report. Output is truncated to ``limit`` characters.
    """
    parts: list[str] = []
    for c in text:
        cat = unicodedata.category(c)
        if c in ("\n", "\t"):
            parts.append("\\n" if c == "\n" else "\\t")
        elif (
            cat in ("Cc", "Cf", "Cn", "Co", "Cs", "Zl", "Zp")
            or (cat == "Zs" and c != " ")
            or is_tag_char(c)
            or is_variation_selector_supplement(c)
        ):
            parts.append(f"\\u{{{ord(c):04X}}}")
        else:
            parts.append(c)
    out = "".join(parts)
    if len(out) > limit:
        out = out[: limit - 1] + "…"
    return out


def split_identifier(name: str) -> list[str]:
    """``sendEmail`` / ``send_email`` / ``send-email`` -> ``["send", "email"]``."""
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    return [p.lower() for p in re.split(r"[^A-Za-z0-9]+", name) if p]
