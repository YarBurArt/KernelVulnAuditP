"""Terminal glyph helpers: Unicode detection and glyph fallbacks."""

import locale
import os
import sys

from presentation.terminal import stream_tty


def supports_unicode(stream=None) -> bool:
    """Whether the terminal can render non-ASCII glyphs.

    Pure TTYs (TERM=linux / dumb / vt*) with a non-UTF-8 locale often lack
    those glyphs in their font; callers fall back to ASCII markers on them.
    """
    stream = stream or sys.stdout
    term_env = os.environ.get("TERM") or ""
    if term_env in ("dumb", "linux") or term_env.startswith("vt"):
        return False
    if not stream_tty(stream):
        return True
    encoding = ""
    try:
        encoding = str(stream.encoding or "").lower()
    except (AttributeError, ValueError):
        encoding = ""
    if not encoding:
        try:
            encoding = str(locale.getencoding()).lower()
        except (AttributeError, ValueError):
            encoding = ""
    return "utf" in encoding


_unicode_supported: bool | None = None


def unicode_glyph(unicode_char: str, ascii_fallback: str) -> str:
    """Pick a glyph for the current terminal, ASCII-safe on pure TTYs."""
    global _unicode_supported
    if _unicode_supported is None:
        _unicode_supported = supports_unicode()
    return unicode_char if _unicode_supported else ascii_fallback