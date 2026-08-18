"""Glyph compatibility shims for stripped-down (non-Unicode) terminals."""

import pytest

from gui import compat


@pytest.fixture(autouse=True)
def _restore_glyph_tables():
    """Restore Textual's glyph tables and the memoization flag after each test."""
    from textual._border import BORDER_CHARS
    from textual.renderables.bar import Bar
    from textual.scrollbar import ScrollBarRender

    original = {
        "borders": dict(BORDER_CHARS),
        "bar": (Bar.BAR, Bar.HALF_BAR_LEFT, Bar.HALF_BAR_RIGHT),
        "scroll": (
            list(ScrollBarRender.VERTICAL_BARS),
            list(ScrollBarRender.HORIZONTAL_BARS),
        ),
    }
    compat._APPLIED = False
    yield
    BORDER_CHARS.clear()
    BORDER_CHARS.update(original["borders"])
    Bar.BAR, Bar.HALF_BAR_LEFT, Bar.HALF_BAR_RIGHT = original["bar"]
    ScrollBarRender.VERTICAL_BARS[:] = original["scroll"][0]
    ScrollBarRender.HORIZONTAL_BARS[:] = original["scroll"][1]
    compat._APPLIED = False


def test_noop_when_unicode_supported(monkeypatch):
    monkeypatch.setattr(compat, "supports_unicode", lambda: True)

    assert compat.apply_glyph_compat() is False

    from textual._border import BORDER_CHARS

    assert BORDER_CHARS["round"] == (
        ("╭", "─", "╮"),
        ("│", " ", "│"),
        ("╰", "─", "╯"),
    )


def test_ascii_borders_when_limited(monkeypatch):
    monkeypatch.setattr(compat, "supports_unicode", lambda: False)

    assert compat.apply_glyph_compat() is True

    from textual._border import BORDER_CHARS
    from textual.renderables.bar import Bar
    from textual.scrollbar import ScrollBarRender

    assert BORDER_CHARS["round"] == (
        ("+", "-", "+"),
        ("|", " ", "|"),
        ("+", "-", "+"),
    )
    # the tab underline / progress bar glyphs
    assert Bar.BAR == "-"
    assert Bar.HALF_BAR_LEFT == "<"
    assert Bar.HALF_BAR_RIGHT == ">"
    # scrollbar thumbs
    assert ScrollBarRender.VERTICAL_BARS[0] == "|"
    assert ScrollBarRender.HORIZONTAL_BARS[0] == "-"
    assert ScrollBarRender.VERTICAL_BARS[-1] == " "


def test_memoized_across_calls(monkeypatch):
    calls = []

    def limited() -> bool:
        calls.append(1)
        return False

    monkeypatch.setattr(compat, "supports_unicode", limited)

    assert compat.apply_glyph_compat() is True
    assert compat.apply_glyph_compat() is True
    assert len(calls) == 1


def test_round_trip_after_tui_init(monkeypatch):
    """apply_glyph_compat is safe to call from KernelVulnTUI.__init__."""
    from textual._border import BORDER_CHARS

    monkeypatch.setattr(compat, "supports_unicode", lambda: False)
    assert compat.apply_glyph_compat() is True

    box = BORDER_CHARS["round"]
    # every glyph in the round border must now be plain ASCII
    for row in box:
        for char in row:
            assert char.isascii(), char
