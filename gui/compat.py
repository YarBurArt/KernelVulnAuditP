"""Runtime glyph shims for terminals without full Unicode box-drawing glyphs"""

from __future__ import annotations

from term import supports_unicode

#: per-glyph ASCII replacement for Textual box-drawing
_BOX_GLYPHS = {
    # corners
    "╭": "+", "╮": "+", "╰": "+", "╯": "+",
    "┌": "+", "┐": "+", "└": "+", "┘": "+",
    "╔": "+", "╗": "+", "╚": "+", "╝": "+",
    "┏": "+", "┓": "+", "┗": "+", "┛": "+",
    "▗": "+", "▖": "+", "▝": "+", "▘": "+",
    "▛": "+", "▜": "+", "▙": "+", "▟": "+",
    # horizontal strokes
    "─": "-", "━": "-", "═": "-", "╍": "-",
    "▁": "-", "▄": "-", "▀": "-", "▔": "-",
    # vertical strokes
    "│": "|", "║": "|", "╏": "|", "┃": "|",
    "▎": "|", "▏": "|", "▐": "|", "▌": "|", "▊": "|", "▕": "|",
    # fills
    "█": "#",
}


def _ascii_border(border: tuple | list) -> tuple:
    if not isinstance(border, (tuple, list)) or len(border) != 3:
        return tuple(border)
    return tuple(
        tuple(_BOX_GLYPHS.get(char, char) for char in row) for row in border
    )


_APPLIED = False


def apply_glyph_compat() -> bool:
    """Swap Textual hard-coded glyphs for ASCII when the terminal cannot draw them"""
    global _APPLIED
    if _APPLIED:
        return True
    if supports_unicode():
        return False

    from textual._border import BORDER_CHARS  # DEBUG
    from textual.renderables.bar import Bar
    from textual.scrollbar import ScrollBarRender

    for name, border in tuple(BORDER_CHARS.items()):
        BORDER_CHARS[name] = _ascii_border(border)

    Bar.BAR = "-"
    Bar.HALF_BAR_LEFT = "<"
    Bar.HALF_BAR_RIGHT = ">"

    ScrollBarRender.VERTICAL_BARS = ["|", "|", "|", "|", "|", "|", "|", " "]
    ScrollBarRender.HORIZONTAL_BARS = ["-", "-", "-", "-", "-", "-", "-", " "]

    _APPLIED = True
    return True


__all__ = ["apply_glyph_compat"]