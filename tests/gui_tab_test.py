"""Keyboard tab navigation for the scan page (pure-TTY, mouse-less terminals).

TabbedContent ships no key bindings of its own, so on a plain TTY the tabs
are switched with the numbered shortcuts and the [ ] cycling actions added
on ScanPage.
"""

from typing import cast

import anyio
from textual.app import App
from textual.widgets import Static, TabbedContent

from gui.pages.base_screen import BaseScreen
from gui.pages.scan_page import _TAB_KEYS, ScanPage


class _TabApp(App[None]):
    def on_mount(self) -> None:
        self.push_screen(ScanPage())


def test_tab_keys_match_pane_order():
    assert [pane_id for pane_id, *_ in _TAB_KEYS] == [
        "tab-audit",
        "tab-selinux",
        "tab-caps",
        "tab-cve",
        "tab-sandbox",
        "tab-engine",
    ]


def test_numbered_tab_shortcuts():
    async def main() -> None:
        app = _TabApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            tabbed = app.screen.query_one(TabbedContent)
            assert tabbed.active == "tab-audit"
            await pilot.press("4")
            await pilot.pause()
            assert tabbed.active == "tab-cve"
            await pilot.press("6")
            await pilot.pause()
            assert tabbed.active == "tab-engine"
            await pilot.press("1")
            await pilot.pause()
            assert tabbed.active == "tab-audit"

    anyio.run(main)


def test_bracket_keys_cycle_tabs():
    async def main() -> None:
        app = _TabApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            tabbed = app.screen.query_one(TabbedContent)
            assert tabbed.active == "tab-audit"
            await pilot.press("]")
            await pilot.pause()
            assert tabbed.active == "tab-selinux"
            await pilot.press("]")
            await pilot.pause()
            assert tabbed.active == "tab-caps"
            await pilot.press("[")
            await pilot.pause()
            assert tabbed.active == "tab-selinux"
            # wrap around the ends
            await pilot.press("[")
            await pilot.pause()
            assert tabbed.active == "tab-audit"
            await pilot.press("[")
            await pilot.pause()
            assert tabbed.active == "tab-engine"

    anyio.run(main)


def test_vim_h_l_keys_cycle_tabs():
    async def main() -> None:
        app = _TabApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            tabbed = app.screen.query_one(TabbedContent)
            assert tabbed.active == "tab-audit"
            await pilot.press("l")
            await pilot.pause()
            assert tabbed.active == "tab-selinux"
            await pilot.press("l")
            await pilot.pause()
            assert tabbed.active == "tab-caps"
            await pilot.press("h")
            await pilot.pause()
            assert tabbed.active == "tab-selinux"
            await pilot.press("h")
            await pilot.pause()
            assert tabbed.active == "tab-audit"
            await pilot.press("h")
            await pilot.pause()
            assert tabbed.active == "tab-engine"

    anyio.run(main)


def test_footer_is_composed_for_key_hints():
    async def main() -> None:
        from textual.widgets import Footer

        app = _TabApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            assert app.screen.query_one(Footer) is not None

    anyio.run(main)


async def _fill_scroll(screen, list_id: str) -> Static:
    scroll = screen.query_one(f"#{list_id}")
    for i in range(60):
        await scroll.mount(Static(f"row {i}"), before=None)
    return scroll


def test_scroll_target_tracks_active_tab():
    """j/k/arrows must scroll the currently visible tab list, not the hidden
    first tab: inactive TabPanes keep display=True on their children, so the
    scroll target is resolved by walking the ancestor chain instead."""

    async def main() -> None:
        app = _TabApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            screen = cast(BaseScreen, app.screen)
            audit = await _fill_scroll(screen, "audit_list")
            selinux = await _fill_scroll(screen, "selinux_list")
            await pilot.pause()

            assert screen._scroll_target() is audit

            await pilot.press("]")
            await pilot.pause()
            assert screen._scroll_target() is selinux

            await pilot.press("j")
            await pilot.pause()
            assert selinux.scroll_y > 0
            await pilot.press("k")
            await pilot.pause()
            assert selinux.scroll_y == 0

    anyio.run(main)


def test_scroll_target_prefers_console_on_engine_tab():
    """On the Engine-stdout tab the big scroll area is the console log."""

    async def main() -> None:
        from gui.widgets.console_log import ConsoleLog

        app = _TabApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            screen = cast(BaseScreen, app.screen)
            await pilot.press("6")
            await pilot.pause()
            target = screen._scroll_target()
            assert target is screen.query_one(ConsoleLog)

    anyio.run(main)


def test_rendered_skips_hidden_tab_panes():
    async def main() -> None:
        app = _TabApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            screen = cast(BaseScreen, app.screen)
            audit = screen.query_one("#audit_list")
            selinux = screen.query_one("#selinux_list")
            # both panes are hidden except the active one
            assert screen._rendered(audit) is True
            assert screen._rendered(selinux) is False
            await pilot.press("]")
            await pilot.pause()
            assert screen._rendered(audit) is False
            assert screen._rendered(selinux) is True

    anyio.run(main)