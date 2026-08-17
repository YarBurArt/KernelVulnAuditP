"""Keyboard tab navigation for the scan page (pure-TTY, mouse-less terminals).

TabbedContent ships no key bindings of its own, so on a plain TTY the tabs
are switched with the numbered shortcuts and the [ ] cycling actions added
on ScanPage.
"""

import anyio
from textual.app import App
from textual.widgets import TabbedContent

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


def test_footer_is_composed_for_key_hints():
    async def main() -> None:
        from textual.widgets import Footer

        app = _TabApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            assert app.screen.query_one(Footer) is not None

    anyio.run(main)