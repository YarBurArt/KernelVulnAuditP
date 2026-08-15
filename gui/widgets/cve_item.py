"""Collapsible CVE + PoC row for the Exploit Vectors tab"""

from __future__ import annotations

from textual.widgets import Collapsible, Static

from gui.shared.formatting import is_url, markup_escape


class CveItem(Collapsible):
    """A vulnerability row: [source] cve_id title + details + clickable links.

    Children are passed to Collapsible.__init__ so the stock compose
    wraps them in a Contents container, which is what the -collapsed CSS hides.
    """

    def __init__(
        self,
        source: str,
        cve_id: str,
        title: str,
        details: str,
        urls: list[str] | None = None,
        *args,
        **kwargs,
    ) -> None:
        self.cve_id = str(cve_id)
        src = markup_escape(f"[{source}]").ljust(8)
        cve = markup_escape(self.cve_id).ljust(15)
        title_text = markup_escape(title)

        children: list[Static] = [Static(markup_escape(details), classes="mono")]
        for url in urls or []:
            if is_url(url):
                children.append(
                    Static(
                        f'[link="{url}"]{markup_escape(url)}[/link]',
                        classes="mono link",
                    )
                )
            else:
                children.append(Static(markup_escape(url), classes="mono dim"))

        super().__init__(
            *args,
            *children,
            title=f"[dim]{src}[/] [bold]{cve}[/] {title_text}",
            collapsed=True,
            **kwargs,
        )
