"""Deduplicated reference links for a hardening tab"""

from __future__ import annotations

from typing import Any

from textual.widgets import Collapsible, Static

from gui.shared.formatting import markup_escape


class ReferencesBar(Collapsible):
    """Collapsed "References (N)" block listing unique links for a section, cuz structure of Kernel docs"""

    def __init__(self, links: list[Any], *args, **kwargs) -> None:
        self._links = [str(link) for link in links]
        kwargs.setdefault("collapsed", True)
        super().__init__(
            *[self._link_static(link) for link in self._links],
            title=self._references_title(),
            **kwargs,
        )

    @staticmethod
    def _link_static(link: str) -> Static:
        return Static(
            f'[link="{link}"]{markup_escape(link)}[/link]',
            classes="mono link",
        )

    def _references_title(self) -> str:
        return f"References ({len(self._links)})"

    def set_links(self, links: list[Any]) -> None:
        self._links = [str(link) for link in links]
        self.title = self._references_title()
        contents = self.query_one(Collapsible.Contents)
        for child in list(contents.children):
            child.remove()
        contents.mount(*[self._link_static(link) for link in self._links])