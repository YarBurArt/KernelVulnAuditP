"""Thread-safe progress adapter implementing the AppServices bar API."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


class ProgressAdapter:
    """
    AppServices calls step/update/finish from a worker thread; each
    call is marshaled to the event loop through marshal (as
    App.call_from_thread) so widgets are only touched from the UI thread.
    When marshal is None the updates run synchronously just for tests
    """

    def __init__(
        self,
        target: Any,
        marshal: Callable[[Callable[..., Any]], Any] | None = None,
        total: int = 0,
        label: str = "",
        on_label: Callable[[str, bool, str], None] | None = None,
    ):
        self._target = target
        self._marshal = marshal
        self._total = max(int(total or 0), 0)
        self._label = label
        self._n = 0
        self._on_label = on_label
        self._emit()

    def _emit(self, final: bool = False, note: str = "") -> None:
        if self._target is None:
            return
        total = self._total if self._total > 0 else max(self._n, 1)
        frac = min(max(self._n / total, 0.0), 1.0)
        label = self._label
        # the note is display-only for the bar; the listeners (stages panel)
        # get the clean step label so "hardening complete" still maps to the
        # "hardening" sub-step instead of being dropped.
        display = f"{label} {note}" if note else label

        def _update() -> None:
            self._target.update(frac, display, visible=True, final=final)
            if self._on_label is not None:
                self._on_label(label, final, note)

        if self._marshal is not None:
            try:
                self._marshal(_update)
            except RuntimeError:
                # event loop is shutdown, then drop the update
                pass
        else:
            _update()

    def set_total(self, total: int, label: str | None = None) -> None:
        self._total = max(int(total or 0), 0)
        if label is not None:
            self._label = label
        self._emit()

    def set_label(self, label: str) -> None:
        self._label = label
        self._emit()

    def update(self, n: int, label: str | None = None, note: str = "") -> None:
        self._n = max(int(n or 0), 0)
        if label is not None:
            self._label = label
        self._emit(note=note)

    def step(self, amount: int = 1, label: str | None = None, note: str = "") -> None:
        self.update(self._n + amount, label, note)

    def detail(self, label: str, note: str = "") -> None:
        """rerender the current state carrying a per-step outcome note"""
        self._label = label
        self._emit(note=note)

    def finish(self, label: str | None = None, note: str = "") -> None:
        if label is not None:
            self._label = label
        if self._total > 0:
            self._n = self._total
        self._emit(final=True, note=note)