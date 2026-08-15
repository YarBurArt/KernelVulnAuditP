"""Thin facade over AppServices for the TUI controllers"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from app_services import AppServices
from db.db import ThreatDB


class Services:
    """Minimal AppServices adapter bound to a TUI progress factory"""

    def __init__(
        self,
        db: ThreatDB,
        progress: Callable[..., Any] | None = None,
    ) -> None:
        self._svc = AppServices(db=db, progress=progress)

    def run_local_recon(self, store_recs: bool = False):
        return self._svc.run_local_recon(store_recs)

    def run_feeds_recon(self, store_kev: bool = True):
        return self._svc.run_feeds_recon(store_kev)

    def run_execution_tests(self) -> dict[str, Any]:
        return self._svc.run_execution_tests()


__all__ = ["Services"]