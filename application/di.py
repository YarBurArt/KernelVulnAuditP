"""Dishka composition root for the application service graph.

Entry shims resolve ThreatDB and AppServices (and an optional
progress factory) from this container instead of hand-wiring them, so the
dependency graph is declared once and reused by CLI, report and GUI flows.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from dishka import Container, Provider, Scope, make_container, provide

from app_services import AppServices
from config import DB_BACKEND
from db.db import ThreatDB, get_db

ProgressFactory = Callable[..., Any] | None


class _AppProvider(Provider):
    def __init__(self, backend: str = DB_BACKEND, db: ThreatDB | None = None):
        super().__init__()
        self._backend = backend
        self._db = db

    @provide(scope=Scope.APP)
    def db(self) -> ThreatDB:
        if self._db is not None:
            return self._db
        return get_db(self._backend)

    @provide(scope=Scope.APP)
    def services(
        self, db: ThreatDB, progress: ProgressFactory
    ) -> AppServices:
        return AppServices(db=db, progress=progress)


class _ProgressProvider(Provider):
    def __init__(self, progress: ProgressFactory = None):
        super().__init__()
        self._progress = progress

    @provide(scope=Scope.APP)
    def progress(self) -> ProgressFactory:
        return self._progress


def build_container(
    backend: str = DB_BACKEND,
    progress: ProgressFactory = None,
    db: ThreatDB | None = None,
) -> Container:
    """Build a container resolving ThreatDB and AppServices.

    progress is the optional bar factory used by the service layer; pass
    None to run without progress bars. db overrides the backend-backed
    database (used by tests and callers that already hold a connection).
    """
    return make_container(
        _AppProvider(backend=backend, db=db),
        _ProgressProvider(progress),
    )


__all__ = ["ProgressFactory", "build_container"]