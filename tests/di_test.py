from typing import Any

from app_services import AppServices
from application.di import build_container
from db.db import ThreatDB
from db.db_rd import InMemoryThreatDB


def test_container_resolves_db_and_services():
    container = build_container(backend="memory")
    try:
        db = container.get(ThreatDB)
        services = container.get(AppServices)
        assert isinstance(db, InMemoryThreatDB)
        assert services.db is db
    finally:
        container.close()


def test_container_default_progress_none():
    container = build_container(backend="memory")
    try:
        assert container.get(AppServices).progress is None
    finally:
        container.close()


def test_container_custom_progress():
    def bar(**kwargs: Any) -> None:
        return None

    container = build_container(backend="memory", progress=bar)
    try:
        assert container.get(AppServices).progress is bar
    finally:
        container.close()


def test_container_db_override():
    db = InMemoryThreatDB()
    container = build_container(backend="orm", db=db)
    try:
        assert container.get(ThreatDB) is db
        assert container.get(AppServices).db is db
    finally:
        container.close()


def test_container_resolves_once():
    container = build_container(backend="memory")
    try:
        db1 = container.get(ThreatDB)
        db2 = container.get(ThreatDB)
        assert db1 is db2
    finally:
        container.close()