from datetime import UTC, datetime

import pytest

from db.db_orm import ThreatIntelligenceORM
from schemas import HostInfoData


@pytest.fixture
def db(tmp_path):
    database = ThreatIntelligenceORM(db_url=f"sqlite:///{tmp_path / 'ti.db'}")
    yield database
    database.close()


def _sample_host(hostname: str = "host1"):
    return HostInfoData(
        hostname=hostname,
        kernel_version="6.8.0",
        captured_at=datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC),
    )


def test_get_latest_host_info_empty_returns_none(db):
    assert db.get_latest_host_info() is None


def test_add_host_info_invalid_data_raises_and_rolls_back(db):
    with pytest.raises(Exception):
        db.host_info.add_host_info(
            HostInfoData(
                hostname="bad",
                kernel_version="6.8.0",
                users=[{"username": "not-a-user-object"}],
            )
        )

    assert db.get_host_infos() == []


def test_add_host_info_duplicate_user_raises_sqlalchemy_error_and_rolls_back(db):
    from schemas import HostUser

    with pytest.raises(Exception):
        db.host_info.add_host_info(
            HostInfoData(
                hostname="dup",
                kernel_version="6.8.0",
                users=[
                    HostUser(username="alice", uid=1000, gid=1000),
                    HostUser(username="alice", uid=1001, gid=1001),
                ],
            )
        )

    assert db.get_host_infos() == []


def test_get_host_info_missing_returns_none(db):
    assert db.get_host_info(9999) is None


def test_add_and_get_roundtrip(db):
    host = db.add_host_info(_sample_host())
    got = db.get_host_info(host.id)

    assert got is not None
    assert got.hostname == "host1"
    assert got.kernel_version == "6.8.0"


def test_get_latest_host_info_returns_most_recent(db):
    db.add_host_info(_sample_host("older"))
    newest = db.add_host_info(_sample_host("newest"))

    latest = db.get_latest_host_info()

    assert latest is not None
    assert latest.hostname == "newest"
    assert latest.id == newest.id