from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from db.db_orm import ThreatIntelligenceORM
from db.models import Base, SecurityRecommendation
from db.recommendation_repo import RecommendationRepository


@pytest.fixture
def repo(tmp_path):
    db_path = tmp_path / "ti_test.db"
    database = ThreatIntelligenceORM(db_url=f"sqlite:///{db_path}")
    yield database.recommendations
    database.close()


def _rec(
    test_id: str = "KRNL-6000",
    category: str = "kernel",
    severity: str = "HIGH",
    status: str = "FAIL",
    **kwargs,
) -> SecurityRecommendation:
    return SecurityRecommendation(
        test_id=test_id,
        category=category,
        severity=severity,
        status=status,
        **kwargs,
    )


def test_add_security_recommendation_returns_id(repo):
    rid = repo.add_security_recommendation(_rec())

    assert isinstance(rid, int)
    assert rid >= 1


def test_add_roundtrip_preserves_fields(repo):
    rid = repo.add_security_recommendation(
        _rec(
            description="restrict core dumps",
            field_name="fs.suid_dumpable",
            expected_value="0",
            actual_value="2",
            source="lynis",
            raw_data={"solution": "https://kernel.org/doc"},
        )
    )

    rows = repo.get_security_recommendations()
    assert len(rows) == 1
    row = rows[0]
    assert row["id"] == rid
    assert row["description"] == "restrict core dumps"
    assert row["field_name"] == "fs.suid_dumpable"
    assert row["expected_value"] == "0"
    assert row["actual_value"] == "2"
    assert row["source"] == "lynis"
    assert row["raw_data"] == {"solution": "https://kernel.org/doc"}


def test_add_missing_test_id_rolls_back_and_raises(repo):
    rec = SecurityRecommendation(description="no test id")

    with pytest.raises(Exception):
        repo.add_security_recommendation(rec)

    assert repo.get_security_recommendations() == []


def test_bulk_insert_counts_successes(repo):
    count = repo.bulk_insert_recommendations(
        [
            _rec("KRNL-6001"),
            _rec("KRNL-6002", category="selinux", severity="MEDIUM", status="WARNING"),
            _rec("KRNL-6003"),
        ]
    )

    assert count == 3


def test_bulk_insert_skips_failed_records(repo):
    count = repo.bulk_insert_recommendations(
        [
            _rec("KRNL-6001"),
            SecurityRecommendation(description="bad"),
            _rec("KRNL-6002"),
        ]
    )

    assert count == 2
    assert len(repo.get_security_recommendations()) == 2


def test_get_recommendations_filters_category_and_status(repo):
    repo.bulk_insert_recommendations(
        [
            _rec("KRNL-6001", category="kernel", status="FAIL"),
            _rec("KRNL-6002", category="kernel", status="WARNING"),
            _rec("KRNL-6003", category="selinux", status="FAIL"),
        ]
    )

    assert len(repo.get_security_recommendations(category="kernel")) == 2
    assert len(repo.get_security_recommendations(status="FAIL")) == 2
    assert len(
        repo.get_security_recommendations(category="kernel", status="FAIL")
    ) == 1


def test_get_recommendations_pagination_and_order(repo):
    repo.bulk_insert_recommendations(
        [
            _rec("KRNL-6001", severity="LOW"),
            _rec("KRNL-6002", severity="HIGH"),
            _rec("KRNL-6003", severity="CRITICAL"),
        ]
    )

    # ordered by severity desc: alphabetical on the string column
    page = repo.get_security_recommendations(limit=2, offset=0)
    assert [r["test_id"] for r in page] == ["KRNL-6001", "KRNL-6002"]

    next_page = repo.get_security_recommendations(limit=2, offset=2)
    assert [r["test_id"] for r in next_page] == ["KRNL-6003"]


def test_get_recommendations_empty_db(repo):
    assert repo.get_security_recommendations() == []


def test_get_recommendations_stats(repo):
    repo.bulk_insert_recommendations(
        [
            _rec("KRNL-6001", category="kernel", severity="HIGH", status="FAIL"),
            _rec("KRNL-6002", category="kernel", severity="MEDIUM", status="WARNING"),
            _rec("KRNL-6003", category="selinux", severity="HIGH", status="FAIL"),
            SecurityRecommendation(test_id="KRNL-6004"),
        ]
    )

    stats = repo.get_recommendations_stats()

    assert stats["total"] == 4
    assert stats["by_category"] == {"kernel": 2, "selinux": 1}
    assert stats["by_status"] == {"FAIL": 2, "WARNING": 1}
    assert stats["by_severity"] == {"HIGH": 2, "MEDIUM": 1}


def test_get_recommendations_stats_empty(repo):
    stats = repo.get_recommendations_stats()

    assert stats["total"] == 0
    assert stats["by_category"] == {}
    assert stats["by_status"] == {}
    assert stats["by_severity"] == {}


def test_repo_requires_session_factory():
    assert RecommendationRepository(sessionmaker()).get_session() is not None


def test_created_at_defaults_to_now(repo):
    now = datetime.now(UTC).timestamp()
    rid = repo.add_security_recommendation(_rec())
    row = repo.get_security_recommendations()[0]

    assert row["created_at"] is not None
    created = datetime.fromisoformat(str(row["created_at"]))
    created = created.replace(tzinfo=UTC)
    assert abs(now - created.timestamp()) < 60


def test_orm_facade_delegates_to_repo(tmp_path):
    db_path = tmp_path / "ti.db"
    with ThreatIntelligenceORM(db_url=f"sqlite:///{db_path}") as db:
        rid = db.add_security_recommendation(_rec("KRNL-9999"))

        assert db.get_security_recommendations(category="kernel")[0]["id"] == rid
        assert db.get_recommendations_stats()["total"] == 1