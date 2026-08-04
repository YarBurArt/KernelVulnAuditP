from datetime import datetime

import pytest

from db import get_db
from db.db_rd import InMemoryThreatDB
from schemas import HostInfoData, HostUser


@pytest.fixture
def db():
    database = get_db("memory")
    yield database
    database.close()


def _sample_host(hostname: str = "memsample", captured_at: datetime | None = None):
    return HostInfoData(
        hostname=hostname,
        kernel_version="6.8.0",
        captured_at=captured_at,
        users=[HostUser(username="bob", uid=1000, gid=1000)],
    )


def test_get_db_returns_correct_backend():
    db = get_db("memory")

    mro_names = [c.__name__ for c in type(db).__mro__]

    assert "ThreatDB" in mro_names
    assert isinstance(db, InMemoryThreatDB)

    db.close()


def test_unknown_backend_raises():
    with pytest.raises(ValueError):
        get_db("unknown")


def test_upsert_returns_int_id(db):
    vid = db.upsert_vulnerability(
        {
            "cve_id": "CVE-2024-0001",
            "description": "Test RCE",
            "cvss_v3_score": 9.8,
            "severity": "CRITICAL",
            "sources": ["NIST_NVD"],
        }
    )

    assert isinstance(vid, int)


def test_upsert_update_keeps_same_id(db):
    vid1 = db.upsert_vulnerability(
        {
            "cve_id": "CVE-2024-0001",
            "description": "Initial",
            "cvss_v3_score": 9.8,
            "severity": "CRITICAL",
        }
    )

    vid2 = db.upsert_vulnerability(
        {
            "cve_id": "CVE-2024-0001",
            "description": "Updated description",
            "cvss_v3_score": 9.8,
            "severity": "CRITICAL",
        }
    )

    assert vid1 == vid2


def test_get_vulnerability_roundtrip(db):
    db.upsert_vulnerability(
        {
            "cve_id": "CVE-2024-0001",
            "description": "Updated description",
            "cvss_v3_score": 9.8,
            "severity": "CRITICAL",
        }
    )

    vuln = db.get_vulnerability("CVE-2024-0001")

    assert vuln is not None
    assert vuln["cve_id"] == "CVE-2024-0001"
    assert vuln["description"] == "Updated description"


def test_get_vulnerability_missing_returns_none(db):
    assert db.get_vulnerability("CVE-9999-9999") is None


def test_add_exploit_updates_flags(db):
    db.upsert_vulnerability(
        {
            "cve_id": "CVE-2024-0001",
            "cvss_v3_score": 9.8,
            "severity": "CRITICAL",
        }
    )

    db.add_exploit(
        "CVE-2024-0001",
        {
            "exploit_type": "POC",
            "source": "GitHub",
            "url": "https://github.com/user/poc",
            "verified": True,
        },
    )

    vuln = db.get_vulnerability("CVE-2024-0001")

    assert vuln["has_exploit"] is True
    assert vuln["exploit_count"] == 1


def test_add_cisa_kev_updates_flags_and_score(db):
    db.upsert_vulnerability(
        {
            "cve_id": "CVE-2024-0001",
            "cvss_v3_score": 9.8,
            "severity": "CRITICAL",
        }
    )

    db.add_exploit(
        "CVE-2024-0001",
        {
            "exploit_type": "POC",
            "source": "GitHub",
        },
    )

    db.add_cisa_kev(
        "CVE-2024-0001",
        {
            "date_added": "2024-01-20",
            "required_action": "Patch now",
            "known_ransomware": True,
        },
    )

    vuln = db.get_vulnerability("CVE-2024-0001")

    assert vuln["in_cisa_kev"] is True
    assert vuln["criticality_score"] > 60


def test_sandbox_run_roundtrip(db):
    db.upsert_vulnerability(
        {
            "cve_id": "CVE-2024-0001",
            "cvss_v3_score": 9.8,
            "severity": "CRITICAL",
        }
    )

    db.add_sandbox_run(
        "CVE-2024-0001",
        {
            "run_timestamp": "2024-01-21T10:30:00",
            "sandbox_platform": "virtme-ng",
            "exploit_file_hash": "aabbcc",
            "execution_success": True,
            "exit_code": 0,
            "stdout": "Got shell\n",
            "stderr": "",
            "stdin": "./xpl\n",
            "open_processes": ["/bin/sh"],
            "open_files": ["/etc/passwd"],
            "notes": "LPE confirmed",
        },
    )

    runs = db.get_sandbox_runs("CVE-2024-0001")

    assert len(runs) == 1
    assert runs[0]["sandbox_platform"] == "virtme-ng"


def test_get_vulnerability_with_details(db):
    db.upsert_vulnerability(
        {
            "cve_id": "CVE-2024-0001",
            "cvss_v3_score": 9.8,
            "severity": "CRITICAL",
        }
    )

    db.add_exploit(
        "CVE-2024-0001",
        {
            "exploit_type": "POC",
            "source": "GitHub",
        },
    )

    db.add_cisa_kev(
        "CVE-2024-0001",
        {
            "date_added": "2024-01-20",
        },
    )

    db.add_sandbox_run(
        "CVE-2024-0001",
        {
            "sandbox_platform": "virtme-ng",
        },
    )

    full = db.get_vulnerability_with_details("CVE-2024-0001")

    assert len(full["exploits"]) == 1
    assert full["cisa_kev"] is not None
    assert len(full["sandbox_runs"]) == 1


def test_search_and_filters(db):
    db.upsert_vulnerability(
        {
            "cve_id": "CVE-2024-0001",
            "cvss_v3_score": 9.8,
            "severity": "CRITICAL",
        }
    )

    db.add_exploit(
        "CVE-2024-0001",
        {
            "exploit_type": "POC",
        },
    )

    db.add_cisa_kev(
        "CVE-2024-0001",
        {
            "known_ransomware": True,
        },
    )

    db.upsert_vulnerability(
        {
            "cve_id": "CVE-2024-0002",
            "description": "Low severity info leak",
            "cvss_v3_score": 3.1,
            "severity": "LOW",
            "sources": ["OSV"],
        }
    )

    assert len(db.search(severity="CRITICAL")) == 1
    assert len(db.search(min_cvss=9.0)) == 1
    assert len(db.get_critical()) == 1
    assert len(db.get_with_exploits()) == 1
    assert len(db.get_cisa_kev_list()) == 1


def test_bulk_insert_returns_count(db):
    inserted = db.bulk_insert(
        [
            {
                "cve_id": "CVE-2024-0010",
                "cvss_v3_score": 7.5,
                "severity": "HIGH",
            },
            {
                "cve_id": "CVE-2024-0011",
                "cvss_v3_score": 6.0,
                "severity": "MEDIUM",
            },
        ]
    )

    assert inserted == 2


def test_statistics(db):
    db.upsert_vulnerability(
        {
            "cve_id": "CVE-2024-0001",
            "cvss_v3_score": 9.8,
            "severity": "CRITICAL",
        }
    )

    db.add_exploit(
        "CVE-2024-0001",
        {
            "exploit_type": "POC",
        },
    )

    db.add_cisa_kev(
        "CVE-2024-0001",
        {
            "known_ransomware": True,
        },
    )

    db.bulk_insert(
        [
            {
                "cve_id": "CVE-2024-0010",
                "cvss_v3_score": 7.5,
                "severity": "HIGH",
            },
            {
                "cve_id": "CVE-2024-0011",
                "cvss_v3_score": 6.0,
                "severity": "MEDIUM",
            },
            {
                "cve_id": "CVE-2024-0012",
                "cvss_v3_score": 3.0,
                "severity": "LOW",
            },
        ]
    )

    stats = db.get_statistics()

    assert stats["total"] == 4
    assert stats["with_exploits"] == 1
    assert stats["in_cisa_kev"] == 1
    assert stats["ransomware_related"] == 1
    assert stats["avg_cvss"] > 0


def test_context_manager():
    with get_db("memory") as db:
        db.upsert_vulnerability(
            {
                "cve_id": "CVE-2024-9999",
                "cvss_v3_score": 5.0,
            }
        )


def test_host_info_roundtrip(db):
    hid = db.add_host_info(_sample_host())

    got = db.get_host_info(hid)

    assert got is not None
    assert got.id == hid
    assert got.hostname == "memsample"
    assert got.kernel_version == "6.8.0"
    assert got.users[0].username == "bob"
    assert got.users[0].uid == 1000


def test_host_info_missing_returns_none(db):
    assert db.get_host_info(424242) is None


def test_host_info_latest_ordering(db):
    db.add_host_info(_sample_host("older", datetime(2023, 1, 1, 8, 0, 0)))
    db.add_host_info(_sample_host("newer", datetime(2025, 1, 1, 8, 0, 0)))

    latest = db.get_latest_host_info()

    assert latest is not None
    assert latest.hostname == "newer"


def test_host_infos_header_only(db):
    db.add_host_info(_sample_host("h1"))

    headers = db.get_host_infos()

    assert [h.hostname for h in headers] == ["h1"]
    assert headers[0].users == []
    assert headers[0].groups == []


def test_host_infos_pagination(db):
    for i in range(3):
        db.add_host_info(_sample_host(f"host-{i}", datetime(2024, 1, i + 1)))

    page = db.get_host_infos(limit=2, offset=0)

    assert [h.hostname for h in page] == ["host-2", "host-1"]
