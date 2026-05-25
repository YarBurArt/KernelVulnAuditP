import pytest

from db_rd import InMemoryThreatDB


@pytest.fixture
def db():
    database = InMemoryThreatDB()
    yield database
    database.close()


def _base_vuln():
    return {
        "cve_id": "CVE-2024-1086",
        "description": "Critical RCE vulnerability",
        "published_date": "2024-01-15",
        "cvss_v3_score": 9.8,
        "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL",
        "cwe_ids": ["CWE-89"],
        "sources": ["NIST_NVD"],
    }


def test_upsert_and_get(db):
    vid = db.upsert_vulnerability(_base_vuln())

    assert isinstance(vid, int)
    assert vid >= 1

    vuln = db.get_vulnerability("CVE-2024-1086")

    assert vuln is not None
    assert vuln["severity"] == "CRITICAL"
    assert vuln["cvss_v3_score"] == 9.8


def test_update_keeps_same_id(db):
    vid1 = db.upsert_vulnerability(_base_vuln())

    updated = _base_vuln()
    updated["description"] = "Updated description"

    vid2 = db.upsert_vulnerability(updated)

    assert vid1 == vid2
    assert db.get_vulnerability("CVE-2024-1086")["description"] == "Updated description"


def test_missing_returns_none(db):
    assert db.get_vulnerability("CVE-9999-9999") is None


def test_exploit_tracking(db):
    db.upsert_vulnerability(_base_vuln())

    db.add_exploit("CVE-2024-1086", {
        "exploit_type": "POC",
        "source": "GitHub",
        "url": "https://github.com/user/exploit",
        "verified": True,
    })

    vuln = db.get_vulnerability("CVE-2024-1086")

    assert vuln["has_exploit"] is True
    assert vuln["exploit_count"] == 1

    db.add_exploit("CVE-2024-1086", {
        "exploit_type": "POC",
        "source": "Exploit-DB",
        "verified": False,
    })

    assert db.get_vulnerability("CVE-2024-1086")["exploit_count"] == 2


def test_cisa_and_criticality(db):
    db.upsert_vulnerability(_base_vuln())

    db.add_cisa_kev("CVE-2024-1086", {
        "date_added": "2024-01-20",
        "required_action": "Apply updates",
        "known_ransomware": True,
    })

    vuln = db.get_vulnerability("CVE-2024-1086")

    assert vuln["in_cisa_kev"] is True
    assert vuln["criticality_score"] == 100

def test_reference_and_sandbox(db):
    db.upsert_vulnerability(_base_vuln())

    db.add_reference(
        "CVE-2024-1086",
        url="https://github.com/user/poc",
        ref_type="GITHUB",
        source="GitHub",
    )

    db.add_exploit("CVE-2024-1086", {
        "exploit_type": "POC",
        "source": "GitHub",
        "url": "https://github.com/user/exploit",
        "verified": True,
    })

    db.add_exploit("CVE-2024-1086", {
        "exploit_type": "POC",
        "source": "Exploit-DB",
        "verified": False,
    })

    db.add_sandbox_run("CVE-2024-1086", {
        "run_timestamp": "2024-01-21T10:30:00",
        "sandbox_platform": "virtme-ng",
        "exploit_file_hash": "a1b2c3d4e5f6",
        "execution_success": True,
        "exit_code": 0,
        "stdout": "Exploit executed",
        "stderr": "Warning",
        "stdin": "./xpl\n",
        "open_processes": ["/bin/sh"],
        "open_files": ["/etc/passwd"],
        "notes": "Confirmed RCE",
    })

    full = db.get_vulnerability_with_details("CVE-2024-1086")

    assert len(full["references"]) == 1
    assert len(full["sandbox_runs"]) == 1
    assert len(full["exploits"]) == 2


def test_search_and_filters(db):
    db.upsert_vulnerability(_base_vuln())
    db.add_cisa_kev("CVE-2024-1086", {
        "date_added": "2024-01-20",
        "required_action": "Apply updates",
        "known_ransomware": True,
    })

    db.add_exploit("CVE-2024-1086", {
        "exploit_type": "POC",
        "source": "GitHub",
    })

    db.upsert_vulnerability({
        "cve_id": "CVE-2024-0002",
        "description": "Low severity info disclosure",
        "cvss_v3_score": 3.1,
        "severity": "LOW",
        "sources": ["OSV"],
    })

    assert len(db.search(severity="CRITICAL")) == 1
    assert len(db.search(severity="LOW")) == 1
    assert len(db.search(min_cvss=9.0)) == 1
    assert len(db.search(min_cvss=3.0)) == 2
    assert len(db.search(has_exploit=True)) == 1
    assert len(db.search(in_cisa_kev=True)) == 1


def test_pagination(db):
    db.upsert_vulnerability(_base_vuln())

    db.upsert_vulnerability({
        "cve_id": "CVE-2024-0002",
        "cvss_v3_score": 3.1,
        "severity": "LOW",
    })

    assert len(db.search(min_cvss=3.0, limit=10, offset=1)) == 1


def test_bulk_and_stats(db):
    db.upsert_vulnerability(_base_vuln())

    inserted = db.bulk_insert([
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
    ])

    assert inserted == 2

    stats = db.get_statistics()

    assert stats["total"] == 3
    assert stats["with_exploits"] >= 0
    assert stats["in_cisa_kev"] >= 0
    assert stats["avg_cvss"] > 0
    assert "CRITICAL" in stats["by_severity"]


def test_internal_require_raises(db):
    with pytest.raises(ValueError):
        db._require("CVE-9999-9999")


def test_context_manager():
    with InMemoryThreatDB() as db:
        db.upsert_vulnerability({
            "cve_id": "CVE-2024-9999",
            "cvss_v3_score": 5.0,
        })