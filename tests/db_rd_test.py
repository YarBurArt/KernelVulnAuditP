from datetime import UTC, datetime

import pytest

from core.entities import (
    CisaKevEntry,
    Exploit,
    HostInfo,
    SandboxRun,
    SecurityRecommendation,
    Vulnerability,
)
from db.db_rd import InMemoryThreatDB


@pytest.fixture
def db():
    database = InMemoryThreatDB()
    yield database
    database.close()


def _base_vuln():
    return Vulnerability(
        cve_id="CVE-2024-1086",
        description="Critical RCE vulnerability",
        published_date=datetime(2024, 1, 15, tzinfo=UTC),
        cvss_v3_score=9.8,
        cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        severity="CRITICAL",
        cwe_ids=["CWE-89"],
        sources=["NIST_NVD"],
    )


def test_upsert_and_get(db):
    vid = db.upsert_vulnerability(_base_vuln())

    assert isinstance(vid, int)
    assert vid >= 1

    vuln = db.get_vulnerability("CVE-2024-1086")

    assert vuln is not None
    assert vuln.severity == "CRITICAL"
    assert vuln.cvss_v3_score == 9.8


def test_update_keeps_same_id(db):
    vid1 = db.upsert_vulnerability(_base_vuln())

    updated = _base_vuln()
    updated.description = "Updated description"

    vid2 = db.upsert_vulnerability(updated)

    assert vid1 == vid2
    assert db.get_vulnerability("CVE-2024-1086").description == "Updated description"


def test_missing_returns_none(db):
    assert db.get_vulnerability("CVE-9999-9999") is None


def test_exploit_tracking(db):
    db.upsert_vulnerability(_base_vuln())

    db.add_exploit(
        "CVE-2024-1086",
        Exploit(
            exploit_type="POC",
            source="GitHub",
            url="https://github.com/user/exploit",
            verified=True,
        ),
    )

    vuln = db.get_vulnerability("CVE-2024-1086")

    assert vuln.has_exploit is True
    assert vuln.exploit_count == 1

    db.add_exploit(
        "CVE-2024-1086",
        Exploit(
            exploit_type="POC",
            source="Exploit-DB",
            verified=False,
        ),
    )

    assert db.get_vulnerability("CVE-2024-1086").exploit_count == 2


def test_cisa_and_criticality(db):
    db.upsert_vulnerability(_base_vuln())

    db.add_cisa_kev(
        "CVE-2024-1086",
        CisaKevEntry(
            date_added=datetime(2024, 1, 20, tzinfo=UTC),
            required_action="Apply updates",
            known_ransomware=True,
        ),
    )

    vuln = db.get_vulnerability("CVE-2024-1086")

    assert vuln.in_cisa_kev is True
    assert vuln.criticality_score == 100


def test_reference_and_sandbox(db):
    db.upsert_vulnerability(_base_vuln())

    db.add_reference(
        "CVE-2024-1086",
        url="https://github.com/user/poc",
        ref_type="GITHUB",
        source="GitHub",
    )

    db.add_exploit(
        "CVE-2024-1086",
        Exploit(
            exploit_type="POC",
            source="GitHub",
            url="https://github.com/user/exploit",
            verified=True,
        ),
    )

    db.add_exploit(
        "CVE-2024-1086",
        Exploit(
            exploit_type="POC",
            source="Exploit-DB",
            verified=False,
        ),
    )

    db.add_sandbox_run(
        "CVE-2024-1086",
        SandboxRun(
            run_timestamp=datetime(2024, 1, 21, 10, 30, tzinfo=UTC),
            sandbox_platform="virtme-ng",
            exploit_file_hash="a1b2c3d4e5f6",
            execution_success=True,
            exit_code=0,
            stdout="Exploit executed",
            stderr="Warning",
            stdin="./xpl\n",
            open_processes=["/bin/sh"],
            open_files=["/etc/passwd"],
            notes="Confirmed RCE",
        ),
    )

    full = db.get_vulnerability_with_details("CVE-2024-1086")

    assert len(full.references) == 1
    assert len(full.sandbox_runs) == 1
    assert len(full.exploits) == 2


def test_search_and_filters(db):
    db.upsert_vulnerability(_base_vuln())
    db.add_cisa_kev(
        "CVE-2024-1086",
        CisaKevEntry(
            date_added=datetime(2024, 1, 20, tzinfo=UTC),
            required_action="Apply updates",
            known_ransomware=True,
        ),
    )

    db.add_exploit(
        "CVE-2024-1086",
        Exploit(
            exploit_type="POC",
            source="GitHub",
        ),
    )

    db.upsert_vulnerability(
        Vulnerability(
            cve_id="CVE-2024-0002",
            description="Low severity info disclosure",
            cvss_v3_score=3.1,
            severity="LOW",
            sources=["OSV"],
        )
    )

    assert len(db.search(severity="CRITICAL")) == 1
    assert len(db.search(severity="LOW")) == 1
    assert len(db.search(min_cvss=9.0)) == 1
    assert len(db.search(min_cvss=3.0)) == 2
    assert len(db.search(has_exploit=True)) == 1
    assert len(db.search(in_cisa_kev=True)) == 1


def test_pagination(db):
    db.upsert_vulnerability(_base_vuln())

    db.upsert_vulnerability(
        Vulnerability(
            cve_id="CVE-2024-0002",
            cvss_v3_score=3.1,
            severity="LOW",
        )
    )

    assert len(db.search(min_cvss=3.0, limit=10, offset=1)) == 1


def test_bulk_and_stats(db):
    db.upsert_vulnerability(_base_vuln())

    inserted = db.bulk_insert(
        [
            Vulnerability(
                cve_id="CVE-2024-0010",
                cvss_v3_score=7.5,
                severity="HIGH",
            ),
            Vulnerability(
                cve_id="CVE-2024-0011",
                cvss_v3_score=6.0,
                severity="MEDIUM",
            ),
        ]
    )

    assert inserted == 2

    stats = db.get_statistics()

    assert stats.total == 3
    assert stats.with_exploits >= 0
    assert stats.in_cisa_kev >= 0
    assert stats.avg_cvss > 0
    assert "CRITICAL" in stats.by_severity


def test_internal_require_raises(db):
    with pytest.raises(ValueError):
        db._require("CVE-9999-9999")


def test_context_manager():
    with InMemoryThreatDB() as db:
        db.upsert_vulnerability(
            Vulnerability(
                cve_id="CVE-2024-9999",
                cvss_v3_score=5.0,
            )
        )


def test_kev_known_ransomware_false(db):
    db.upsert_vulnerability(_base_vuln())
    db.add_cisa_kev("CVE-2024-1086", CisaKevEntry(known_ransomware=False))

    vuln = db.get_vulnerability("CVE-2024-1086")
    assert vuln.in_cisa_kev is True
    assert vuln.known_ransomware is not True


def test_details_missing_returns_none(db):
    assert db.get_vulnerability_with_details("CVE-9999-9999") is None


def test_exploitdb_reference_counts(db):
    db.upsert_vulnerability(_base_vuln())
    db.add_reference("CVE-2024-1086", "https://edb.com/1", ref_type="EXPLOIT_DB")

    vuln = db.get_vulnerability("CVE-2024-1086")
    assert vuln.exploitdb_refs == 1

    db.add_reference("CVE-2024-1086", "https://gh.com/1", source="GitHub")
    db.add_reference("CVE-2024-1086", "https://nvd.com/1", ref_type="ADVISORY")
    assert db.get_vulnerability("CVE-2024-1086").github_refs == 1


def test_statistics_no_cvss(db):
    db.upsert_vulnerability(Vulnerability(cve_id="CVE-2024-2000"))
    db.upsert_vulnerability(_base_vuln())

    stats = db.get_statistics()

    assert stats.avg_cvss > 0
    assert stats.by_severity["CRITICAL"] == 1


def test_statistics_empty(db):
    stats = db.get_statistics()

    assert stats.total == 0
    assert stats.avg_cvss == 0
    assert stats.by_severity == {}
    assert stats.with_exploits == 0
    assert stats.critical_count == 0


def test_recommendation_crud(db):
    rec = SecurityRecommendation(
        test_id="KRNL-1000",
        category="kernel",
        severity="HIGH",
        status="open",
    )
    rid = db.add_security_recommendation(rec)

    assert rid == 1
    recs = db.get_security_recommendations()
    assert len(recs) == 1
    assert recs[0].test_id == "KRNL-1000"

    db.add_security_recommendation(
        SecurityRecommendation(
            test_id="KRNL-2000",
            category="selinux",
            severity="LOW",
            status="fixed",
        )
    )

    assert len(db.get_security_recommendations(category="selinux")) == 1
    assert len(db.get_security_recommendations(status="fixed")) == 1
    assert len(db.get_security_recommendations(limit=1, offset=1)) == 1


def test_recommendations_bulk_with_error(db):
    good = SecurityRecommendation(
        test_id="KRNL-3000", category="kernel", severity="MEDIUM", status="open"
    )

    class _Broken:
        test_id = "KRNL-BAD"

        def __setattr__(self, name, value):
            if name == "id":
                raise AttributeError("cannot set id")
            super().__setattr__(name, value)

    inserted = db.bulk_insert_recommendations([good, _Broken()])

    assert inserted == 1


def test_recommendations_stats(db):
    db.add_security_recommendation(
        SecurityRecommendation(
            test_id="KRNL-1000", category="kernel", severity="HIGH", status="open"
        )
    )
    db.add_security_recommendation(
        SecurityRecommendation(
            test_id="KRNL-2000", category=None, severity=None, status=None
        )
    )

    stats = db.get_recommendations_stats()

    assert stats.total == 2
    assert stats.by_category["kernel"] == 1
    assert stats.by_status["open"] == 1
    assert stats.by_severity["HIGH"] == 1


def test_host_add_sets_timestamps(db):
    host = HostInfo(hostname="h1", kernel_version="6.8.0", captured_at=None)
    hid = db.add_host_info(host)

    got = db.get_host_info(hid)

    assert got is not None
    assert got.captured_at is not None
    assert got.created_at is not None
    assert got.updated_at is not None


def test_host_add_keeps_existing_timestamps(db):
    when = datetime(2023, 5, 1, 8, 0, 0, tzinfo=UTC)
    host = HostInfo(
        hostname="h1",
        kernel_version="6.8.0",
        captured_at=when,
        created_at=when,
    )
    hid = db.add_host_info(host)

    got = db.get_host_info(hid)

    assert got is not None
    assert got.captured_at == when
    assert got.created_at == when


def test_host_info_missing_with_entries(db):
    db.add_host_info(HostInfo(hostname="h1", kernel_version="6.8.0"))

    assert db.get_host_info(424242) is None


def test_latest_host_info_empty_returns_none(db):
    assert db.get_latest_host_info() is None


def test_bulk_insert_skips_bad_rows(db):
    inserted = db.bulk_insert(
        [
            _base_vuln(),
            {"cvss_v3_score": 7.0},
            Vulnerability(cve_id="CVE-2024-0002", cvss_v3_score=6.0),
        ]
    )

    assert inserted == 2
