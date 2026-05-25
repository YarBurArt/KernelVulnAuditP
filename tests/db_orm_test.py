import pytest
from datetime import datetime

from db_orm import ThreatIntelligenceORM


@pytest.fixture
def db(tmp_path):
    db_path = tmp_path / "ti_test.db"
    database = ThreatIntelligenceORM(db_url=f"sqlite:///{db_path}")
    yield database
    database.close()


def test_upsert_vulnerability(db):
    vuln = db.upsert_vulnerability({
        "cve_id": "CVE-2024-5678",
        "description": "Critical SQL injection vulnerability",
        "published_date": datetime(2024, 1, 15),
        "cvss_v3_score": 9.8,
        "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL",
        "cwe_ids": ["CWE-89"],
        "sources": ["NIST_NVD", "OSV"],
    })

    assert vuln.cve_id == "CVE-2024-5678"
    assert vuln.id is not None


def test_add_affected_product(db):
    db.upsert_vulnerability({
        "cve_id": "CVE-2024-5678",
        "cvss_v3_score": 9.8,
        "severity": "CRITICAL",
    })

    db.add_affected_product("CVE-2024-5678", {
        "vendor": "Example Corp",
        "product": "Framework",
        "version": "1.2.3",
        "package_ecosystem": "rpm",
        "package_name": "example-framework",
    })

    full = db.get_vulnerability_with_details("CVE-2024-5678")

    assert len(full["affected_products"]) == 1


def test_add_exploit(db):
    db.upsert_vulnerability({
        "cve_id": "CVE-2024-5678",
        "cvss_v3_score": 9.8,
        "severity": "CRITICAL",
    })

    db.add_exploit("CVE-2024-5678", {
        "exploit_type": "POC",
        "source": "GitHub",
        "url": "https://github.com/user/cve-2024-5678-poc",
        "verified": True,
    })

    full = db.get_vulnerability_with_details("CVE-2024-5678")

    assert len(full["exploits"]) == 1
    assert full["exploits"][0]["url"] == "https://github.com/user/cve-2024-5678-poc"


def test_add_reference(db):
    db.upsert_vulnerability({
        "cve_id": "CVE-2024-5678",
        "cvss_v3_score": 9.8,
        "severity": "CRITICAL",
    })

    db.add_reference(
        "CVE-2024-5678",
        url="https://nvd.nist.gov/vuln/detail/CVE-2024-5678",
        ref_type="ADVISORY",
        source="NVD",
    )

    full = db.get_vulnerability_with_details("CVE-2024-5678")

    assert len(full["references"]) == 1
    assert full["references"][0]["url"].startswith("https://nvd")


def test_add_cisa_kev(db):
    db.upsert_vulnerability({
        "cve_id": "CVE-2024-5678",
        "cvss_v3_score": 9.8,
        "severity": "CRITICAL",
    })

    db.add_cisa_kev("CVE-2024-5678", {
        "date_added": datetime(2024, 1, 20),
        "required_action": "Apply updates immediately",
        "known_ransomware": True,
        "vendor_project": "Example Corp",
        "product": "Web Framework",
    })

    full = db.get_vulnerability_with_details("CVE-2024-5678")

    assert full["cisa_kev"] is not None
    assert full["in_cisa_kev"] is True


def test_add_sandbox_run(db):
    db.upsert_vulnerability({
        "cve_id": "CVE-2024-5678",
        "cvss_v3_score": 9.8,
        "severity": "CRITICAL",
    })

    s_hash = "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890"

    db.add_sandbox_run("CVE-2024-5678", {
        "run_timestamp": datetime(2024, 1, 21, 10, 30),
        "sandbox_platform": "virtme-ng",
        "exploit_file_hash": s_hash,
        "execution_success": True,
        "exit_code": 0,
        "stdout": "Exploit started...",
        "stderr": "Warning",
        "stdin": "./xpl\n",
        "open_processes": ["/bin/bash", "/bin/nc"],
        "open_files": ["/tmp/xpl", "/etc/passwd"],
        "notes": "Confirmed LPE",
    })

    runs = db.get_sandbox_runs("CVE-2024-5678")

    assert len(runs) == 1
    assert runs[0]["sandbox_platform"] == "virtme-ng"


def test_full_details(db):
    db.upsert_vulnerability({
        "cve_id": "CVE-2024-5678",
        "cvss_v3_score": 9.8,
        "severity": "CRITICAL",
    })

    db.add_exploit("CVE-2024-5678", {
        "exploit_type": "POC",
    })

    db.add_cisa_kev("CVE-2024-5678", {
        "known_ransomware": True,
    })

    db.add_reference(
        "CVE-2024-5678",
        url="https://example.com/advisory",
        ref_type="ADVISORY",
        source="NVD",
    )

    db.add_sandbox_run("CVE-2024-5678", {
        "sandbox_platform": "virtme-ng",
    })

    full = db.get_vulnerability_with_details("CVE-2024-5678")

    assert len(full["exploits"]) == 1
    assert len(full["references"]) == 1
    assert len(full["sandbox_runs"]) == 1
    assert full["cisa_kev"] is not None


def test_statistics_and_filters(db):
    db.upsert_vulnerability({
        "cve_id": "CVE-2024-5678",
        "cvss_v3_score": 9.8,
        "severity": "CRITICAL",
    })

    db.upsert_vulnerability({
        "cve_id": "CVE-2024-0002",
        "cvss_v3_score": 3.1,
        "severity": "LOW",
    })

    stats = db.get_statistics()

    assert stats["total"] >= 2

    critical = db.get_critical(limit=10)
    assert len(critical) >= 1


def test_context_manager():
    with ThreatIntelligenceORM("sqlite:///ti_test.db") as db:
        db.upsert_vulnerability({
            "cve_id": "CVE-2024-9999",
            "cvss_v3_score": 5.0,
        })