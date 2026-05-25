import pytest

from db_pr import SimpleThreatDB


@pytest.fixture
def db():
    database = SimpleThreatDB()
    yield database
    database.close()


def test_upsert_vulnerability(db):
    vid = db.upsert_vulnerability({
        "cve_id": "CVE-2024-1234",
        "description": "Critical RCE vulnerability",
        "published_date": "2024-01-15",
        "cvss_v3_score": 9.8,
        "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL",
        "cwe_ids": ["CWE-89", "CWE-79"],
        "in_cisa_kev": True,
        "has_exploit": True,
        "exploit_count": 2,
        "github_refs": 3,
        "sources": ["NIST_NVD", "CISA_KEV", "OSV"],
    })

    assert vid is not None


def test_add_affected_product_internal_id(db):
    vid = db.upsert_vulnerability({
        "cve_id": "CVE-2024-1234",
        "severity": "CRITICAL",
        "cvss_v3_score": 9.8,
    })

    db.add_affected_product(vid, {
        "vendor": "Apache",
        "product": "Struts",
        "version": "2.5.x",
    })

    full = db.get_vulnerability_with_details("CVE-2024-1234")

    assert len(full["affected_products"]) == 1


def test_public_api_exploit(db):
    db.upsert_vulnerability({
        "cve_id": "CVE-2024-1234",
        "severity": "CRITICAL",
        "cvss_v3_score": 9.8,
    })

    db.add_exploit("CVE-2024-1234", {
        "exploit_type": "POC",
        "source": "GitHub",
        "url": "https://github.com/user/exploit",
        "verified": True,
    })

    full = db.get_vulnerability_with_details("CVE-2024-1234")

    assert len(full["exploits"]) == 1
    assert full["exploits"][0]["url"] == "https://github.com/user/exploit"


def test_add_cisa_kev(db):
    db.upsert_vulnerability({
        "cve_id": "CVE-2024-1234",
        "severity": "CRITICAL",
        "cvss_v3_score": 9.8,
    })

    db.add_cisa_kev("CVE-2024-1234", {
        "date_added": "2024-01-20",
        "required_action": "Apply updates",
        "known_ransomware": True,
    })

    full = db.get_vulnerability_with_details("CVE-2024-1234")

    assert full["cisa_kev"] is not None
    assert full["in_cisa_kev"] is True


def test_add_sandbox_run(db):
    db.upsert_vulnerability({
        "cve_id": "CVE-2024-1234",
        "severity": "CRITICAL",
        "cvss_v3_score": 9.8,
    })

    db.add_sandbox_run("CVE-2024-1234", {
        "run_timestamp": "2024-01-21T10:30:00",
        "sandbox_platform": "virtme-ng",
        "exploit_file_hash": "a1b2c3d4e5f6...",
        "execution_success": True,
        "exit_code": 0,
        "stdout": "Exploit executed successfully\nRoot shell obtained\n",
        "stderr": "Warning: deprecated syscall\n",
        "stdin": "./xpl\n",
        "open_processes": ["/bin/sh", "/bin/nc", "python3"],
        "open_files": ["/tmp/exploit", "/etc/passwd"],
        "notes": "Confirmed RCE",
    })

    runs = db.get_sandbox_runs("CVE-2024-1234")

    assert len(runs) == 1
    assert runs[0]["sandbox_platform"] == "virtme-ng"


def test_critical_and_stats(db):
    db.upsert_vulnerability({
        "cve_id": "CVE-2024-1234",
        "severity": "CRITICAL",
        "cvss_v3_score": 9.8,
    })

    db.upsert_vulnerability({
        "cve_id": "CVE-2024-0002",
        "severity": "LOW",
        "cvss_v3_score": 3.1,
    })

    critical = db.get_critical(limit=10)
    stats = db.get_statistics()

    assert len(critical) >= 1
    assert stats["total"] >= 2


def test_context_manager():
    with SimpleThreatDB() as db:
        db.upsert_vulnerability({
            "cve_id": "CVE-2024-9999",
            "cvss_v3_score": 5.0,
        })