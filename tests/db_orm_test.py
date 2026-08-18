from datetime import UTC, datetime

import pytest

from db.db_orm import ThreatIntelligenceORM
from schemas import (
    HostEnvironmentVariable,
    HostGroup,
    HostInfoData,
    HostKernelHardening,
    HostKernelModule,
    HostUser,
)


@pytest.fixture
def db(tmp_path):
    db_path = tmp_path / "ti_test.db"
    database = ThreatIntelligenceORM(db_url=f"sqlite:///{db_path}")
    yield database
    database.close()


def _sample_host(hostname: str = "sample", captured_at: datetime | None = None):
    return HostInfoData(
        hostname=hostname,
        kernel_version="6.8.0",
        captured_at=captured_at or datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC),
        environment_variables=[HostEnvironmentVariable(name="PATH", value="/usr/bin")],
        kernel_modules=[HostKernelModule(module_name="ext4", size=4096)],
        kernel_hardening=[HostKernelHardening(test_id="KRNL-6000", status="ok")],
        users=[HostUser(username="bob", uid=1000, gid=1000)],
        groups=[HostGroup(group_name="admin", gid=1002, members=["bob", "alice"])],
    )


def test_upsert_vulnerability(db):
    vuln = db.upsert_vulnerability(
        {
            "cve_id": "CVE-2024-5678",
            "description": "Critical SQL injection vulnerability",
            "published_date": datetime(2024, 1, 15, tzinfo=UTC),
            "cvss_v3_score": 9.8,
            "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "severity": "CRITICAL",
            "cwe_ids": ["CWE-89"],
            "sources": ["NIST_NVD", "OSV"],
        }
    )

    assert vuln.cve_id == "CVE-2024-5678"
    assert vuln.id is not None


def test_add_affected_product(db):
    db.upsert_vulnerability(
        {
            "cve_id": "CVE-2024-5678",
            "cvss_v3_score": 9.8,
            "severity": "CRITICAL",
        }
    )

    db.add_affected_product(
        "CVE-2024-5678",
        {
            "vendor": "Example Corp",
            "product": "Framework",
            "version": "1.2.3",
            "package_ecosystem": "rpm",
            "package_name": "example-framework",
        },
    )

    full = db.get_vulnerability_with_details("CVE-2024-5678")

    assert len(full["affected_products"]) == 1


def test_add_exploit(db):
    db.upsert_vulnerability(
        {
            "cve_id": "CVE-2024-5678",
            "cvss_v3_score": 9.8,
            "severity": "CRITICAL",
        }
    )

    db.add_exploit(
        "CVE-2024-5678",
        {
            "exploit_type": "POC",
            "source": "GitHub",
            "url": "https://github.com/user/cve-2024-5678-poc",
            "verified": True,
        },
    )

    full = db.get_vulnerability_with_details("CVE-2024-5678")

    assert len(full["exploits"]) == 1
    assert full["exploits"][0]["url"] == "https://github.com/user/cve-2024-5678-poc"


def test_add_reference(db):
    db.upsert_vulnerability(
        {
            "cve_id": "CVE-2024-5678",
            "cvss_v3_score": 9.8,
            "severity": "CRITICAL",
        }
    )

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
    db.upsert_vulnerability(
        {
            "cve_id": "CVE-2024-5678",
            "cvss_v3_score": 9.8,
            "severity": "CRITICAL",
        }
    )

    db.add_cisa_kev(
        "CVE-2024-5678",
        {
            "date_added": datetime(2024, 1, 20, tzinfo=UTC),
            "required_action": "Apply updates immediately",
            "known_ransomware": True,
            "vendor_project": "Example Corp",
            "product": "Web Framework",
        },
    )

    full = db.get_vulnerability_with_details("CVE-2024-5678")

    assert full["cisa_kev"] is not None
    assert full["in_cisa_kev"] is True


def test_add_sandbox_run(db):
    db.upsert_vulnerability(
        {
            "cve_id": "CVE-2024-5678",
            "cvss_v3_score": 9.8,
            "severity": "CRITICAL",
        }
    )

    s_hash = "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890"

    db.add_sandbox_run(
        "CVE-2024-5678",
        {
            "run_timestamp": datetime(2024, 1, 21, 10, 30, tzinfo=UTC),
            "sandbox_platform": "virtme-ng",
            "exploit_file_hash": s_hash,
            "execution_success": True,
            "exit_code": 0,
            "stdout": "Exploit started...",
            "stderr": "Warning",
            "stdin": "./xpl\n",
            "open_processes": ["/bin/bash", "/bin/nc"],
            "open_files": ["/opt/xpl", "/etc/passwd"],
            "notes": "Confirmed LPE",
        },
    )

    runs = db.get_sandbox_runs("CVE-2024-5678")

    assert len(runs) == 1
    assert runs[0]["sandbox_platform"] == "virtme-ng"


def test_full_details(db):
    db.upsert_vulnerability(
        {
            "cve_id": "CVE-2024-5678",
            "cvss_v3_score": 9.8,
            "severity": "CRITICAL",
        }
    )

    db.add_exploit(
        "CVE-2024-5678",
        {
            "exploit_type": "POC",
        },
    )

    db.add_cisa_kev(
        "CVE-2024-5678",
        {
            "known_ransomware": True,
        },
    )

    db.add_reference(
        "CVE-2024-5678",
        url="https://example.com/advisory",
        ref_type="ADVISORY",
        source="NVD",
    )

    db.add_sandbox_run(
        "CVE-2024-5678",
        {
            "sandbox_platform": "virtme-ng",
        },
    )

    full = db.get_vulnerability_with_details("CVE-2024-5678")

    assert len(full["exploits"]) == 1
    assert len(full["references"]) == 1
    assert len(full["sandbox_runs"]) == 1
    assert full["cisa_kev"] is not None


def test_statistics_and_filters(db):
    db.upsert_vulnerability(
        {
            "cve_id": "CVE-2024-5678",
            "cvss_v3_score": 9.8,
            "severity": "CRITICAL",
        }
    )

    db.upsert_vulnerability(
        {
            "cve_id": "CVE-2024-0002",
            "cvss_v3_score": 3.1,
            "severity": "LOW",
        }
    )

    stats = db.get_statistics()

    assert stats["total"] >= 2

    critical = db.get_critical(limit=10)
    assert len(critical) >= 1


def test_context_manager():
    with ThreatIntelligenceORM("sqlite:///ti_test.db") as db:
        db.upsert_vulnerability(
            {
                "cve_id": "CVE-2024-9999",
                "cvss_v3_score": 5.0,
            }
        )


def test_add_host_info_and_children(db):
    hid = db.add_host_info(_sample_host()).id

    got = db.get_host_info(hid)

    assert got is not None
    assert got.hostname == "sample"
    assert got.kernel_version == "6.8.0"
    assert got.environment_variables[0].name == "PATH"
    assert got.environment_variables[0].value == "/usr/bin"
    assert got.kernel_modules[0].module_name == "ext4"
    assert got.kernel_modules[0].size == 4096
    assert got.kernel_hardening[0].test_id == "KRNL-6000"
    assert got.kernel_hardening[0].status == "ok"
    assert got.users[0].username == "bob"
    assert got.users[0].uid == 1000
    assert got.groups[0].group_name == "admin"
    assert set(got.groups[0].members) == {"bob", "alice"}


def test_host_info_missing_returns_none(db):
    assert db.get_host_info(424242) is None


def test_latest_host_info_ordering(db):
    db.add_host_info(_sample_host("older", datetime(2023, 1, 1, 8, 0, 0, tzinfo=UTC)))
    db.add_host_info(_sample_host("newer", datetime(2025, 1, 1, 8, 0, 0, tzinfo=UTC)))

    latest = db.get_latest_host_info()

    assert latest is not None
    assert latest.hostname == "newer"


def test_host_infos_header_only(db):
    db.add_host_info(_sample_host())

    headers = db.get_host_infos()

    assert len(headers) == 1
    assert headers[0].hostname == "sample"
    assert headers[0].groups == []
    assert headers[0].users == []


def test_host_infos_pagination(db):
    for i in range(3):
        db.add_host_info(_sample_host(f"host-{i}", datetime(2024, 1, i + 1, tzinfo=UTC)))

    page = db.get_host_infos(limit=2, offset=0)

    assert [h.hostname for h in page] == ["host-2", "host-1"]
