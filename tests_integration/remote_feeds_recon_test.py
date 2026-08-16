"""
integration tests for ReconFeeds with mocked HTTP backends.
Network calls are stubbed via monkeypatched httpx.get/httpx.post
"""

import asyncio
import json
from datetime import UTC, datetime

import httpx
import pytest

from config import (
    CISA_KEV_URL,
    CVEORG_BASE_URL,
    GITHUB_API_URL,
    NIST_API_URL,
    NIST_CVE_DETAILS_API_URL,
    OSV_API_URL,
)
from recon.parse_recon_reports import ParseReports
from recon.remote_feeds_recon import ReconFeeds


class _FakeResponse:
    def __init__(self, payload=None, content=b"", status_code=200, json_error=None):
        self._payload = payload
        self.content = content
        self.status_code = status_code
        self._json_error = json_error
        self.request = httpx.Request("GET", "http://fake")

    def json(self):
        if self._json_error is not None:
            raise self._json_error
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                f"HTTP {self.status_code}", request=self.request, response=self
            )


class _FakeHTTP:
    """route-based httpx stub: route(url[, json]) sets a canned response.
    json optionally restricts the route to a matching request body, which
    is used to simulate OSV pagination where several POSTs share one URL.
    """

    def __init__(self):
        self.routes = []
        self.calls = []

    def route(
        self,
        url,
        payload=None,
        exception=None,
        content=b"",
        status_code=200,
        json_error=None,
        json=None,
        times=None,
    ):
        self.routes.append(
            {
                "url": url,
                "json": json,
                "payload": payload,
                "exception": exception,
                "content": content,
                "status_code": status_code,
                "json_error": json_error,
                "times": times,
            }
        )

    def __call__(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        for route in self.routes:
            if not url.startswith(route["url"]):
                continue
            if route["json"] is not None and route["json"] != kwargs.get("json"):
                continue
            if route["times"] is not None:
                if route["times"] <= 0:
                    continue
                route["times"] -= 1
            if route["exception"] is not None:
                raise route["exception"]
            return _FakeResponse(
                payload=route["payload"],
                content=route["content"],
                status_code=route["status_code"],
                json_error=route["json_error"],
            )
        return _FakeResponse(payload=None)


class _FakeClient:
    """fake httpx.AsyncClient used by ReconFeeds, routing to a shared _FakeHTTP"""

    def __init__(self, http, *args, **kwargs):
        self._http = http

    async def get(self, url, **kwargs):
        return self._http("GET", url, **kwargs)

    async def post(self, url, **kwargs):
        return self._http("POST", url, **kwargs)

    async def aclose(self):
        return None


@pytest.fixture
def fake_http(monkeypatch):
    http = _FakeHTTP()

    def make_client(*args, **kwargs):
        return _FakeClient(http)

    monkeypatch.setattr("recon.remote_feeds_recon.httpx.AsyncClient", make_client)
    return http


@pytest.fixture(autouse=True)
def _no_nvd_gate(monkeypatch):
    """zero the NVD min-interval so rate-limit tests are not slowed by sleeps"""
    monkeypatch.setattr("recon.remote_feeds_recon._NVD_MIN_INTERVAL", 0.0)


def _run(coro):
    """run a single ReconFeeds coroutine in a fresh event loop (pytest is sync)"""
    return asyncio.run(coro)


@pytest.fixture
def kev_path(tmp_path, monkeypatch):
    path = tmp_path / "kev.json"
    monkeypatch.setattr("recon.remote_feeds_recon.CISA_KEV_PATH", str(path))
    return path


@pytest.fixture
def rf():
    return ReconFeeds()

def _cve_org_payload(cve_id="CVE-2024-1086", metric_key="cvssV3_1", base_score=7.8):
    """CVE JSON 5.x shape returned by cveawg.mitre.org"""
    metric = {
        "format": "CVSS",
        "cvssV3_1": {
            "version": "3.1",
            "vectorString": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            "baseScore": 7.8,
            "baseSeverity": "HIGH",
        },
        "cvssV2_0": {
            "version": "2.0",
            "vectorString": "AV:L/AC:L/Au:N/C:C/I:C/A:C",
            "baseScore": 7.2,
            "baseSeverity": "HIGH",
        },
    }
    if metric_key:
        metric = {"format": "CVSS", metric_key: metric[metric_key]}

    return {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.1",
        "cveMetadata": {"cveId": cve_id, "state": "PUBLISHED"},
        "containers": {
            "cna": {
                "providerMetadata": {"orgId": "mitre"},
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Use-after-free in nftables leading to privilege escalation.",
                    }
                ],
                "metrics": [metric],
                "problemTypes": [
                    {"descriptions": [{"lang": "en", "description": "CWE-416"}]}
                ],
                "references": [{"url": "https://example.com/advisory"}],
            }
        },
    }


def _cve_org_payload_no_metrics(cve_id="CVE-2024-1086"):
    return {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.1",
        "cveMetadata": {"cveId": cve_id, "state": "PUBLISHED"},
        "containers": {
            "cna": {
                "descriptions": [
                    {"lang": "en", "value": "No CVSS data yet for this CVE."}
                ]
            }
        },
    }


def _nist_raw_payload(cve_id="CVE-2024-1086", published="2024-01-31T13:15:00.000"):
    """nist NVD CVE API 2.0 shape"""
    return {
        "resultsPerPage": 1,
        "totalResults": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "sourceIdentifier": "cve@mitre.org",
                    "published": published,
                    "lastModified": "2024-02-01T00:00:00.000",
                    "vulnStatus": "Analyzed",
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": "nftables use-after-free leads to privilege escalation.",
                        }
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "source": "nvd@nist.gov",
                                "type": "Primary",
                                "cvssData": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                                    "baseScore": 7.8,
                                    "baseSeverity": "HIGH",
                                },
                            }
                        ]
                    },
                    "weaknesses": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "description": [{"lang": "en", "value": "CWE-416"}],
                        }
                    ],
                    "references": [{"url": "https://example.com/ref"}],
                    "affected": [
                        {
                            "vendor": "linux",
                            "product": "linux_kernel",
                            "versions": [
                                {
                                    "version": "5.15",
                                    "status": "affected",
                                    "lessThan": "5.15.1",
                                }
                            ],
                        }
                    ],
                }
            }
        ],
    }


def _kev_catalog():
    return {
        "title": "CISA Catalog",
        "catalogVersion": "2024.01.01",
        "vulnerabilities": [
            {
                "cveID": "CVE-2022-0492",
                "vendorProject": "Linux",
                "product": "Linux Kernel",
                "shortDescription": "cgroup release_agent escape",
                "knownRansomwareCampaignUse": "Known",
            },
            {
                "cveID": "CVE-2021-4034",
                "vendorProject": "Red Hat",
                "product": "Polkit",
                "shortDescription": "pkexec LPE",
            },
            {
                "cveID": "CVE-2020-14386",
                "vendorProject": "Linux",
                "product": "Kernel",
                "shortDescription": "af_packet out-of-bounds",
            },
            {
                "cveID": "CVE-2023-1234",
                "vendorProject": "Some Co",
                "product": "SomeApp",
                "shortDescription": "unrelated",
            },
        ],
    }


def _github_payload():
    return {
        "items": [
            {
                "name": "cve-2024-1086-poc",
                "full_name": "user/cve-2024-1086-poc",
                "description": "PoC for CVE-2024-1086",
                "stargazers_count": 42,
                "language": "C",
                "html_url": "https://github.com/user/cve-2024-1086-poc",
            },
            {
                "name": "exploit",
                "full_name": "user/exploit",
                "description": "no cve mentioned",
                "stargazers_count": 5,
                "language": "Python",
                "html_url": "https://github.com/user/exploit",
            },
            {
                "name": "other",
                "full_name": "user/other",
                "description": "CVE-2024-1086 only in description",
                "stargazers_count": 1,
                "language": "C",
                "html_url": "https://github.com/user/other",
            },
        ]
    }


def _osv_payload():
    return {
        "vulns": [
            {
                "id": "CVE-2024-1086",
                "summary": "nf_tables: use-after-free",
                "details": "long details",
                "references": [{"type": "ADVISORY", "url": "https://example.com"}],
                "database_specific": {"severity": "HIGH"},
            },
            {
                "id": "CVE-2024-0001",
                "summary": "some other kernel bug",
                "references": [],
            },
        ]
    }


def _osv_kernel_payload():
    """
    OSV response shape for a vulnerable longterm kernel, matching
    the schema OSV uses for the "Kernel" package in the "Linux" ecosystem
    """
    return {
        "vulns": [
            {
                "id": "CVE-2024-1086",
                "summary": "nf_tables: use-after-free",
                "details": "A use-after-free in nf_tables.",
                "aliases": ["CVE-2024-1086"],
                "references": [{"type": "ADVISORY", "url": "https://example.com"}],
                "affected": [
                    {
                        "package": {"name": "Kernel", "ecosystem": "Linux"},
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [
                                    {"introduced": "0"},
                                    {"fixed": "6.1.76"},
                                ],
                            }
                        ],
                    }
                ],
            },
            {
                "id": "CVE-2024-50000",
                "summary": "netfilter race condition",
                "aliases": ["CVE-2024-50000"],
                "references": [],
                "affected": [
                    {
                        "package": {"name": "Kernel", "ecosystem": "Linux"},
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [
                                    {"introduced": "2.6.16"},
                                    {"fixed": "6.6.66"},
                                ],
                            }
                        ],
                    }
                ],
            },
        ]
    }

@pytest.mark.integration
def test_get_kev_downloads_catalog(fake_http, kev_path, rf):
    fake_http.route(CISA_KEV_URL, content=b'{"hello": 1}')

    _run(rf.get_kev())

    assert kev_path.read_bytes() == b'{"hello": 1}'
    assert fake_http.calls[0][0] == "GET"
    assert fake_http.calls[0][1] == CISA_KEV_URL


@pytest.mark.integration
def test_get_kev_http_error_raises(fake_http, kev_path, rf):
    fake_http.route(CISA_KEV_URL, status_code=503, content=b"unavailable")

    with pytest.raises(httpx.HTTPStatusError):
        _run(rf.get_kev())


@pytest.mark.integration
def test_load_kev_filters_kernel_products(kev_path, rf):
    kev_path.write_text(json.dumps(_kev_catalog()), encoding="utf-8")

    _run(rf.load_kev())

    cve_ids = [item["cveID"] for item in rf.kev_kern_vuln]
    assert "CVE-2022-0492" in cve_ids
    assert "CVE-2020-14386" in cve_ids
    assert "CVE-2021-4034" not in cve_ids
    assert "CVE-2023-1234" not in cve_ids


@pytest.mark.integration
def test_load_kev_list_format(kev_path, rf):
    kev_path.write_text(
        json.dumps(
            [
                {
                    "cveID": "CVE-2022-0492",
                    "vendorProject": "Linux",
                    "product": "Linux Kernel",
                },
                {
                    "cveID": "CVE-2023-0001",
                    "vendorProject": "Other",
                    "product": "app",
                },
            ]
        ),
        encoding="utf-8",
    )

    _run(rf.load_kev())

    assert [item["cveID"] for item in rf.kev_kern_vuln] == ["CVE-2022-0492"]


@pytest.mark.integration
def test_load_kev_missing_file_downloads(fake_http, kev_path, rf):
    import json

    fake_http.route(CISA_KEV_URL, content=json.dumps(_kev_catalog()).encode())
    _run(rf.load_kev())

    assert kev_path.exists()
    assert any(item["cveID"] == "CVE-2022-0492" for item in rf.kev_kern_vuln)


@pytest.mark.integration
def test_load_kev_unexpected_format(kev_path, rf):
    kev_path.write_text('"just a string"', encoding="utf-8")
    _run(rf.load_kev())

    assert rf.kev_kern_vuln == []


def _kev_catalog_with_dates():
    return {
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-31431",
                "vendorProject": "Linux",
                "product": "Kernel",
                "dateAdded": "2026-05-01",
            },
            {
                "cveID": "CVE-2025-38352",
                "vendorProject": "Linux",
                "product": "Kernel",
                "dateAdded": "2025-09-04",
            },
            {
                "cveID": "CVE-2024-53197",
                "vendorProject": "Linux",
                "product": "Kernel",
                "dateAdded": "2025-04-09",
            },
            {
                "cveID": "CVE-2022-0492",
                "vendorProject": "Linux",
                "product": "Linux Kernel",
                "dateAdded": "2022-03-02",
            },
        ]
    }


@pytest.mark.integration
def test_load_kev_no_build_date_keeps_all(kev_path, rf):
    kev_path.write_text(json.dumps(_kev_catalog_with_dates()), encoding="utf-8")
    _run(rf.load_kev())

    assert {item["cveID"] for item in rf.kev_kern_vuln} == {
        "CVE-2026-31431",
        "CVE-2025-38352",
        "CVE-2024-53197",
        "CVE-2022-0492",
    }


@pytest.mark.integration
def test_load_kev_build_date_filters_later_added(kev_path, rf):
    kev_path.write_text(json.dumps(_kev_catalog_with_dates()), encoding="utf-8")
    build_date = int(datetime(2026, 4, 22, tzinfo=UTC).timestamp())
    _run(rf.load_kev(build_date))

    cve_ids = [item["cveID"] for item in rf.kev_kern_vuln]
    assert "CVE-2026-31431" in cve_ids
    assert "CVE-2025-38352" not in cve_ids
    assert "CVE-2024-53197" not in cve_ids
    assert "CVE-2022-0492" not in cve_ids


@pytest.mark.integration
def test_load_kev_build_date_later_than_all(kev_path, rf):
    kev_path.write_text(json.dumps(_kev_catalog_with_dates()), encoding="utf-8")
    build_date = int(datetime(2027, 1, 1, tzinfo=UTC).timestamp())
    _run(rf.load_kev(build_date))

    assert rf.kev_kern_vuln == []

@pytest.mark.integration
def test_github_search_parses_repos(fake_http, rf):
    url = GITHUB_API_URL.format(q="cve 6.1.0")
    fake_http.route(url, payload=_github_payload())

    results = _run(rf.github_search("6.1.0"))

    assert len(results) == 2
    first = results[0]
    assert first.cve_id == "CVE-2024-1086"
    assert first.repo_name == "user/cve-2024-1086-poc"
    assert first.stars == 42
    assert first.language == "C"
    assert first.repo_url == "https://github.com/user/cve-2024-1086-poc"


@pytest.mark.integration
def test_github_search_dedup_same_repo(fake_http, rf):
    url = GITHUB_API_URL.format(q="cve 6.1.0")
    item = {
        "name": "x",
        "full_name": "user/x",
        "description": "CVE-2024-1086 and CVE-2024-1086",
        "stargazers_count": 1,
        "language": "C",
        "html_url": "https://github.com/user/x",
    }
    fake_http.route(url, payload={"items": [item, dict(item)]})

    results = _run(rf.github_search("6.1.0"))

    assert len(results) == 1


@pytest.mark.integration
def test_github_search_empty_items(fake_http, rf):
    url = GITHUB_API_URL.format(q="cve 6.1.0")
    fake_http.route(url, payload={"items": []})

    assert _run(rf.github_search("6.1.0")) == []


@pytest.mark.integration
def test_github_search_skips_no_cve(fake_http, rf):
    url = GITHUB_API_URL.format(q="cve 6.1.0")
    fake_http.route(
        url,
        payload={
            "items": [
                {
                    "name": "no-cve",
                    "full_name": "user/no-cve",
                    "description": "nothing here",
                    "stargazers_count": 1,
                    "language": "C",
                    "html_url": "https://github.com/user/no-cve",
                }
            ]
        },
    )

    assert _run(rf.github_search("6.1.0")) == []

@pytest.mark.integration
def test_nist_search_parses_cvss_v31(fake_http, rf):
    url = NIST_API_URL.format(version="6.1.0")
    fake_http.route(url, payload=_nist_raw_payload())

    findings = _run(rf.nist_search("6.1.0", None))

    assert len(findings) == 1
    f = findings[0]
    assert f.cve_id == "CVE-2024-1086"
    assert f.source == "NIST"
    assert f.cvss_score == 7.8
    assert f.severity == "HIGH"
    assert "use-after-free" in f.description


@pytest.mark.integration
def test_nist_search_no_metrics(fake_http, rf):
    url = NIST_API_URL.format(version="6.1.0")
    payload = _nist_raw_payload()
    del payload["vulnerabilities"][0]["cve"]["metrics"]
    fake_http.route(url, payload=payload)

    findings = _run(rf.nist_search("6.1.0", None))

    assert len(findings) == 1
    assert findings[0].cvss_score is None


@pytest.mark.integration
def test_nist_search_date_filter(fake_http, rf):
    url = NIST_API_URL.format(version="6.1.0")
    payload = {
        "vulnerabilities": [
            {"cve": _nist_raw_payload()["vulnerabilities"][0]["cve"]},
            {
                "cve": {
                    **_nist_raw_payload()["vulnerabilities"][0]["cve"],
                    "id": "CVE-2023-1234",
                    "published": "2023-06-01T00:00:00.000",
                }
            },
        ]
    }
    fake_http.route(url, payload=payload)
    min_ts = int(datetime(2024, 1, 1, tzinfo=UTC).timestamp())

    findings = _run(rf.nist_search("6.1.0", min_ts))

    assert [f.cve_id for f in findings] == ["CVE-2024-1086"]


@pytest.mark.integration
def test_nist_search_http_error_returns_empty(fake_http, rf):
    url = NIST_API_URL.format(version="6.1.0")
    fake_http.route(url, exception=httpx.ConnectError("timeout"))

    assert _run(rf.nist_search("6.1.0", None)) == []


@pytest.mark.integration
def test_nist_search_json_decode_error_returns_empty(fake_http, rf):
    url = NIST_API_URL.format(version="6.1.0")
    fake_http.route(
        url,
        payload={"not": "json"},
        json_error=json.JSONDecodeError("bad", "doc", 0),
    )

    assert _run(rf.nist_search("6.1.0", None)) == []


@pytest.mark.integration
def test_nist_search_malformed_structure_returns_empty(fake_http, rf):
    url = NIST_API_URL.format(version="6.1.0")
    fake_http.route(url, payload={"vulnerabilities": "not-a-list"})

    assert _run(rf.nist_search("6.1.0", None)) == []


@pytest.mark.integration
def test_nist_search_retries_once_on_429(fake_http, rf):
    """a 429 with Retry-After backoff must retry and still return findings"""
    url = NIST_API_URL.format(version="6.1.0")
    fake_http.route(url, payload={}, status_code=429, times=1)
    fake_http.route(url, payload=_nist_raw_payload())

    findings = _run(rf.nist_search("6.1.0", None))

    assert len(findings) == 1
    assert findings[0].cve_id == "CVE-2024-1086"
    # exactly one rate-limited call, then the successful one
    assert len([c for c in fake_http.calls if c[0] == "GET"]) == 2


@pytest.mark.integration
def test_nist_search_gives_up_after_repeated_429(fake_http, rf):
    """persistent rate-limiting must stop retrying and return partial []"""
    url = NIST_API_URL.format(version="6.1.0")
    fake_http.route(url, payload={}, status_code=429)

    assert _run(rf.nist_search("6.1.0", None)) == []
    # _NVD_MAX_RETRIES backoffs + the initial attempt
    assert len([c for c in fake_http.calls if c[0] == "GET"]) == 4


@pytest.mark.integration
def test_osv_search_parses_vulns(fake_http, rf):
    fake_http.route(OSV_API_URL, payload=_osv_payload())

    findings = _run(rf.osv_search("6.1.0"))

    assert len(findings) == 2
    first = findings[0]
    assert first.cve_id == "CVE-2024-1086"
    assert first.source == "OSV"
    assert first.description == "nf_tables: use-after-free"
    assert first.references == ["https://example.com"]
    assert first.severity == "HIGH"


@pytest.mark.integration
def test_osv_search_http_error_returns_empty(fake_http, rf):
    fake_http.route(OSV_API_URL, exception=httpx.ConnectError("down"))

    assert _run(rf.osv_search("6.1.0")) == []


@pytest.mark.integration
def test_osv_search_malformed_structure_returns_empty(fake_http, rf):
    fake_http.route(OSV_API_URL, payload={"vulns": "not-a-list"})

    assert _run(rf.osv_search("6.1.0")) == []


@pytest.mark.integration
def test_osv_search_posts_version_payload(fake_http, rf):
    fake_http.route(OSV_API_URL, payload={"vulns": []})

    _run(rf.osv_search("6.1.0"))

    method, url, kwargs = fake_http.calls[0]
    assert method == "POST"
    assert url == OSV_API_URL
    assert kwargs["json"] == {
        "version": "6.1.0",
        "package": {"name": "Kernel", "ecosystem": "Linux"},
    }


@pytest.mark.integration
def test_osv_search_real_vulnerable_versions(fake_http, rf):
    """OSV search try on vulnerable versions like 4.19 / 5.3 longterm kernels"""
    fake_http.route(
        OSV_API_URL,
        json={"version": "4.19.0", "package": {"name": "Kernel", "ecosystem": "Linux"}},
        payload=_osv_kernel_payload(),
    )

    findings = _run(rf.osv_search("4.19.0"))

    assert findings
    assert all(f.cve_id.startswith("CVE-") for f in findings)
    assert all(f.source == "OSV" for f in findings)
    _, _, kwargs = fake_http.calls[0]
    assert kwargs["json"]["version"] == "4.19.0"


@pytest.mark.integration
def test_osv_search_expands_advisory_aliases(fake_http, rf):
    """distro advisory try mapping to several CVEs is expanded"""
    fake_http.route(
        OSV_API_URL,
        payload={
            "vulns": [
                {
                    "id": "MGASA-2026-0312",
                    "summary": "kernel update",
                    "aliases": ["CVE-2026-31431", "CVE-2025-38352"],
                }
            ]
        },
    )

    findings = _run(rf.osv_search("6.6.0"))

    assert sorted(f.cve_id for f in findings) == [
        "CVE-2025-38352",
        "CVE-2026-31431",
    ]
    assert all(f.source == "OSV" for f in findings)


@pytest.mark.integration
def test_osv_search_dedupes_shared_cves(fake_http, rf):
    """if two OSV records referencing the same CVE yield one finding"""
    fake_http.route(
        OSV_API_URL,
        payload={
            "vulns": [
                {
                    "id": "CVE-2024-1086",
                    "summary": "from cve record",
                    "aliases": [],
                },
                {
                    "id": "DSA-5000",
                    "summary": "from debian advisory",
                    "aliases": ["CVE-2024-1086"],
                },
            ]
        },
    )

    findings = _run(rf.osv_search("6.1.0"))

    assert [f.cve_id for f in findings] == ["CVE-2024-1086"]


@pytest.mark.integration
def test_osv_search_follows_pagination(fake_http, rf):
    page1 = {"version": "4.19.0", "package": {"name": "Kernel", "ecosystem": "Linux"}}
    page2 = {**page1, "page_token": "next-token"}
    fake_http.route(
        OSV_API_URL,
        json=page1,
        payload={
            "vulns": [{"id": "CVE-2024-1086", "aliases": []}],
            "next_page_token": "next-token",
        },
    )
    fake_http.route(
        OSV_API_URL,
        json=page2,
        payload={"vulns": [{"id": "CVE-2025-38352", "aliases": []}]},
    )

    findings = _run(rf.osv_search("4.19.0"))

    assert sorted(f.cve_id for f in findings) == [
        "CVE-2024-1086",
        "CVE-2025-38352",
    ]
    posted_bodies = [c[2]["json"] for c in fake_http.calls if c[1] == OSV_API_URL]
    assert page2 in posted_bodies


@pytest.mark.integration
def test_osv_search_enriches_cvss_from_nist(fake_http, rf):
    """OSV records carry no numeric CVSS score; missing data comes from NIST API"""
    fake_http.route(OSV_API_URL, payload=_osv_payload())
    fake_http.route(CVEORG_BASE_URL + "CVE-2024-1086", payload=_cve_org_payload())
    fake_http.route(
        CVEORG_BASE_URL + "CVE-2024-0001", payload=_cve_org_payload("CVE-2024-0001")
    )

    findings = _run(rf.osv_search("6.1.0"))

    assert findings[0].cvss_score == 7.8
    assert findings[0].severity == "HIGH"


@pytest.mark.integration
def test_osv_search_enrichment_keeps_osv_data_on_nist_error(fake_http, rf):
    """if NIST/CVE.org enrichment fails, the OSV finding is still returned"""
    fake_http.route(OSV_API_URL, payload=_osv_payload())
    fake_http.route(
        CVEORG_BASE_URL + "CVE-2024-1086", exception=httpx.ConnectError("down")
    )
    fake_http.route(
        NIST_CVE_DETAILS_API_URL + "CVE-2024-1086",
        exception=httpx.ConnectError("down"),
    )

    findings = _run(rf.osv_search("6.1.0"))

    assert findings[0].cve_id == "CVE-2024-1086"
    assert findings[0].description == "nf_tables: use-after-free"


@pytest.mark.integration
def test_osv_search_retries_transient_read_error(fake_http, rf, monkeypatch):
    """A dropped connection mid-body (httpx.ReadError) must be retried, not
    silently abort the search."""
    monkeypatch.setattr("recon.remote_feeds_recon._OSV_RETRY_BASE_DELAY", 0.0)
    fake_http.route(OSV_API_URL, exception=httpx.ReadError("mid-body drop"), times=1)
    fake_http.route(OSV_API_URL, payload=_osv_payload())

    findings = _run(rf.osv_search("6.1.0"))

    osv_posts = [c for c in fake_http.calls if c[1] == OSV_API_URL]
    assert len(osv_posts) == 2
    assert [f.cve_id for f in findings] == ["CVE-2024-1086", "CVE-2024-0001"]


@pytest.mark.integration
def test_osv_search_gives_up_after_repeated_transport_errors(fake_http, rf, monkeypatch):
    """Persistent transport errors must stop retrying and return []."""
    monkeypatch.setattr("recon.remote_feeds_recon._OSV_RETRY_BASE_DELAY", 0.0)
    from recon import remote_feeds_recon as rfr

    fake_http.route(
        OSV_API_URL,
        exception=httpx.ReadError("down"),
        times=rfr._OSV_RETRIES + 1,
    )

    assert _run(rf.osv_search("6.1.0")) == []
    assert len([c for c in fake_http.calls if c[1] == OSV_API_URL]) == rfr._OSV_RETRIES + 1


@pytest.mark.integration
def test_osv_search_keeps_first_page_when_later_page_transient_fails(
    fake_http, rf, monkeypatch
):
    """If a follow-up page dies with a transient error, the findings already
    collected from earlier pages must survive."""
    monkeypatch.setattr("recon.remote_feeds_recon._OSV_RETRY_BASE_DELAY", 0.0)
    from recon import remote_feeds_recon as rfr

    page1 = {"version": "6.1.0", "package": {"name": "Kernel", "ecosystem": "Linux"}}
    page2 = {**page1, "page_token": "next-token"}
    fake_http.route(
        OSV_API_URL,
        json=page1,
        payload={
            "vulns": [{"id": "CVE-2024-1086", "aliases": []}],
            "next_page_token": "next-token",
        },
    )
    fake_http.route(
        OSV_API_URL,
        json=page2,
        exception=httpx.ReadError("connection reset"),
        times=rfr._OSV_RETRIES + 1,
    )

    findings = _run(rf.osv_search("6.1.0"))

    assert [f.cve_id for f in findings] == ["CVE-2024-1086"]


@pytest.mark.integration
def test_reformat_cve_details_empty():
    assert ParseReports.reformat_cve_details({}) == {}
    assert ParseReports.reformat_cve_details({"vulnerabilities": []}) == {}


@pytest.mark.integration
def test_reformat_cve_details_full():
    reformatted = ParseReports.reformat_cve_details(_nist_raw_payload())

    cna = reformatted["containers"]["cna"]
    assert reformatted["dataType"] == "CVE_RECORD"
    assert cna["descriptions"][0]["value"].startswith("nftables")
    assert cna["metrics"][0]["cvssV3_1"]["baseScore"] == 7.8
    assert cna["problemTypes"][0]["descriptions"][0]["cweId"] == "CWE-416"
    assert cna["references"][0]["url"] == "https://example.com/ref"
    assert cna["affected"][0]["versions"] == [
        {"version": "5.15", "status": "affected", "lessThan": "5.15.1"}
    ]


@pytest.mark.integration
def test_reformat_cve_details_no_vuln_data():
    payload = _nist_raw_payload()
    del payload["vulnerabilities"][0]["cve"]["descriptions"]
    del payload["vulnerabilities"][0]["cve"]["metrics"]

    reformatted = ParseReports.reformat_cve_details(payload)

    cna = reformatted["containers"]["cna"]
    assert cna["descriptions"] == []
    assert cna["metrics"] == []

@pytest.mark.integration
def test_cve_org_details_mitre_primary(fake_http, rf):
    payload = _cve_org_payload()
    fake_http.route(CVEORG_BASE_URL + "CVE-2024-1086", payload=payload)

    data = _run(rf._cve_org_details("CVE-2024-1086"))

    assert data is payload
    assert rf._mitre_available is True


@pytest.mark.integration
def test_cve_org_details_fallback_to_nist(fake_http, rf):
    mitre_url = CVEORG_BASE_URL + "CVE-2024-1086"
    nist_url = NIST_CVE_DETAILS_API_URL + "CVE-2024-1086"
    fake_http.route(mitre_url, exception=httpx.ConnectError("mitre down"))
    fake_http.route(nist_url, payload=_nist_raw_payload())

    data = _run(rf._cve_org_details("CVE-2024-1086"))

    assert data["dataType"] == "CVE_RECORD"
    assert data["containers"]["cna"]["metrics"][0]["cvssV3_1"]["baseScore"] == 7.8
    assert rf._mitre_available is False


@pytest.mark.integration
def test_cve_org_details_uses_nist_after_fallback(fake_http, rf):
    mitre_url = CVEORG_BASE_URL + "CVE-2024-1086"
    nist_url = NIST_CVE_DETAILS_API_URL + "CVE-2024-1086"
    fake_http.route(mitre_url, exception=httpx.ConnectError("down"))
    fake_http.route(nist_url, payload=_nist_raw_payload())

    _run(rf._cve_org_details("CVE-2024-1086"))
    _run(rf._cve_org_details("CVE-2024-1086"))

    mitre_calls = [c for c in fake_http.calls if c[1] == mitre_url]
    nist_calls = [c for c in fake_http.calls if c[1] == nist_url]
    assert len(mitre_calls) == 1
    assert len(nist_calls) == 2


@pytest.mark.integration
def test_cve_org_details_both_fail_raises(fake_http, rf):
    fake_http.route(
        CVEORG_BASE_URL + "CVE-2024-1086", exception=httpx.ConnectError("down")
    )
    fake_http.route(
        NIST_CVE_DETAILS_API_URL + "CVE-2024-1086",
        exception=httpx.ConnectError("nist down"),
    )

    with pytest.raises(httpx.ConnectError):
        _run(rf._cve_org_details("CVE-2024-1086"))

@pytest.mark.integration
def test_get_cve_details_cve_org_format_parses_cvss(fake_http, rf):
    fake_http.route(CVEORG_BASE_URL + "CVE-2024-1086", payload=_cve_org_payload())

    details = _run(rf.get_cve_details("CVE-2024-1086"))

    assert details["description"].startswith("Use-after-free")
    assert details["cvss_v3_score"] == 7.8
    assert details["severity"] == "HIGH"
    assert details["cvss_v3_vector"] == "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    assert details["nist_url"] == CVEORG_BASE_URL + "CVE-2024-1086"
    assert details["raw"]["dataType"] == "CVE_RECORD"


@pytest.mark.integration
def test_get_cve_details_prefers_v3_over_v2(fake_http, rf):
    fake_http.route(CVEORG_BASE_URL + "CVE-2024-1086", payload=_cve_org_payload())

    details = _run(rf.get_cve_details("CVE-2024-1086"))

    assert details["cvss_v3_score"] == 7.8


@pytest.mark.integration
def test_get_cve_details_falls_back_to_v2(fake_http, rf):
    payload = _cve_org_payload(metric_key="cvssV2_0")
    fake_http.route(CVEORG_BASE_URL + "CVE-2024-1086", payload=payload)

    details = _run(rf.get_cve_details("CVE-2024-1086"))

    assert details["cvss_v3_score"] == 7.2


@pytest.mark.integration
def test_get_cve_details_no_metrics(fake_http, rf):
    fake_http.route(
        CVEORG_BASE_URL + "CVE-2024-1086", payload=_cve_org_payload_no_metrics()
    )

    details = _run(rf.get_cve_details("CVE-2024-1086"))

    assert details["cvss_v3_score"] is None
    assert details["severity"] is None
    assert details["description"] == "No CVSS data yet for this CVE."


@pytest.mark.integration
def test_get_cve_details_nist_fallback_pipeline(fake_http, rf):
    fake_http.route(
        CVEORG_BASE_URL + "CVE-2024-1086", exception=httpx.ConnectError("down")
    )
    fake_http.route(
        NIST_CVE_DETAILS_API_URL + "CVE-2024-1086", payload=_nist_raw_payload()
    )

    details = _run(rf.get_cve_details("CVE-2024-1086"))

    assert details["cvss_v3_score"] == 7.8
    assert details["severity"] == "HIGH"
    assert details["description"].startswith("nftables")


@pytest.mark.integration
def test_get_cve_details_error_returns_empty(fake_http, rf):
    fake_http.route(
        CVEORG_BASE_URL + "CVE-2024-1086", exception=httpx.ConnectError("down")
    )
    fake_http.route(
        NIST_CVE_DETAILS_API_URL + "CVE-2024-1086",
        exception=httpx.ConnectError("nist down"),
    )

    assert _run(rf.get_cve_details("CVE-2024-1086")) == {}


@pytest.mark.integration
def test_get_cve_details_malformed_mitre_falls_back_to_nist(fake_http, rf):
    mitre_url = CVEORG_BASE_URL + "CVE-2024-1086"
    nist_url = NIST_CVE_DETAILS_API_URL + "CVE-2024-1086"
    fake_http.route(
        mitre_url,
        payload={"cveMetadata": "bad"},
        json_error=json.JSONDecodeError("bad json", "doc", 0),
    )
    fake_http.route(nist_url, payload=_nist_raw_payload())

    details = _run(rf.get_cve_details("CVE-2024-1086"))

    assert details["cvss_v3_score"] == 7.8
    assert rf._mitre_available is False


@pytest.mark.integration
def test_get_cve_details_many_batches_and_dedups(fake_http, rf):
    fake_http.route(CVEORG_BASE_URL + "CVE-2024-1086", payload=_cve_org_payload())
    fake_http.route(
        CVEORG_BASE_URL + "CVE-2024-0001", payload=_cve_org_payload("CVE-2024-0001")
    )

    details = _run(rf.get_cve_details_many(
        ["CVE-2024-1086", "CVE-2024-0001", "CVE-2024-1086"]
    ))

    assert list(details.keys()) == ["CVE-2024-1086", "CVE-2024-0001"]
    assert details["CVE-2024-1086"]["cvss_v3_score"] == 7.8


@pytest.mark.integration
def test_get_cve_details_many_empty(fake_http, rf):
    assert _run(rf.get_cve_details_many([])) == {}


@pytest.mark.integration
def test_get_cve_details_many_drops_failed(fake_http, rf):
    fake_http.route(
        CVEORG_BASE_URL + "CVE-2024-1086", exception=httpx.ConnectError("down")
    )
    fake_http.route(
        NIST_CVE_DETAILS_API_URL + "CVE-2024-1086",
        exception=httpx.ConnectError("nist down"),
    )
    # once MITRE is down, remaining CVEs fall back to NIST globally
    fake_http.route(
        NIST_CVE_DETAILS_API_URL + "CVE-2024-0001",
        payload=_nist_raw_payload("CVE-2024-0001"),
    )

    details = _run(rf.get_cve_details_many(["CVE-2024-1086", "CVE-2024-0001"]))

    assert list(details.keys()) == ["CVE-2024-0001"]
