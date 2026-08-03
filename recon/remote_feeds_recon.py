import json
import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import httpx

from config import (
    CISA_KEV_PATH,
    CISA_KEV_URL,
    CVEORG_BASE_URL,
    GITHUB_API_URL,
    NIST_API_URL,
    NIST_CVE_DETAILS_API_URL,
    OSV_API_URL,
)
from core import filter_items_by_date
from recon.parse_recon_reports import ParseReports
from schemas import (
    CVEFinding,
    GitHubPoC,
)

logger = logging.getLogger(f"kernel_audit.{__name__}")

# OSV queries paginate after ~1000 results; cap the follow-up pages
_OSV_MAX_PAGES = 10
_DETAILS_WORKERS = 4
_FEEDS_USER_AGENT = "kernelvulnauditp/0.1.1"

# concrete exceptions raised by httpx calls or malformed feed payloads
_FEED_API_ERRORS = (
    httpx.HTTPError,
    ValueError,
    KeyError,
    IndexError,
    TypeError,
    AttributeError,
)


class ReconFeeds:
    """
    get data from cve org and KEV, GitHub search
    using LocalRecon kernel version
    """

    def __init__(self):
        self.kev_kern_vuln = []
        self._mitre_available = True
        self._mitre_lock = threading.Lock()
        self._details_cache: dict[str, dict[str, Any]] = {}
        self._cache_lock = threading.Lock()

        # trying pooled connections
        self._client = httpx.Client(
            http2=True,
            headers={"User-Agent": _FEEDS_USER_AGENT},
            timeout=httpx.Timeout(10.0, connect=5.0),
            follow_redirects=True,
        )
        self.parser = ParseReports()

    def close(self) -> None:
        """close the shared HTTP session and its pooled connections"""
        self._client.close()

    def get_kev(self):
        """download CISA KEV catalog"""
        res = self._client.get(CISA_KEV_URL)
        res.raise_for_status()
        with open(CISA_KEV_PATH, "wb") as f:
            f.write(res.content)
        logger.info("Downloaded KEV catalog: %d bytes", len(res.content))

    def load_kev(self, build_date: int | None = None):
        """load CISA KEV catalog and filter for Kernel products + year"""
        if not os.path.exists(CISA_KEV_PATH):
            logger.info("KEV catalog not found, downloading...")
            self.get_kev()

        with open(CISA_KEV_PATH, "r") as f:
            data = json.load(f)

        # CISA KEV format: {"title": "...", "vulnerabilities": [...]}
        if isinstance(data, dict):
            vulns = data.get("vulnerabilities", [])
        elif isinstance(data, list):
            vulns = data
        else:
            logger.warning("Unexpected KEV format: %s", type(data))
            return

        if build_date is not None:
            vulns = filter_items_by_date(
                vulns, date_field="dateAdded", min_timestamp=build_date
            )

        self.kev_kern_vuln = []
        for vuln in vulns:
            product = vuln.get("product", "")
            vendor = vuln.get("vendorProject", "")
            if (
                product
                and "kernel" in product.lower()
                or vendor
                and "linux" in vendor.lower()
            ):
                self.kev_kern_vuln.append(vuln)

        logger.debug("KEV vulnerabilities: %d", len(self.kev_kern_vuln))

    def github_search(self, kern_version: str) -> list[GitHubPoC]:
        """Search PoC repositories on GitHub"""
        data = self._client.get(
            GITHUB_API_URL.format(q=f"cve {kern_version}")
        ).json()

        pocs = self.parser.parse_github_pocs(data or {})
        logger.debug("github_search found %d PoCs", len(pocs))
        return pocs

    def _cve_org_details(self, cve_id: str) -> dict[str, Any]:
        """get cve details from cve.org MITRE API, if not accessible then NIST v2 API"""
        if self._mitre_available:
            try:
                response = self._client.get(CVEORG_BASE_URL + cve_id)
                response.raise_for_status()
                return response.json()

            except (httpx.HTTPError, ValueError) as exc:
                logger.warning(
                    "MITRE API unavailable, switching to NIST: %s",
                    exc,
                )
                with self._mitre_lock:
                    self._mitre_available = False

        response = self._client.get(NIST_CVE_DETAILS_API_URL + cve_id)
        response.raise_for_status()
        return self.parser.reformat_cve_details(response.json())

    def nist_search(self, kern_r_version, date) -> list[CVEFinding]:
        """Search for vulnerabilities in NIST database"""
        url: str = NIST_API_URL.format(version=kern_r_version)
        try:
            response = self._client.get(url)
            response.raise_for_status()
            data = response.json()
            logger.debug("NIST total=%d", len((data or {}).get("vulnerabilities", [])))
            findings = self.parser.parse_nist_findings(data or {}, date)
            logger.debug("NIST after date filter=%d", len(findings))
            return findings

        except _FEED_API_ERRORS as e:
            logger.warning("NIST search error: %s", str(e))
            return []

    def osv_search(self, kern_r_version) -> list[CVEFinding]:
        """Search for Linux kernel CVEs in OSV, enriching missing data from NIST."""
        payload = {
            "version": kern_r_version,
            "package": {"name": "Kernel", "ecosystem": "Linux"},
        }
        findings: list[CVEFinding] = []
        seen: set[str] = set()
        page_token: str | None = None

        for _ in range(_OSV_MAX_PAGES):
            body = dict(payload)
            if page_token:
                body["page_token"] = page_token
            try:
                response = self._client.post(OSV_API_URL, json=body)
                response.raise_for_status()
                data = response.json()
            except _FEED_API_ERRORS as e:
                logger.warning("OSV search error: %s", str(e))
                break

            for vuln in data.get("vulns", []) or []:
                if not isinstance(vuln, dict):
                    continue
                for cve_id in self.parser.osv_cve_ids(vuln):
                    if cve_id in seen:
                        continue
                    seen.add(cve_id)
                    findings.append(self.parser.build_osv_finding(cve_id, vuln))

            page_token = data.get("next_page_token")
            if not page_token:
                break

        self._enrich_osv_findings(findings)
        return findings

    def _enrich_osv_findings(self, findings: list[CVEFinding]) -> None:
        """batch-fetch CVE metadata concurrently to fill missing OSV data"""
        details_map = self.get_cve_details_many([f.cve_id for f in findings])
        for finding in findings:
            details = details_map.get(finding.cve_id)
            if not details:
                continue
            if not finding.description:
                description = details.get("description")
                if isinstance(description, str):
                    finding.description = description
            if not finding.severity:
                severity = details.get("severity")
                if isinstance(severity, str):
                    finding.severity = severity
            if finding.cvss_score is None:
                score = details.get("cvss_v3_score")
                if isinstance(score, (int, float)):
                    finding.cvss_score = float(score)

    def get_cve_details(self, cve_id: str) -> dict[str, Any]:
        """filter CVE metadata using the configured API for db"""
        with self._cache_lock:
            cached = self._details_cache.get(cve_id)
        if cached is not None:
            return cached

        try:
            data = self._cve_org_details(cve_id)
        except _FEED_API_ERRORS as e:
            logger.warning("%s get_cve_details error: %s", cve_id, str(e))
            return {}
        if not data:
            return {}

        details = self.parser.extract_cve_details(
            data, f"{CVEORG_BASE_URL}{cve_id}"
        )
        logger.info("found %s CVSS score: %s", cve_id, details["cvss_v3_score"])
        logger.debug("found %s details raw data: %s", cve_id, data)

        with self._cache_lock:
            self._details_cache[cve_id] = details
        return details

    def get_cve_details_many(self, cve_ids: list[str]) -> dict[str, dict[str, Any]]:
        """fetch details concurrently, preserving input order"""
        unique_ids = list(dict.fromkeys(cve_ids))
        if not unique_ids:
            return {}
        with ThreadPoolExecutor(max_workers=_DETAILS_WORKERS) as pool:
            results = pool.map(self.get_cve_details, unique_ids)
            return {
                cve_id: details
                for cve_id, details in zip(unique_ids, results)
                if details
            }