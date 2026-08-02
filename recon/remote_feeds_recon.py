import json
import logging
import os
import re
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
from core import extract_cvss, filter_items_by_date
from schemas import (
    CVEFinding,
    GitHubPoC,
)

logger = logging.getLogger(f"kernel_audit.{__name__}")
CVE_RE = re.compile(r"(CVE-\d{4}-\d+)", re.IGNORECASE)

# OSV queries paginate after ~1000 results; cap the follow-up pages
_OSV_MAX_PAGES = 10

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

    @staticmethod
    def get_kev():
        """download CISA KEV catalog"""
        res = httpx.get(
            CISA_KEV_URL, follow_redirects=True, headers={"User-Agent": "Mozilla/5.0"}
        )
        res.raise_for_status()
        with open(CISA_KEV_PATH, "wb") as f:
            f.write(res.content)
        logger.info("Downloaded KEV catalog: %d bytes", len(res.content))

    def load_kev(self, build_date: int | None = None):
        """load CISA KEV catalog and filter for Kernel products.

        When ``build_date`` (epoch seconds) is given, only KEV entries added to
        the catalog at or after the kernel build date are kept, so CVEs
        published/broadcast after the kernel was built are dropped.
        """
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

    @staticmethod
    def github_search(kern_version: str) -> list[GitHubPoC]:
        """Search PoC repositories on GitHub"""
        data = httpx.get(GITHUB_API_URL.format(q=f"cve {kern_version}")).json()

        results: list[GitHubPoC] = []
        seen: set[str] = set()

        for repo in data.get("items", []):
            text = " ".join(
                [
                    repo.get("name", "") or "",
                    repo.get("full_name", "") or "",
                    repo.get("description", "") or "",
                ]
            )
            # check also cve-poc names
            matches = re.findall(r"CVE-\d{4}-\d+", text, flags=re.IGNORECASE)

            if not matches:
                continue

            cve_id = matches[0].upper()

            key = f"{cve_id}:{repo.get('full_name', '')}"
            if key in seen:
                continue
            seen.add(key)

            results.append(
                GitHubPoC(
                    cve_id=cve_id,
                    repo_name=repo.get("full_name", ""),
                    repo_url=repo.get("html_url", ""),
                    description=repo.get("description", "") or "",
                    stars=repo.get("stargazers_count", 0),
                    language=repo.get("language") or "",
                )
            )

        logger.debug("github_search found %d PoCs", len(results))
        return results

    @staticmethod
    def _reformat_cve_details(data_raw: dict) -> dict:
        vulns = data_raw.get("vulnerabilities", [])
        if not vulns:
            return {}
        nist_cve = vulns[0].get("cve", {})
        if not nist_cve:
            return {}

        descriptions = nist_cve.get("descriptions", [])
        published = nist_cve.get("published", "")
        modified = nist_cve.get("lastModified", "")
        source_id = nist_cve.get("sourceIdentifier", "")

        metrics = []
        nist_metrics = nist_cve.get("metrics", {})
        for nk, mk in (
            ("cvssMetricV40", "cvssV4_0"),
            ("cvssMetricV31", "cvssV3_1"),
            ("cvssMetricV30", "cvssV3_0"),
            ("cvssMetricV2", "cvssV2_0"),
        ):
            for m in nist_metrics.get(nk, []):
                metrics.append({mk: m.get("cvssData", {})})

        problem_types = []
        for w in nist_cve.get("weaknesses", []):
            for desc in w.get("description", []):
                cv = desc.get("value", "")
                problem_types.append(
                    {
                        "descriptions": [
                            {
                                "lang": desc.get("lang", "en"),
                                "description": cv,
                                "cweId": cv if cv.startswith("CWE-") else "",
                                "type": "CWE",
                            }
                        ]
                    }
                )

        references = []
        for r in nist_cve.get("references", []):
            ref = {"url": r.get("url", "")}
            src = r.get("source")
            if src:
                ref["tags"] = [src]
            references.append(ref)

        affected = []
        for a in nist_cve.get("affected", []):
            item = {
                "vendor": a.get("vendor", ""),
                "product": a.get("product", ""),
                "versions": a.get("versions", []),
            }
            if a.get("modules"):
                item["modules"] = a["modules"]
            affected.append(item)

        return {
            "dataType": "CVE_RECORD",
            "dataVersion": "5.2",
            "cveMetadata": {
                "cveId": nist_cve.get("id", ""),
                "assignerOrgId": source_id,
                "state": nist_cve.get("vulnStatus", "PUBLISHED"),
                "datePublished": published,
                "dateUpdated": modified,
            },
            "containers": {
                "cna": {
                    "providerMetadata": {
                        "orgId": source_id,
                        "dateUpdated": modified,
                    },
                    "descriptions": descriptions,
                    "metrics": metrics,
                    "problemTypes": problem_types,
                    "references": references,
                    "affected": affected,
                }
            },
        }

    def _cve_org_details(self, cve_id: str) -> dict[str, Any]:
        """get cve details from cve.org MITRE API, if not accessible then NIST v2 API"""
        if self._mitre_available:
            try:
                response = httpx.get(CVEORG_BASE_URL + cve_id, timeout=5.0)
                response.raise_for_status()
                return response.json()

            except (httpx.HTTPError, ValueError) as exc:
                logger.warning(
                    "MITRE API unavailable, switching to NIST: %s",
                    exc,
                )
                self._mitre_available = False

        response = httpx.get(NIST_CVE_DETAILS_API_URL + cve_id, timeout=5.0)
        response.raise_for_status()
        return self._reformat_cve_details(response.json())

    @staticmethod
    def _filter_by_date(nist_result_raw, min_ts: int) -> list[dict]:
        if min_ts is None:
            return nist_result_raw.get("vulnerabilities", [])
        return filter_items_by_date(
            nist_result_raw.get("vulnerabilities", []),
            date_field="published",
            min_timestamp=min_ts,
        )

    def nist_search(self, kern_r_version, date) -> list[CVEFinding]:
        """Search for vulnerabilities in NIST database"""
        url: str = NIST_API_URL.format(version=kern_r_version)
        try:
            response = httpx.get(url)
            response.raise_for_status()
            data = response.json()
            logger.debug("NIST total=%d", len(data.get("vulnerabilities", [])))
            raw = self._filter_by_date(data, date)
            logger.debug("NIST after date filter=%d", len(raw))

            findings: list[CVEFinding] = []
            for item in raw:
                cve = item.get("cve", {})
                cve_id = cve.get("id") or item.get("cveId")
                if not cve_id:
                    continue

                desc = ""
                for d in cve.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc = d.get("value", "")
                        break

                cvss, severity, _ = extract_cvss(cve.get("metrics", {}))

                findings.append(
                    CVEFinding(
                        cve_id=str(cve_id),
                        description=desc,
                        severity=severity or "",
                        cvss_score=cvss,
                        source="NIST",
                        references=[],
                        raw_data=item,
                    )
                )
            return findings

        except _FEED_API_ERRORS as e:
            logger.warning("NIST search error: %s", str(e))
            return []

    @staticmethod
    def _osv_cve_ids(vuln: dict) -> list[str]:
        """resolve one OSV record to concrete CVE IDs.

        OSV entries can be advisory IDs (e.g. ``MGASA-2026-0312``,
        ``DEBIAN-CVE-...``) whose CVE ids live in ``aliases``, and one
        advisory can bundle several CVEs.  A record with a CVE id (or an
        advisory without usable aliases) falls back to its own id.
        """
        candidates: list[str] = [vuln.get("id", "")]
        candidates.extend(vuln.get("aliases", []) or [])
        cve_ids = [
            str(c).upper() for c in candidates if str(c).upper().startswith("CVE-")
        ]
        if not cve_ids and vuln.get("id"):
            cve_ids.append(str(vuln["id"]))
        return list(dict.fromkeys(cve_ids))

    def _osv_enriched_finding(self, cve_id: str, vuln: dict) -> CVEFinding:
        """build an OSV finding, filling missing data (CVSS) from NIST."""
        db_specific = vuln.get("database_specific") or {}
        finding = CVEFinding(
            cve_id=cve_id,
            description=vuln.get("summary", "") or "",
            severity=str(db_specific.get("severity") or ""),
            cvss_score=None,
            source="OSV",
            references=vuln.get("references", []) or [],
            raw_data=vuln,
        )
        details = self.get_cve_details(cve_id)
        if not details:
            return finding
        if not finding.description:
            finding.description = details.get("description", "")
        if not finding.severity:
            finding.severity = details.get("severity", "")
        if finding.cvss_score is None:
            finding.cvss_score = details.get("cvss_v3_score")
        return finding

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
                response = httpx.post(OSV_API_URL, json=body)
                response.raise_for_status()
                data = response.json()
            except _FEED_API_ERRORS as e:
                logger.warning("OSV search error: %s", str(e))
                return findings

            for vuln in data.get("vulns", []) or []:
                if not isinstance(vuln, dict):
                    continue
                for cve_id in self._osv_cve_ids(vuln):
                    if cve_id in seen:
                        continue
                    seen.add(cve_id)
                    findings.append(self._osv_enriched_finding(cve_id, vuln))

            page_token = data.get("next_page_token")
            if not page_token:
                break

        return findings

    def get_cve_details(self, cve_id: str) -> dict:
        """filter CVE metadata using the configured API, need for db"""
        try:
            data = self._cve_org_details(cve_id)
        except _FEED_API_ERRORS as e:
            logger.warning("%s get_cve_details error: %s", cve_id, str(e))
            return {}
        if not data:
            return {}
        containers = data.get("containers", {}) or {}
        cna = containers.get("cna", {}) or {}
        # cve.org / reformatted NIST use containers.cna, raw NIST 2.0 uses cve
        cve_obj = data.get("cve", {}) or cna

        descriptions = cve_obj.get("descriptions", [])
        description = next(
            (item.get("value") for item in descriptions if item.get("lang") == "en"),
            None,
        )
        if not description and descriptions:
            description = descriptions[0].get("value")

        cvss_score, cvss_severity, cvss_vector = extract_cvss(cve_obj.get("metrics"))

        logger.info("found %s CVSS score: %s", cve_id, cvss_score)
        logger.debug("found %s details raw data: %s", cve_id, data)
        return {
            "description": description,
            "cvss_v3_score": cvss_score,
            "cvss_v3_vector": cvss_vector,
            "severity": cvss_severity,
            "raw": data,
            "nist_url": f"{CVEORG_BASE_URL}{cve_id}",
        }
