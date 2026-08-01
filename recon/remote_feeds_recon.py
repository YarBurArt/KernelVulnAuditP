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
from core import (
    filter_items_by_date,
)
from schemas import (
    CVEFinding,
    GitHubPoC,
)

logger = logging.getLogger(f"kernel_audit.{__name__}")
CVE_RE = re.compile(r"(CVE-\d{4}-\d+)", re.IGNORECASE)


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

    def load_kev(self):
        """load CISA KEV catalog and filter for Kernel products"""
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

        self.kev_kern_vuln = []
        for vuln in vulns:
            product = vuln.get("product", "")
            vendor = vuln.get("vendorProject", "")
            if product and "kernel" in product.lower() or vendor and "linux" in vendor.lower():
                self.kev_kern_vuln.append(vuln)

        logger.debug("KEV vulnerabilities: %d", len(self.kev_kern_vuln))

    # TODO: KEV check with build date
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
            for ad in a.get("affectedData", []):
                item = {
                    "vendor": ad.get("vendor", ""),
                    "product": ad.get("product", ""),
                    "versions": ad.get("versions", []),
                }
                if ad.get("modules"):
                    item["modules"] = ad["modules"]
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

            except httpx.HTTPError as exc:
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

                metrics = cve.get("metrics", {})
                cvss = None
                if "cvssMetricV31" in metrics:
                    cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]

                findings.append(
                    CVEFinding(
                        cve_id=str(cve_id),
                        description=desc,
                        severity="",
                        cvss_score=cvss,
                        source="NIST",
                        references=[],
                        raw_data=item,
                    )
                )
            return findings

        except Exception as e:
            logger.warning("NIST search error: %s", str(e))
            return []

    @staticmethod
    def osv_search(kern_r_version) -> list[CVEFinding]:
        """Search for vulnerabilities by api OSV database"""
        payload = {
            "version": kern_r_version,
            "package": {"name": "linux", "ecosystem": "Linux"},
        }
        try:
            response = httpx.post(OSV_API_URL, json=payload)
            response.raise_for_status()
            data = response.json()

            findings: list[CVEFinding] = []

            for v in data.get("vulns", []):
                findings.append(
                    CVEFinding(
                        cve_id=v.get("id", ""),
                        description=v.get("summary", ""),
                        severity="",
                        cvss_score=None,
                        source="OSV",
                        references=v.get("references", []),
                        raw_data=v,
                    )
                )

            return findings

        except Exception as e:
            logger.warning("OSV search error: %s", str(e))
            return []

    def get_cve_details(self, cve_id: str) -> dict:
        """filter CVE metadata using the configured API, need for db"""
        try:
            data = self._cve_org_details(cve_id)
        except Exception as e:
            logger.warning("%s get_cve_details error: %s", cve_id, str(e))
            return {}
        cve_obj = data.get("cve", {})
        descriptions = cve_obj.get("descriptions", [])
        description = next(
            (item.get("value") for item in descriptions if item.get("lang") == "en"),
            None,
        )
        if not description and descriptions:
            description = descriptions[0].get("value")

        # try CVSS v3.1, then v3.0, then v2
        metrics = cve_obj.get("metrics", {})
        cvss_score = None
        cvss_severity = None
        cvss_vector = None
        # FIXME
        for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                metric = metric_list[0]
                cvss_data = metric.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_severity = cvss_data.get("baseSeverity")
                cvss_vector = cvss_data.get("vectorString")
                break

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
