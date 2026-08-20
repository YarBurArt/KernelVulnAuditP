import asyncio
import json
import logging
import os
import random
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
from core.entities import CVEFinding, GitHubPoC
from core.parsing import filter_items_by_date
from recon.parse_recon_reports import ParseReports

logger = logging.getLogger(f"kernel_audit.{__name__}")

# OSV queries paginate after ~1000 results; cap the follow-up pages
_OSV_MAX_PAGES = 10
# OSV intermittently drops connections mid-body; retry transient transport
# errors (httpx.ReadError/ReadTimeout/ConnectError) before giving up
_OSV_TRANSIENT_ERRORS = (httpx.TransportError,)
_OSV_RETRIES = 2
_OSV_RETRY_BASE_DELAY = 1.0
_DETAILS_WORKERS = 4
# NIST pages its CVE catalog server-side; the largest page keeps the request count minimal,
# so only one page's JSON is ever resident instead of the whole catalog, near was leak
_NIST_PAGE_SIZE = 2000
# truncated with a warning instead of hammering the API.
_MAX_NIST_PAGES = 8
_FEEDS_USER_AGENT = "kernelvulnauditp/0.1.1"

# OSV requests get their own timeout as a per-request override
_OSV_READ_TIMEOUT = 40.0

# NVD API 2.0 allows around 5 requests per 30s without an API key
# With NVD_API_KEY set the interval drops to the faster tier; both are overridable with NVD_MIN_INTERVAL.
_NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
_NVD_MIN_INTERVAL = float(
    os.environ.get("NVD_MIN_INTERVAL", "0.6" if _NVD_API_KEY else "6.0")
)
_NVD_MAX_RETRIES = 3

# concrete exceptions raised by httpx calls or malformed feed payloads
_FEED_API_ERRORS = (
    httpx.HTTPError,
    ValueError,
    KeyError,
    IndexError,
    TypeError,
    AttributeError,
)


def _exc_desc(exc: BaseException) -> str:
    """human-readable exception description for Engine Stdout TUI log view"""
    message = str(exc).strip()
    return f"{type(exc).__name__}: {message}" if message else type(exc).__name__

#: KEV catalog fields that the rest of the tool actually reads,
#: everything else is dropped on load so we never retain the full data per run.
_KEV_FIELDS = (
    "cveID",
    "vendorProject",
    "product",
    "vulnerabilityName",
    "dateAdded",
    "shortDescription",
    "requiredAction",
    "dueDate",
    "knownRansomwareCampaignUse",
    "notes",
)


def _write_bytes(path: str, content: bytes) -> None:
    """blocking file write helper, run off the event loop via asyncio.to_thread"""
    with open(path, "wb") as f:
        f.write(content)


def _read_text(path: str) -> str:
    """blocking file read helper, run off the event loop via asyncio.to_thread"""
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


class ReconFeeds:
    """
    get data from cve org and KEV, GitHub search
    using LocalRecon kernel version

    All network methods are async and share one httpx.AsyncClient bound to
    the currently running event loop; callers that need a sync entry point run
    them through asyncio.run at the AppServices layer.
    """

    def __init__(self):
        self.kev_kern_vuln: list[dict[str, Any]] = []
        self._mitre_available = True
        self._details_cache: dict[str, dict[str, Any]] = {}
        self._summary_cache: dict[str, dict[str, Any]] = {}
        self._client: httpx.AsyncClient | None = None
        self._client_loop: asyncio.AbstractEventLoop | None = None
        # NVD politeness gate; keyed to the running loop like the client because
        # asyncio.Lock binds to the loop it is first used on.
        self._nvd_lock: asyncio.Lock | None = None
        self._nvd_lock_loop: asyncio.AbstractEventLoop | None = None
        self._nvd_last_ts = 0.0
        self.parser = ParseReports()

    async def _get_client(self) -> httpx.AsyncClient:
        """return the pooled AsyncClient, (re)creating it for a new loop.

        asyncio.run tears the loop down after each top-level call, so the
        client is keyed to the running loop and recreated on loop changes.
        """
        loop = asyncio.get_running_loop()
        if self._client is None or self._client_loop is not loop:
            await self._drop_client()
            self._client = httpx.AsyncClient(
                http2=True,
                headers={"User-Agent": _FEEDS_USER_AGENT},
                timeout=httpx.Timeout(10.0, connect=5.0),
                follow_redirects=True,
            )
            self._client_loop = loop
        return self._client

    async def _drop_client(self) -> None:
        """close any client whose event loop is gone, tolerating a dead loop"""
        client, self._client = self._client, None
        self._client_loop = None
        if client is not None:
            try:
                await client.aclose()
            except RuntimeError:
                # loop already closed (asyncio.run teardown), and if py>=3.14t
                pass

    async def close(self) -> None:
        """close the shared HTTP session and its pooled connections"""
        await self._drop_client()

    async def _nvd_get(self, url: str, **params: Any) -> httpx.Response:
        """rate-limited NVD GET: min-interval gate ... and 429 Retry-After backoff"""
        loop = asyncio.get_running_loop()
        if self._nvd_lock is None or self._nvd_lock_loop is not loop:
            self._nvd_lock = asyncio.Lock()
            self._nvd_lock_loop = loop
            self._nvd_last_ts = 0.0

        client = await self._get_client()
        headers = {"apiKey": _NVD_API_KEY} if _NVD_API_KEY else None

        assert self._nvd_lock is not None
        async with self._nvd_lock:
            wait = _NVD_MIN_INTERVAL - (loop.time() - self._nvd_last_ts)
            if wait > 0:
                await asyncio.sleep(wait)

            attempts = 0
            while True:
                self._nvd_last_ts = loop.time()
                response = await client.get(url, params=params or None, headers=headers)
                if response.status_code != 429 or attempts >= _NVD_MAX_RETRIES:
                    return response

                attempts += 1
                resp_headers: dict | None = getattr(response, "headers", None)
                retry_after = 0.0
                if resp_headers is not None:
                    try:
                        retry_after = float(resp_headers.get("Retry-After", "0") or 0)
                    except (TypeError, ValueError):
                        retry_after = 0.0
                delay = retry_after or (_NVD_MIN_INTERVAL * (2**attempts))
                delay += random.uniform(0, 1)
                logger.warning(
                    "NVD rate-limited (%s); backing off %.1fs (attempt %d/%d)",
                    url,
                    delay,
                    attempts,
                    _NVD_MAX_RETRIES,
                )
                await asyncio.sleep(delay)

    async def get_kev(self):
        """download CISA KEV catalog"""
        client = await self._get_client()
        res = await client.get(CISA_KEV_URL)
        res.raise_for_status()
        await asyncio.to_thread(_write_bytes, CISA_KEV_PATH, res.content)
        logger.info("Downloaded KEV catalog: %d bytes", len(res.content))

    async def load_kev(self, build_date: int | None = None):
        """load CISA KEV catalog and filter for Kernel products + year"""
        if not os.path.exists(CISA_KEV_PATH):
            logger.info("KEV catalog not found, downloading...")
            await self.get_kev()

        data = json.loads(await asyncio.to_thread(_read_text, CISA_KEV_PATH))

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
                self.kev_kern_vuln.append(
                    {field: vuln.get(field) for field in _KEV_FIELDS}
                )

        logger.debug("KEV vulnerabilities: %d", len(self.kev_kern_vuln))

    async def github_search(self, kern_version: str) -> list[GitHubPoC]:
        """Search PoC repositories on GitHub"""
        client = await self._get_client()
        data = (
            await client.get(GITHUB_API_URL.format(q=f"cve {kern_version}"))
        ).json()

        pocs = self.parser.parse_github_pocs(data or {})
        logger.debug("github_search found %d PoCs", len(pocs))
        return pocs

    async def _cve_org_details(self, cve_id: str) -> dict[str, Any]:
        """get cve details from cve.org MITRE API, if not accessible then NIST v2 API"""
        client = await self._get_client()
        if self._mitre_available:
            try:
                response = await client.get(CVEORG_BASE_URL + cve_id)
                response.raise_for_status()
                return response.json()

            except (httpx.HTTPError, ValueError) as exc:
                logger.warning(
                    "MITRE API unavailable, switching to NIST: %s",
                    exc,
                )
                self._mitre_available = False

        response = await self._nvd_get(NIST_CVE_DETAILS_API_URL + cve_id)
        response.raise_for_status()
        return self.parser.reformat_cve_details(response.json())

    async def nist_search(self, kern_r_version, date) -> list[CVEFinding]:
        """Search for vulnerabilities in NIST database.

        The NVD CVE API uses offset pagination (max 2,000 results per page),
        loads one page at a time to save memory. Pagination is appended to the CPE-filtered URL;
        httpx can remove the filter when params used. go through _nvd_get, which enforces NVD's rate limits
        """
        findings: list[CVEFinding] = []
        base_url = NIST_API_URL.format(version=kern_r_version)
        start_index = 0

        pages = 0
        try:
            while True:
                pages += 1
                url = (
                    f"{base_url}&startIndex={start_index}"
                    f"&resultsPerPage={_NIST_PAGE_SIZE}"
                )
                response = await self._nvd_get(url)
                response.raise_for_status()
                data = response.json()
                findings.extend(self.parser.parse_nist_findings(data or {}, date))

                vulns = (data or {}).get("vulnerabilities", []) or []
                returned = len(vulns)
                total = int((data or {}).get("totalResults") or 0)
                start_index += returned
                if not returned or start_index >= total:
                    break
                if pages >= _MAX_NIST_PAGES:
                    logger.warning(
                        "NIST result set truncated after %d pages "
                        "(only %d of %d fetched)",
                        pages,
                        start_index,
                        total,
                    )
                    break

        except _FEED_API_ERRORS as e:
            logger.warning("NIST search error: %s", _exc_desc(e))

        logger.debug("NIST after date filter=%d", len(findings))
        return findings

    async def osv_search(self, kern_r_version) -> list[CVEFinding]:
        """Search for Linux kernel CVEs in OSV, enriching missing data from NIST."""
        client = await self._get_client()
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
            data = await self._osv_post(client, body)
            if data is None:
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

        await self._enrich_osv_findings(findings)
        return findings

    async def _osv_post(
        self, client, body: dict[str, Any]
    ) -> dict[str, Any] | None:
        """POST one OSV page; transient transport errors (e.g. the connection
        being dropped mid-body, httpx.ReadError) are retried with backoff."""
        for attempt in range(_OSV_RETRIES + 1):
            try:
                response = await client.post(
                    OSV_API_URL,
                    json=body,
                    timeout=httpx.Timeout(_OSV_READ_TIMEOUT, connect=5.0),
                )
                response.raise_for_status()
                return response.json()
            except _OSV_TRANSIENT_ERRORS as e:
                if attempt < _OSV_RETRIES:
                    logger.warning(
                        "OSV transport error, retrying (%d/%d): %s",
                        attempt + 1,
                        _OSV_RETRIES,
                        _exc_desc(e),
                    )
                    await asyncio.sleep(_OSV_RETRY_BASE_DELAY * (2**attempt))
                    continue
                logger.warning("OSV search error: %s", _exc_desc(e))
                return None
            except _FEED_API_ERRORS as e:
                logger.warning("OSV search error: %s", _exc_desc(e))
                return None
        return None

    async def _enrich_osv_findings(self, findings: list[CVEFinding]) -> None:
        """batch-fetch CVE metadata concurrently to fill missing OSV data"""
        details_map = await self.get_cve_details_many([f.cve_id for f in findings])
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

    async def get_cve_details(self, cve_id: str) -> dict[str, Any]:
        """filter CVE metadata using the configured API for db.

        Returns the full extracted record; only a trimmed summary is kept in the cache
        """
        cached = self._details_cache.get(cve_id)
        if cached is not None:
            return cached

        data = await self._fetch_cve_details(cve_id)
        if not data:
            return {}

        self._details_cache[cve_id] = data
        return data

    async def _fetch_cve_details(self, cve_id: str) -> dict[str, Any]:
        try:
            data = await self._cve_org_details(cve_id)
        except _FEED_API_ERRORS as e:
            logger.warning("%s get_cve_details error: %s", cve_id, _exc_desc(e))
            return {}
        if not data:
            return {}

        return self.parser.extract_cve_details(
            data, f"{CVEORG_BASE_URL}{cve_id}"
        )

    async def _fetch_cve_summary(self, cve_id: str) -> dict[str, Any]:
        """cached, memory-lean CVE metadata (description/cvss/severity only)"""
        cached = self._summary_cache.get(cve_id)
        if cached is not None:
            return cached

        details = await self._fetch_cve_details(cve_id)
        if not details:
            return {}

        summary = {k: v for k, v in details.items() if k != "raw"}
        self._summary_cache[cve_id] = summary
        return summary

    async def get_cve_details_many(self, cve_ids: list[str]) -> dict[str, dict[str, Any]]:
        """fetch CVE summaries concurrently, preserving input order"""
        unique_ids = list(dict.fromkeys(cve_ids))
        if not unique_ids:
            return {}

        sem = asyncio.Semaphore(_DETAILS_WORKERS)

        async def _fetch(cve_id: str) -> tuple[str, dict[str, Any]]:
            async with sem:
                return cve_id, await self._fetch_cve_summary(cve_id)

        results = await asyncio.gather(*(_fetch(cid) for cid in unique_ids))
        return {
            cve_id: summary
            for cve_id, summary in results
            if summary
        }
