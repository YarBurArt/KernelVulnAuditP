import logging
import os
import shlex
import tempfile
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from config import ALLOW_HOST_EXECUTION, ISOLATION_TIMEOUT_SEC
from core import format_timestamp, format_report, summarize_sandbox
from db import ThreatDB
from isolate import Isolate
from recon import LocalRecon, ReconFeeds
from schemas import (
    CVEFinding,
    FeedsReconResult,
    GitHubPoC,
    KernelLPE,
    LesCVEItem,
    LocalReconResult,
    ReconResult,
    SecurityRecommendation,
)
from sqxpl import GitHubExploitSearcher

logger = logging.getLogger(f"kernel_audit.{__name__}")


class AppServices:
    """Service layer shared by CLI and GUI flows."""

    def __init__(self, db: ThreatDB):
        self.lr = LocalRecon()
        self.rf = ReconFeeds()
        self.db = db
        self.poc_searcher = GitHubExploitSearcher()
        self.isolate = Isolate(timeout=ISOLATION_TIMEOUT_SEC)
        self.isolate.allow_host_execution = ALLOW_HOST_EXECUTION

    def store_security_recommendations(
        self, recommendations: list[SecurityRecommendation]
    ) -> int:
        """Persist security recommendations in the DB."""
        return self.db.bulk_insert_recommendations(recommendations)

    def run_local_recon(self, store_recs: bool = False) -> LocalReconResult:
        """Run local recon and optionally store recommendations."""
        kernel: str = self.lr.get_kernel_version_simple()
        build_date: int = self.lr.get_kernel_build_date(kernel)
        logger.info("Local recon started in context %s %s", kernel, build_date)
        # TODO: lynis_result: List[KernelAuditItem] = self.lr.get_lynis_scan_details()
        lynis_result = self.lr.get_lynis_kernel_hardening_details()
        logger.info("Lynis scan completed: %s", len(lynis_result))
        linpeas_result: KernelLPE | None = self.lr.get_linpeas_scan_details()
        logger.info("LinPEAS scan completed")
        les_result: list[LesCVEItem] = self.lr.get_les_scan_details()
        logger.info("LES scan completed: %s", len(les_result))

        return LocalReconResult(
            system=self.lr.environment_info.get("system", ""),
            build_date=build_date,
            security_recommendations=lynis_result,
            kernel_lpe=linpeas_result or KernelLPE(),
            kernel=kernel,
            possible_cves=les_result,
        )

    def run_feeds_recon(self, store_kev: bool = True) -> FeedsReconResult:
        """Fetch threat-intel feeds and optionally store CISA KEV data."""
        kernel: str = self.lr.get_kernel_version_simple()
        build_date: int = self.lr.get_kernel_build_date(kernel)

        logger.debug("Search feeds for kernel %s build_date %s", kernel, build_date)
        if store_kev:
            self._load_and_store_kev()

        findings: list[CVEFinding] = []
        findings.extend(self.rf.nist_search(kernel, build_date))
        findings.extend(self.rf.osv_search(kernel))

        pocs: list[GitHubPoC] = self.rf.github_search(kernel)

        return FeedsReconResult(findings=findings, pocs=pocs)

    def run_full_recon(self) -> ReconResult:
        """Run local + online recon and return combined result."""
        local_r = self.run_local_recon()
        feeds_r = self.run_feeds_recon()
        logger.info("full recon is completed, no isolated tests")
        return ReconResult(local=local_r, feeds=feeds_r)

    def run_execution_tests(self) -> dict:
        """validate kernel CVEs by sandbox-executing PoC"""
        context = self._build_execution_context()
        logger.info("execution tests started in context: %s", context)
        cve_hints = self._collect_kernel_cves()
        report_entries = []

        for cve_id, hint in cve_hints.items():
            entry = self._process_single_cve(cve_id, hint, context)

            if entry is not None:
                report_entries.append(entry)

        return self._build_execution_report(context, report_entries)

    @staticmethod
    def _parse_kev_date(value: str | None) -> datetime | None:
        if not value:
            return None

        try:
            return datetime.strptime(value, "%Y-%m-%d")
        except Exception as exc:
            logger.debug("Failed to parse date '%s': %s", value, exc)
            return None

    def _build_kev_records(
        self,
        kev_item: Dict[str, Any],
    ) -> tuple[str | None, Dict[str, Any], Dict[str, Any]]:

        cve_id = kev_item.get("cveID")
        kev_data = {
            "date_added": self._parse_kev_date(kev_item.get("dateAdded")),
            "due_date": self._parse_kev_date(kev_item.get("dueDate")),
            "required_action": kev_item.get("requiredAction"),
            "known_ransomware": (kev_item.get("knownRansomwareCampaignUse") == "Known"),
            "vendor_project": kev_item.get("vendorProject"),
            "product": kev_item.get("product"),
            "notes": kev_item.get("notes", ""),
        }
        vuln_data = {
            "cve_id": cve_id,
            "description": kev_item.get("shortDescription", ""),
            "in_cisa_kev": True,
            "sources": ["CISA_KEV"],
        }

        return cve_id, kev_data, vuln_data

    def _save_kev_entry(
        self,
        cve_id: str,
        kev_data: Dict[str, Any],
        vuln_data: Dict[str, Any],
    ) -> bool:
        try:
            self.db.upsert_vulnerability(vuln_data)
            self.db.add_cisa_kev(cve_id, kev_data)
            return True

        except Exception as exc:
            if "UNIQUE constraint failed" in str(exc):
                return False
            logger.warning("Error storing %s: %s", cve_id, exc)
            return False

    def _load_and_store_kev(self) -> None:
        """load CISA KEV feed and persist in DB"""
        try:
            self.rf.get_kev()
            self.rf.load_kev()
            logger.info(
                "Loaded %s kernel-related KEV entries", len(self.rf.kev_kern_vuln)
            )

        except Exception as e:
            logger.exception("Failed to load CISA KEV catalog: %s", e)
            return

        stored = 0
        skipped = 0
        for kev_item in self.rf.kev_kern_vuln:
            cve_id, kev_data, vuln_data = self._build_kev_records(kev_item)

            if not cve_id:
                continue
            logger.debug("N KEV: %s | N VULN: %s", kev_data, vuln_data)

            if self._save_kev_entry(cve_id, kev_data, vuln_data):
                stored += 1
            else:
                skipped += 1

        logger.info("Stored %s CISA KEV entries, %s already existed", stored, skipped)

    def _collect_kernel_cves(self) -> Dict[str, Dict[str, Any]]:
        logger.info("Collecting kernel cves by local scans")
        cves: Dict[str, Dict[str, Any]] = {}
        linpeas: KernelLPE | None = self.lr.get_linpeas_scan_details()
        if linpeas is None:
            logger.warning("No linpeas scans found")
            return cves
        logger.info("linpeas scan completed")
        for entry in linpeas.cves:
            if isinstance(entry, str) and entry:
                cves.setdefault(entry, {})["source"] = "linpeas"

        les_items: list[LesCVEItem] = self.lr.get_les_scan_details()
        logger.info("les scan completed")
        for entry_les in les_items:
            cve_id: str = entry_les.cve_id
            if not cve_id:
                continue
            target = cves.setdefault(cve_id, {})
            target.update(asdict(entry_les))
            target["source"] = "les"
        return cves

    @staticmethod
    def _normalize_source(source: str) -> str:
        return "LES" if source.lower() == "les" else source.upper()

    def _build_vulnerability(
        self,
        cve_id: str,
        hint: Dict[str, Any],
        metadata: Dict[str, Any],
        context: Dict[str, Any] | None,
    ) -> Dict[str, Any]:

        description = (
            hint.get("details") or hint.get("title") or metadata.get("description")
        )
        severity = hint.get("severity") or metadata.get("severity")
        raw_data = {"hint": hint, "metadata": metadata.get("raw")}

        if context:
            raw_data["context"] = context

        return {
            "cve_id": cve_id,
            "description": description,
            "cvss_v3_score": metadata.get("cvss_v3_score"),
            "severity": severity,
            "sources": [self._normalize_source(hint.get("source", "linpeas"))],
            "raw_data": raw_data,
        }

    def _persist_cve_hint(
        self,
        cve_id: str,
        hint: Dict[str, Any],
        context: Dict[str, Any] | None = None,
    ) -> Dict[str, Any] | None:

        metadata = self.rf.get_cve_details(cve_id) or {}
        vuln = self._build_vulnerability(cve_id, hint, metadata, context)
        logger.debug("%s hint/refs vuln: %s", cve_id, vuln)
        self.db.upsert_vulnerability(vuln)

        if metadata.get("nist_url"):
            self.db.add_reference(
                cve_id, metadata["nist_url"], ref_type="ADVISORY", source="NIST"
            )

        return {
            "cve_id": vuln["cve_id"],
            "description": vuln["description"],
            "cvss_v3_score": vuln["cvss_v3_score"],
            "severity": vuln["severity"],
            "sources": vuln["sources"],
        }

    def _build_execution_context(self) -> Dict[str, Any]:
        kernel = self.lr.get_kernel_version_simple()
        return {
            "kernel_version": kernel,
            "build_date": self.lr.get_kernel_build_date(kernel),
        }

    def _process_single_cve(
        self,
        cve_id: str,
        hint: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any] | None:

        entry = self._persist_cve_hint(cve_id, hint, context,)
        if entry is None:
            logger.warning("%s additional info hint is not saved", cve_id)
            return None

        repos = self.poc_searcher.search_repositories(cve_id, max_results=3,)
        downloads = GitHubExploitSearcher.load_xpls(repos)
        entry["pocs"] = [self._record_poc_for_cve(cve_id, poc) for poc in downloads]

        return entry

    def _build_execution_report(
        self,
        context: Dict[str, Any],
        entries: List[Dict[str, Any]],
    ) -> Dict[str, Any]:

        build_date = context["build_date"]
        return {
            "kernel": context["kernel_version"],
            "build_date": (
                format_timestamp(build_date) if build_date is not None else None
            ),
            "cves_processed": len(entries),
            "stats": self.db.get_statistics(),
            "entries": entries,
        }

    def _register_poc(self, cve_id: str, poc: Dict[str, Any]) -> None:
        exploit_meta = {
            "exploit_type": "PoC",
            "source": "GitHub",
            "url": poc.get("url"),
            "verified": True,
        }

        logger.debug("record poc meta: %s", exploit_meta)
        self.db.add_exploit(cve_id, exploit_meta)

        if poc.get("url"):
            self.db.add_reference(cve_id, poc["url"], ref_type="EXPLOIT", source="GitHub")

    @staticmethod
    def _build_poc_summary(poc: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "url": poc.get("url"),
            "language": poc.get("language"),
            "stars": poc.get("stars"),
            "compile_cmd": poc.get("compile_cmd"),
            "test_cmd": poc.get("test_cmd"),
        }

    def _execute_poc(
        self,
        cve_id: str,
        poc: Dict[str, Any],
    ) -> Dict[str, Any]:
        command = poc.get("test_cmd") or poc.get("compile_cmd")
        repo: str = poc.get("local_path", "")

        if not command or not repo:
            return {}

        script = self._build_runner_script(Path(repo), str(command))
        logger.debug("build runner script: %s", script)

        try:
            logger.info("%s: %s - is started", cve_id, command)
            result = self.isolate.run_binary(script)
            if not result:
                return {}

            logger.info("%s poc - is finished", cve_id)
            self._store_sandbox_run(cve_id, result, str(command))

            return {"sandbox": summarize_sandbox(result),}

        except Exception as exc:
            logger.warning("%s: %s - is failed: %s", cve_id, command, exc)

            return {"sandbox_error": str(exc),}

        finally:
            try:
                script.unlink()
            except FileNotFoundError as exc:
                logger.debug("unlink failed, missing script: %s", exc)

    def _record_poc_for_cve(
        self,
        cve_id: str,
        poc: Dict[str, Any],
    ) -> Dict[str, Any]:
        self._register_poc(cve_id, poc)
        summary = self._build_poc_summary(poc)
        summary.update(self._execute_poc(cve_id, poc))

        return summary

    @staticmethod
    def _build_runner_script(repo_path: Path, command: str) -> Path:
        fd, path = tempfile.mkstemp(prefix="kernaudit-run-", suffix=".sh")
        os.close(fd)
        script = Path(path)
        script.write_text(
            "#!/bin/sh\n"
            "set -e\n"
            f"cd {shlex.quote(str(repo_path))}\n"
            f"{command}\n",
            encoding="utf-8",
        )
        script.chmod(0o755)
        return script

    def _store_sandbox_run(self, cve_id: str, result, command: str) -> None:
        logs = getattr(result, "logs", {}) or {}
        xpl_hash = logs.get("exploit_hash", logs.get("binary", " "))

        sandbox_data = {
            "sandbox_platform": getattr(result, "execution_mode", "unknown"),
            "run_timestamp": datetime.now(timezone.utc),
            "exploit_file_hash": xpl_hash,
            "execution_success": getattr(result, "returncode", 1) == 0,
            "exit_code": getattr(result, "returncode", -1),
            "crashed": getattr(result, "crashed", False),
            "stdout": getattr(result, "stdout", " "),
            "stderr": getattr(result, "stderr", " "),
            "stdin": command,
            "open_processes": getattr(result, "processes", []),
            "open_files": getattr(result, "files", []),
            "modules": getattr(result, "modules", []),
            "kernel_info": getattr(result, "kernel_info", {}),
            "resources": getattr(result, "resources", {}),
            "notes": logs.get("command"),
        }

        logger.debug("%s full sandbox POC data: %s", cve_id, sandbox_data)
        self.db.add_sandbox_run(cve_id, sandbox_data)

    def save_recon_results(self, results: dict) -> int:
        """Persist a previous execution report into the DB."""
        kernel = results.get("kernel")
        build_date = results.get("build_date")
        context = {"kernel_version": kernel, "build_date": build_date}
        saved = 0
        for entry in results.get("entries", []):
            cve_id = entry.get("cve_id")
            if not cve_id:
                continue
            vuln = {
                "cve_id": cve_id,
                "description": entry.get("description"),
                "cvss_v3_score": entry.get("cvss_v3_score"),
                "severity": entry.get("severity"),
                "sources": entry.get("sources", []),
                "raw_data": {
                    "entry": entry,
                    "context": context,
                },
            }
            logger.info("saving recon results for %s", cve_id)
            logger.debug("recon item for %s is: %s", cve_id, vuln)
            self.db.upsert_vulnerability(vuln)
            saved += 1
        return saved

    def get_cached_recon(self, kernel: str):
        """Return cached CVE entries tied to a kernel version."""
        results = []
        offset = 0
        chunk = 100
        while True:
            batch = self.db.search(limit=chunk, offset=offset)
            if not batch:
                logger.debug("no cached recon entries")
                break
            for vuln in batch:
                raw = vuln.get("raw_data", {})
                context = raw.get("context", {})
                if context.get("kernel_version") == kernel:
                    logger.debug("found cached recon entry: %s", vuln)
                    results.append(vuln)
            if len(batch) < chunk:
                break
            offset += chunk
        return results

    def get_statistics(self):
        """Return aggregated statistics from the DB."""
        stats = self.db.get_statistics()
        rec_stats = self.db.get_recommendations_stats()
        stats["security_recommendations"] = rec_stats
        return stats

    def get_security_recommendations(
        self, category: str | None = None,
        status: str | None = None, limit: int = 100
    ) -> List[dict]:
        """Get security recommendations with optional filters."""
        logger.debug(f"getting recommendations/params for {category}")
        return self.db.get_security_recommendations(
            category=category, status=status, limit=limit)

    def get_cisa_kev_entries(self, limit: int = 100) -> List[dict]:
        """Get CISA KEV entries from DB."""
        return self.db.get_cisa_kev_list(limit=limit)

    def generate_report(self):
        logger.debug(f"generating base report")
        data = self.run_full_recon()
        return format_report(asdict(data))


__all__ = ["AppServices"]
