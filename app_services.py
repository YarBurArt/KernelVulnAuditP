import os
import shlex
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from config import ALLOW_HOST_EXECUTION, DB_BACKEND, ISOLATION_TIMEOUT_SEC
from core import format_timestamp
from db import get_db
from isolate import Isolate
from recon import LocalRecon, ReconFeeds
from schemas import FeedsReconResult, LocalReconResult, ReconResult, SecurityRecommendation
from sqxpl import GitHubExploitSearcher


class AppServices:
    """Service layer shared by CLI and GUI flows."""

    def __init__(self, db: str | None = None):
        self.lr = LocalRecon()
        self.rf = ReconFeeds()
        self.db = db or get_db(DB_BACKEND)
        self.poc_searcher = GitHubExploitSearcher()
        self.isolate = Isolate(timeout=ISOLATION_TIMEOUT_SEC)
        self.isolate.allow_host_execution = ALLOW_HOST_EXECUTION

    def store_security_recommendations(self, recommendations: List[dict]) -> int:
        """Persist security recommendations in the DB."""
        return self.db.bulk_insert_recommendations(recommendations)

    def run_local_recon(self, store_recs: bool = False) -> dict:
        """Run local recon and optionally store recommendations."""
        kernel: str = self.lr.get_kernel_version_simple()
        build_date: str = self.lr.get_kernel_build_date(kernel)
        lynis_result: List[dict] = self.lr.get_lynis_scan_details()
        linpeas_result: dict = self.lr.get_linpeas_scan_details()
        les_result: List[dict] = self.lr.get_les_scan_details()

        if store_recs and lynis_result:
            recs = [SecurityRecommendation.from_dict(item).raw_data for item in lynis_result]
            self.store_security_recommendations(recs)

        return LocalReconResult(
            system=self.lr.environment_info.get("system", ""),
            build_date=build_date,
            kernel_audit=lynis_result,
            kernel_lpe=linpeas_result,
            kernel=kernel,
            possible_cves=les_result,
        )

    def run_feeds_recon(self, store_kev: bool = True) -> dict:
        """Fetch threat-intel feeds and optionally store CISA KEV data."""
        kernel: str = self.lr.get_kernel_version_simple()
        build_date: str = self.lr.get_kernel_build_date(kernel)

        if store_kev:
            self._load_and_store_kev()

        nist = self.rf.nist_search(kernel, build_date)
        osv: dict = self.rf.osv_search(kernel)
        github: dict = self.rf.github_search(kernel)

        return FeedsReconResult(nist=nist, osv=osv, github=github)

    def _load_and_store_kev(self) -> None:
        """Load CISA KEV catalog and persist in DB."""
        try:
            self.rf.get_kev()
            self.rf.load_kev()
            print(f"Loaded {len(self.rf.kev_kern_vuln)} kernel-related KEV entries")
        except Exception as e:
            print(f"KEV load error: {e}")
            import traceback

            traceback.print_exc()
            return

        stored = 0
        skipped = 0
        for kev_item in self.rf.kev_kern_vuln:
            cve_id = kev_item.get("cveID")
            if not cve_id:
                continue

            date_added = None
            due_date = None
            try:
                date_str = kev_item.get("dateAdded")
                if date_str:
                    date_added = datetime.strptime(date_str, "%Y-%m-%d")
                due_str = kev_item.get("dueDate")
                if due_str:
                    due_date = datetime.strptime(due_str, "%Y-%m-%d")
            except Exception:
                pass

            kev_data = {
                "date_added": date_added,
                "due_date": due_date,
                "required_action": kev_item.get("requiredAction"),
                "known_ransomware": kev_item.get("knownRansomwareCampaignUse") == "Known",
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

            try:
                self.db.upsert_vulnerability(vuln_data)
                self.db.add_cisa_kev(cve_id, kev_data)
                stored += 1
            except Exception as e:
                if "UNIQUE constraint failed" in str(e):
                    skipped += 1
                else:
                    print(f"Error storing {cve_id}: {e}")

        print(f"Stored {stored} CISA KEV entries, {skipped} already existed")

    def run_full_recon(self) -> dict:
        """Run local + online recon and return combined result."""
        local_r = self.run_local_recon()
        feeds_r = self.run_feeds_recon()
        return ReconResult(local=local_r, feeds=feeds_r)

    def run_execution_tests(self) -> dict:
        """Validate kernel CVEs by sandbox-executing PoCs."""
        kernel = self.lr.get_kernel_version_simple()
        build_date = self.lr.get_kernel_build_date(kernel)
        cve_hints = self._collect_kernel_cves()
        context = {"kernel_version": kernel, "build_date": build_date}

        report_entries = []
        for cve_id, hint in cve_hints.items():
            entry = self._persist_cve_hint(cve_id, hint, context)
            if entry is None:
                continue
            entry["pocs"] = []
            repos = self.poc_searcher.search_repositories(cve_id, max_results=3)
            downloads = GitHubExploitSearcher.load_xpls(repos)
            for poc in downloads:
                summary = self._record_poc_for_cve(cve_id, poc)
                if summary:
                    entry["pocs"].append(summary)
            report_entries.append(entry)

        stats = self.db.get_statistics()
        p_build = None
        if build_date is not None:
            p_build = format_timestamp(build_date)
        return {
            "kernel": kernel,
            "build_date": p_build,
            "cves_processed": len(report_entries),
            "stats": stats,
            "entries": report_entries,
        }

    def _collect_kernel_cves(self) -> Dict[str, Dict[str, Any]]:
        cves: Dict[str, Dict[str, Any]] = {}
        linpeas = self.lr.get_linpeas_scan_details()
        for entry in linpeas.get("cves", []):
            if isinstance(entry, str) and entry:
                cves.setdefault(entry, {})["source"] = "linpeas"

        les_items = self.lr.get_les_scan_details()
        for entry in les_items:
            cve_id = entry.get("cve_id")
            if not cve_id:
                continue
            target = cves.setdefault(cve_id, {})
            target.update(entry)
            target["source"] = "les"
        return cves

    def _persist_cve_hint(
        self,
        cve_id: str,
        hint: Dict[str, Any],
        context: Dict[str, Any] | None = None,
    ) -> Dict[str, Any] | None:
        metadata = self.rf.get_cve_details(cve_id) or {}
        description = hint.get("details") or hint.get("title") or metadata.get("description")
        severity = hint.get("severity") or metadata.get("severity")
        raw_source = hint.get("source", "linpeas")
        normalized_source = "LES" if raw_source == "les" else raw_source.upper()
        vuln = {
            "cve_id": cve_id,
            "description": description,
            "cvss_v3_score": metadata.get("cvss_v3_score"),
            "severity": severity,
            "sources": [normalized_source],
            "raw_data": {
                "hint": hint,
                "metadata": metadata.get("raw"),
            },
        }
        if context:
            vuln["raw_data"]["context"] = context
        self.db.upsert_vulnerability(vuln)
        if metadata.get("nist_url"):
            self.db.add_reference(cve_id, metadata["nist_url"], ref_type="ADVISORY", source="NIST")
        return {
            "cve_id": cve_id,
            "description": description,
            "cvss_v3_score": metadata.get("cvss_v3_score"),
            "severity": severity,
            "sources": [normalized_source],
        }

    def _record_poc_for_cve(self, cve_id: str, poc: Dict[str, Any]) -> Dict[str, Any] | None:
        exploit_meta = {
            "exploit_type": "PoC",
            "source": "GitHub",
            "url": poc.get("url"),
            "verified": True,
        }
        self.db.add_exploit(cve_id, exploit_meta)
        if poc.get("url"):
            self.db.add_reference(cve_id, poc["url"], ref_type="EXPLOIT", source="GitHub")
        summary = {
            "url": poc.get("url"),
            "language": poc.get("language"),
            "stars": poc.get("stars"),
            "compile_cmd": poc.get("compile_cmd"),
            "test_cmd": poc.get("test_cmd"),
        }
        command = poc.get("test_cmd") or poc.get("compile_cmd")
        repo = poc.get("local_path")
        if command and repo:
            script = self._build_runner_script(Path(repo), command)
            try:
                result = self.isolate.run_binary(script)
                if result:
                    summary["sandbox"] = self._summarize_sandbox(result)
                    self._store_sandbox_run(cve_id, result, command)
            except Exception as exc:
                summary["sandbox_error"] = str(exc)
            finally:
                try:
                    script.unlink()
                except FileNotFoundError:
                    pass
        return summary

    def _build_runner_script(self, repo_path: Path, command: str) -> Path:
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

    def _summarize_sandbox(self, result) -> Dict[str, Any]:
        return {
            "mode": getattr(result, "execution_mode", "unknown"),
            "returncode": getattr(result, "returncode", None),
            "success": getattr(result, "returncode", 1) == 0,
            "stdout": getattr(result, "stdout", ""),
            "stderr": getattr(result, "stderr", ""),
            "logs": getattr(result, "logs", {}),
        }

    def _store_sandbox_run(self, cve_id: str, result, command: str) -> None:
        xpl_hash = result.logs.get("exploit_hash") if hasattr(result, "logs") else ""
        open_fproc = result.logs.get("open_processes", []) if hasattr(result, "logs") else []
        open_f = result.logs.get("open_files", []) if hasattr(result, "logs") else []
        cmd_log = result.logs.get("command") if hasattr(result, "logs") else None
        sandbox_data = {
            "sandbox_platform": getattr(result, "execution_mode", "unknown"),
            "run_timestamp": datetime.now(timezone.utc),
            "exploit_file_hash": xpl_hash,
            "execution_success": getattr(result, "returncode", 1) == 0,
            "exit_code": getattr(result, "returncode", -1),
            "stdout": getattr(result, "stdout", ""),
            "stderr": getattr(result, "stderr", ""),
            "stdin": command,
            "open_processes": open_fproc,
            "open_files": open_f,
            "notes": cmd_log,
        }
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
                break
            for vuln in batch:
                raw = vuln.get("raw_data", {})
                context = raw.get("context", {})
                if context.get("kernel_version") == kernel:
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

    def get_security_recommendations(self, category: str | None = None, status: str | None = None, limit: int = 100) -> List[dict]:
        """Get security recommendations with optional filters."""
        return self.db.get_security_recommendations(category=category, status=status, limit=limit)

    def get_cisa_kev_entries(self, limit: int = 100) -> List[dict]:
        """Get CISA KEV entries from DB."""
        return self.db.get_cisa_kev_list(limit=limit)

    def generate_report(self, kern_v: str = "6.18.0"):
        data = self.run_full_recon(kern_v)
        return self._format_report(data)

    def _format_report(self, data: dict) -> dict:
        nist = data.get("nist", {})
        osv = data.get("osv", {})
        github = data.get("github", [])
        return {
            "kernel": data["kernel"],
            "system": data["system"],
            "build_date": data["build_date"],
            "nist_count": len(nist.get("vulnerabilities", [])) if isinstance(nist, dict) else 0,
            "osv_count": len(osv.get("vulns", [])) if isinstance(osv, dict) else 0,
            "github_count": len(github) if isinstance(github, list) else 0,
        }


__all__ = ["AppServices"]
