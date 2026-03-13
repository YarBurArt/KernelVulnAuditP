import sys
import argparse
import os
import shlex
import tempfile
import subprocess
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
try:
    import flet as ft
    GUI_E = True
except (ImportError, ModuleNotFoundError):
    GUI_E = False

from recon import LocalRecon, ReconFeeds
from db import get_db
from schemas import (
    ReconResult, LocalReconResult, FeedsReconResult,
    SecurityRecommendation
)
from isolate import Isolate
from sqxpl import GitHubExploitSearcher
from config import DB_BACKEND, ISOLATION_TIMEOUT_SEC
from core import flatten_dict_value, format_timestamp


class AppServices:
    """trying to get readable service logic"""
    def __init__(self, db: str = None):
        self.lr = LocalRecon()
        self.rf = ReconFeeds()
        self.db = db or get_db("orm")
        self.poc_searcher = GitHubExploitSearcher()
        self.isolate = Isolate(timeout=ISOLATION_TIMEOUT_SEC)
        self.isolate.allow_host_execution = True

    def store_security_recommendations(
        self, recommendations: List[dict]
    ) -> int:
        """store security recommendations in DB"""
        return self.db.bulk_insert_recommendations(recommendations)

    def run_local_recon(self, store_recs: bool = False) -> dict:
        """run local recon and optionally store recommendations"""
        kernel: str = self.lr.get_kernel_version_simple()
        build_date: str = self.lr.get_kernel_build_date(kernel)
        lynis_result: List[dict] = self.lr.get_lynis_scan_details()
        linpeas_result: dict = self.lr.get_linpeas_scan_details()
        les_result: List[dict] = self.lr.get_les_scan_details()

        if store_recs and lynis_result:
            recs = [
                SecurityRecommendation.from_dict(item).raw_data
                for item in lynis_result
            ]
            self.store_security_recommendations(recs)

        return LocalReconResult(
            system=self.lr.environment_info.get("system", ""),
            build_date=build_date, kernel_audit=lynis_result,
            kernel_lpe=linpeas_result, kernel=kernel,
            possible_cves=les_result
        )

    def run_feeds_recon(self, store_kev: bool = True) -> dict:
        """get feeds and optionally store CISA KEV data"""
        kernel: str = self.lr.get_kernel_version_simple()
        build_date: str = self.lr.get_kernel_build_date(kernel)

        # Load and store CISA KEV catalog
        if store_kev:
            self._load_and_store_kev()

        nist = self.rf.nist_search(kernel, build_date)
        osv: dict = self.rf.osv_search(kernel)
        github: dict = self.rf.github_search(kernel)

        return FeedsReconResult(nist=nist, osv=osv, github=github)

    def _load_and_store_kev(self) -> None:
        """load CISA KEV catalog and store in DB"""
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
            cve_id = kev_item.get('cveID')
            if not cve_id:
                continue

            # Parse date strings to datetime objects for ORM
            date_added = None
            due_date = None
            try:
                date_str = kev_item.get('dateAdded')
                if date_str:
                    date_added = datetime.strptime(date_str, '%Y-%m-%d')
                due_str = kev_item.get('dueDate')
                if due_str:
                    due_date = datetime.strptime(due_str, '%Y-%m-%d')
            except Exception:
                pass

            kev_data = {
                "date_added": date_added,
                "due_date": due_date,
                "required_action": kev_item.get('requiredAction'),
                "known_ransomware": kev_item.get('knownRansomwareCampaignUse') == 'Known',
                "vendor_project": kev_item.get('vendorProject'),
                "product": kev_item.get('product'),
                "notes": kev_item.get('notes', '')
            }

            vuln_data = {
                "cve_id": cve_id,
                "description": kev_item.get('shortDescription', ''),
                "in_cisa_kev": True,
                "sources": ["CISA_KEV"]
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
        """ local + online recon in to dict object"""
        local_r = self.run_local_recon()
        feeds_r = self.run_feeds_recon()
        return ReconResult(local=local_r, feeds=feeds_r)

    def run_execution_tests(self) -> dict:
        """ full validate kernel CVEs by sandbox executing PoC """
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
            repos = self.poc_searcher.search_repositories(
                cve_id, max_results=3)
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
        self, cve_id: str, hint: Dict[str, Any],
        context: Dict[str, Any] | None = None
    ) -> Dict[str, Any] | None:
        metadata = self.rf.get_cve_details(cve_id) or {}
        description = (
            hint.get("details") or hint.get("title")
            or metadata.get("description")
        )
        severity = hint.get("severity") or metadata.get("severity")
        raw_source = hint.get("source", "linpeas")
        normalized_source = (
            "LES" if raw_source == "les" else raw_source.upper()
        )
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
            self.db.add_reference(
                cve_id, metadata["nist_url"],
                ref_type="ADVISORY", source="NIST"
            )
        return {
            "cve_id": cve_id,
            "description": description,
            "cvss_v3_score": metadata.get("cvss_v3_score"),
            "severity": severity,
            "sources": [normalized_source],
        }

    def _record_poc_for_cve(
        self, cve_id: str, poc: Dict[str, Any]
    ) -> Dict[str, Any] | None:
        exploit_meta = {
            "exploit_type": "PoC",
            "source": "GitHub",
            "url": poc.get("url"),
            "verified": True,
        }
        self.db.add_exploit(cve_id, exploit_meta)
        if poc.get("url"):
            self.db.add_reference(
                cve_id, poc["url"], ref_type="EXPLOIT", source="GitHub"
            )
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

    def _build_runner_script(
        self, repo_path: Path, command: str
    ) -> Path:
        fd, path = tempfile.mkstemp(prefix="kernaudit-run-", suffix=".sh")
        os.close(fd)
        script = Path(path)
        script.write_text(
            "#!/bin/sh\n"
            "set -e\n"
            f"cd {shlex.quote(str(repo_path))}\n"
            f"{command}\n",
            encoding="utf-8"
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

    def _store_sandbox_run(
        self, cve_id: str, result, command: str
    ) -> None:
        xpl_hash = result.logs.get(
            "exploit_hash") if hasattr(result, "logs") else ""
        open_fproc = result.logs.get(
            "open_processes", []) if hasattr(result, "logs") else []
        open_f = result.logs.get(
            "open_files", []) if hasattr(result, "logs") else []
        cmd_log = result.logs.get(
            "command") if hasattr(result, "logs") else None
        sandbox_data = {
            "sandbox_platform": getattr(result, "execution_mode", "unknown"),
            "run_timestamp": datetime.now(timezone.utc),
            "exploit_file_hash": xpl_hash,
            "execution_success": getattr(result, "returncode", 1) == 0,
            "exit_code": getattr(result, "returncode", -1),
            "stdout": getattr(result, "stdout", ""),
            "stderr": getattr(result, "stderr", ""),
            "stdin": command, "open_processes": open_fproc,
            "open_files": open_f, "notes": cmd_log,
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
        stats['security_recommendations'] = rec_stats
        return stats

    def get_security_recommendations(
        self, category: str = None, status: str = None,
        limit: int = 100
    ) -> List[dict]:
        """Get security recommendations with optional filters"""
        return self.db.get_security_recommendations(
            category=category, status=status, limit=limit
        )

    def get_cisa_kev_entries(self, limit: int = 100) -> List[dict]:
        """Get CISA KEV entries from DB"""
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
            "nist_count": len(
                nist.get('vulnerabilities', [])
            ) if isinstance(nist, dict) else 0,
            "osv_count": len(
                osv.get('vulns', [])
            ) if isinstance(osv, dict) else 0,
            "github_count": len(
                github
            ) if isinstance(github, list) else 0,
        }


class GUIApp:
    """GUI version"""

    def __init__(self, db=None):
        self.services = AppServices(db=db)
        self.log = None
        self.page = None

    def run(self):
        ft.run(main=self._main_page)

    def _main_page(self, page: ft.Page):
        self.page = page
        page.title = "Kernel Vulnerability Auditor"
        page.window_width = 650
        page.window_height = 600
        page.theme_mode = ft.ThemeMode.DARK
        page.padding = 20
        page.spacing = 15

        # Set button style - less rounded corners
        page.theme = ft.Theme(
            button_theme=ft.ButtonTheme(
                style=ft.ButtonStyle(
                    shape=ft.RoundedRectangleBorder(radius=4)
                )
            )
        )

        self.log = ft.Column(scroll=ft.ScrollMode.AUTO)
        self._create_nav_bar()
        page.add(ft.Text(
            "Welcome to Kernel Vulnerability Auditor",
            size=24
        ))

    def _toggle_theme(self, _):
        # theme fix
        if self.page.theme_mode == ft.ThemeMode.DARK:
            self.page.theme_mode = ft.ThemeMode.LIGHT
        else:
            self.page.theme_mode = ft.ThemeMode.DARK
        self.page.update()

    def _create_nav_bar(self):
        is_dark = self.page.theme_mode == ft.ThemeMode.DARK
        theme_icon = ft.icons.Icons.LIGHT_MODE  \
            if is_dark else ft.icons.Icons.DARK_MODE

        nav_bar = ft.Row([
            ft.Button("Scan", on_click=self._navigate_to_scan),
            ft.Button("Report", on_click=self._navigate_to_report),
            ft.Container(expand=True),
            ft.Button(
                content=ft.Icon(theme_icon, size=20),
                on_click=self._toggle_theme
            )
        ])
        self.page.add(nav_bar)

    def _navigate_to_scan(self, _):
        self.page.clean()
        self._create_nav_bar()
        self.page.add(ft.Text("Running vulnerability scan..."))
        log_container = ft.Container(
            content=self.log, height=360, padding=10,
            expand=True, alignment=ft.Alignment.CENTER_LEFT,
        )
        self.page.add(log_container)
        self.page.add(ft.Row([
            ft.Button("Start Local", on_click=self._start_local),
            ft.Button("Recon ti feeds", on_click=self._start_feeds),
            ft.Button("Full Recon", on_click=self._start_recon),
            ft.Button(
                "Run Execution Tests", on_click=self._run_execution_tests),
            ft.Button("Save to DB", on_click=self._save_to_db),
        ], alignment=ft.MainAxisAlignment.START, spacing=10))
        self.page.update()

    def _navigate_to_report(self, _):
        """generate and show report, try streamlit then CLI"""
        self.page.clean()
        self._create_nav_bar()
        self.page.add(ft.Text("Generating vulnerability report..."))
        
        try:
            # try to run streamlit report
            report_path = Path(__file__).parent / "report.py"
            if not report_path.exists():
                raise FileNotFoundError("report.py not found")
            
            # check if streamlit is available
            streamlit_available = False
            try:
                import streamlit
                streamlit_available = True
            except (ImportError, ModuleNotFoundError):
                pass
            
            if streamlit_available:
                # try to launch streamlit
                self._append_log("Launching Streamlit report...")
                try:
                    # run streamlit as subprocess
                    proc = subprocess.Popen(
                        [sys.executable, "-m", "streamlit", "run", str(report_path)],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    self._append_log(
                        "Streamlit report launched in browser at http://localhost:8501")
                    self._append_log(
                        "Close this window to stop the report server")
                except Exception as e:
                    self._append_log(f"Streamlit launch failed: {e}")
                    self._append_log("Falling back to CLI report...")
                    self._run_cli_report()
            else:
                # no streamlit, run CLI
                self._append_log("Streamlit not available, running CLI report...")
                self._run_cli_report()
                
        except Exception as e:
            self._append_log(f"Report error: {e}")
            self._run_cli_report()
        
        self.page.update()

    def _run_cli_report(self):
        """run report in CLI mode and show output"""
        try:
            from report import build_report_data, CLIReportRenderer
            from db import get_db
            
            db = get_db("orm")
            data = build_report_data(db)
            db.close()
            
            # render to CLI-style output
            renderer = CLIReportRenderer(data, verbose=True)
            output = renderer._build_full_report()
            self._append_log(output)
            self._append_log("Report generated (CLI mode)")
        except Exception as e:
            self._append_log(f"CLI report error: {e}")
            import traceback
            self._append_log(traceback.format_exc())

    def _start_local(self, _):
        self.log.controls.clear()
        self._append_log("Starting local recon...")
        try:
            result_dt: LocalReconResult = self.services.run_local_recon()
            result = asdict(result_dt)
            if result['build_date'] is not None:
                result['build_date'] = format_timestamp(result['build_date'])
            self._append_log(result)
            self._append_log("Local recon finished.")
        except Exception as e:
            self._append_log(f"Local recon error: {e}")

    def _start_feeds(self, _):
        self.log.controls.clear()
        self._append_log("Starting TI feeds recon...")
        try:
            result = self.services.run_feeds_recon()
            self._append_log(asdict(result))
            self._append_log("Feeds recon finished.")
        except Exception as e:
            self._append_log(f"Feeds recon error: {e}")

    def _start_recon(self, _):
        self.log.controls.clear()
        self._append_log("Starting TI feeds recon (local → feeds)...")
        try:
            result = self.services.run_full_recon()
            self._append_log(asdict(result))
            self._append_log("Recon feeds finished.")
        except Exception as e:
            self._append_log(f"Recon feeds error: {e}")

    def _run_execution_tests(self, _):
        self.log.controls.clear()
        self._append_log("Running execution tests (LES → PoC → sandbox)...")
        try:
            report = self.services.run_execution_tests()
            self._append_log(report)
            self._append_log("Execution tests finished.")
        except Exception as e:
            self._append_log(f"Execution tests error: {e}")

    def _save_to_db(self, _):
        """Save current recon results to DB."""
        # TODO: call services.save_recon_results() and log count
        pass

    def _get_cell_text(self, v: Any) -> str:
        return flatten_dict_value(v)

    def _is_url(self, text: str) -> bool:
        """check if text is a URL"""
        if not isinstance(text, str):
            return False
        return text.startswith(('http://', 'https://')) and len(text) > 8

    def _make_link(self, url: str) -> ft.Container:
        """create clickable link using Container with ink"""
        def open_url(e):
            if self.page:
                self.page.launch_url(url)
        return ft.Container(
            content=ft.Text(
                url, selectable=True, text_align=ft.TextAlign.LEFT,
                color=ft.Colors.BLUE,
                style=ft.TextStyle(decoration=ft.TextDecoration.UNDERLINE),
            ),
            ink=True,
            on_click=open_url,  # FIXME
        )

    def _build_control(self, data):
        """dict[dict, ...] render based on data type"""
        if isinstance(data, dict):
            return self._build_dict(data)

        if isinstance(data, list):
            return self._build_list(data)

        return self._build_value(data)

    def _build_value(self, value):
        """ render values like str, int, bool, etc"""
        return ft.Text(
            str(value), selectable=True,
            text_align=ft.TextAlign.LEFT,
        )

    def _build_dict(self, data: dict):
        """ render dict as expansion tiles"""
        tiles = []
        for key, value in data.items():
            tile = ft.ExpansionTile(title=ft.Text(
                str(key),
                weight=ft.FontWeight.BOLD,
                text_align=ft.TextAlign.LEFT,
            ), controls=[self._build_control(value)],)
            tiles.append(tile)

        return ft.Column(controls=tiles, tight=True, expand=True,)

    def _build_list(self, data: list):
        """ list to flet list, or list[dict] to DataTable"""
        if not data:
            return self._build_value("[]")
        # List of dictionaries → table
        if all(isinstance(item, dict) for item in data):
            return self._build_table(data)
        # recursive parse dict in dict
        return ft.Column(
            controls=[self._build_control(item) for item in data],
            tight=True,
        )

    def _build_table(self, data: list[dict]):
        """dict to flet table, URLs clickable"""
        keys = sorted({k for row in data for k in row.keys()})

        columns = [
            ft.DataColumn(label=ft.Text(
                    key, weight=ft.FontWeight.BOLD,
                    text_align=ft.TextAlign.LEFT,
                ), numeric=False,
            ) for key in keys]
        rows = []
        for row in data:
            cells = []
            for key in keys:
                val = row.get(key, "")
                # check for URL
                if self._is_url(val):
                    cells.append(ft.DataCell(self._make_link(val)))
                else:
                    cells.append(ft.DataCell(ft.Text(
                        self._get_cell_text(val), selectable=True,
                        text_align=ft.TextAlign.LEFT,
                    )))
            rows.append(ft.DataRow(cells=cells))

        return ft.DataTable(
            columns=columns, rows=rows, expand=True, column_spacing=20,
        )

    def _append_log(self, item):
        control = self._build_control(item)
        self.log.controls.append(control)
        self.page.update()


class CLIApp:
    """CLI version"""

    def __init__(self, verbose: bool = False, db=None):
        self.services = AppServices(db=db)
        self.verbose = verbose

    def run_scan(
        self, kern_cve_id_ver: str = "6.1.0", save: bool = False
    ) -> None:
        # TODO: check cache first
        result = self.services.run_full_recon(kern_cve_id_ver)
        self._print_scan_result(asdict(result))
        # TODO: save to DB if requested

    def run_report(self, cve_id: str = "6.1.0"):
        report = self.services.generate_report(cve_id)
        stats = self.services.get_statistics()
        kev_count = stats.get('in_cisa_kev', 0)

        print("\n=== RW intermediate results ===\n"
              f"Kernel: {report['kernel']}\n"
              f"System: {report['system']}\n"
              f"Build Date: {report['build_date']}\n\n"
              "Vulnerabilities:\n"
              f"  NIST: {report['nist_count']}\n"
              f"  OSV: {report['osv_count']}\n"
              f"  GitHub PoC: {report['github_count']}\n"
              f"  CISA KEV: {kev_count}\n\n"
              "Report generated.")

    def _print_scan_result(self, result: dict):
        print("Running local recon...\n"
              f"  Kernel: {result['kernel']}\n"
              f"  System: {result['system']}\n"
              f"  Build date: {result['build_date']}\n")

        print("Running ReconFeeds searches...")

        # Print KEV stats
        stats = self.services.get_statistics()
        kev_count = stats.get('in_cisa_kev', 0)
        ransomware_count = stats.get('ransomware_related', 0)
        print(f"  CISA KEV catalog: {kev_count} entries")
        if ransomware_count:
            print(f"    Ransomware related: {ransomware_count}")

        nist = result.get("nist")
        if isinstance(nist, dict):
            count = len(nist.get('vulnerabilities', []))
            print(f"  NIST vulnerabilities found: {count}")
            if self.verbose and nist:
                for vuln in nist.get('vulnerabilities', [])[:5]:
                    cve_id = vuln.get('cve', {}).get('cveId', 'N/A')
                    desc = vuln.get('cve', {}).get(
                        'descriptions', [{}]
                    )[0].get('value', 'N/A')[:100]
                    print(f"    - {cve_id}: {desc}...")
        else:
            print(f"  NIST: {nist}")

        osv = result.get("osv")
        if isinstance(osv, dict):
            count = len(osv.get('vulns', []))
            print(f"  OSV vulnerabilities found: {count}")
            if self.verbose and osv:
                for vuln in osv.get('vulns', [])[:5]:
                    vuln_id = vuln.get('id', 'N/A')
                    summary = vuln.get('summary', 'N/A')[:100]
                    print(f"    - {vuln_id}: {summary}...")
        else:
            print(f"  OSV: {osv}")

        github = result.get("github")
        if isinstance(github, list):
            print(f"  GitHub repos found: {len(github)}")
            if self.verbose and github:
                for repo in github[:5]:
                    name = repo.get('full_name', 'N/A')
                    stars = repo.get('stars', 0)
                    desc = repo.get('description', 'N/A') or 'No description'
                    print(f"    - {name} ({stars} stars): {desc[:80]}...")
        else:
            print(f"  GitHub: {github}")


def main_cli():
    parser = argparse.ArgumentParser(
        description="Kernel Vulnerability Auditor")
    parser.add_argument(
        "--scan", "-s", action="store_true", help="Perform vulnerability scan")
    parser.add_argument(
        "--report", "-r", action="store_true", help="Generate report")
    parser.add_argument(
        "--exec-tests", action="store_true",
        help="Run execution tests (CVE => PoC -> sandbox)")
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose output")
    parser.add_argument(
        "--cve", type=str, default="6.1.0",
        help="CVE ID for GitHub PoC search by kernel version")
    parser.add_argument(
        "--save", action="store_true", help="Save results to DB")
    parser.add_argument(
        "--list-kev", action="store_true", help="List CISA KEV entries")
    parser.add_argument(
        "--db", type=str, default="simple",
        choices=["simple", "orm", "memory"],
        help="DB backend type and way, sqlite, redis, or just in memory")

    args = parser.parse_args()

    db = get_db("memory")  # faster for test, for real better orm
    app = CLIApp(verbose=args.verbose, db=db)

    if args.list_kev:
        kev_entries = app.services.get_cisa_kev_entries(limit=50)
        print(f"\n=== CISA KEV Catalog ({len(kev_entries)} entries) ===\n")
        for idx, entry in enumerate(kev_entries[:20], 1):
            cve_id = entry.get('cve_id', 'N/A')
            desc = entry.get('description', '')[:80]
            date = entry.get('cisa_kev', {}).get('date_added', 'N/A')
            ransomware = entry.get('cisa_kev', {}).get('known_ransomware', False)
            print(f"  {idx}. {cve_id}")
            print(f"     {desc}...")
            print(f"     Added: {date} | Ransomware: {ransomware}")
            print()
        if len(kev_entries) > 20:
            print(f"  ... and {len(kev_entries) - 20} more")
    elif args.exec_tests:
        report = app.run_execution_tests()
        print(f"Kernel: {report['kernel']}")
        if report.get("build_date"):
            print(f"Build date: {report['build_date']}")
        print(f"CVE hints processed: {report.get('cves_processed', 0)}")
        stats = report.get("stats", {})
        print(f"Stats: total={stats.get('total')}, "
              f"exploits={stats.get('with_exploits')}, "
              f"in CISA KEV={stats.get('in_cisa_kev')}")
        entries = report.get("entries", [])[:5]
        for entry in entries:
            print(f" - {entry['cve_id']}: {entry.get('description', 'N/A')}")
        if len(report.get("entries", [])) > len(entries):
            print(f" ...({len(report['entries']) - len(entries)} more CVEs")
    elif args.scan:
        app.run_scan(args.cve, save=args.save)
    elif args.report:
        app.run_report(args.cve)
    else:
        print("This tool checks the practical functionality of"
              " linux kernel exploits\n"
              "Use --help for available options")

    # TODO: close DB connections after report cuz in memory


def main():
    cli_flag = "--cli" in sys.argv
    gui_flag = "--gui" in sys.argv and GUI_E

    # to downstream arg parsing isn't affected
    for flag in ("--cli", "--gui"):
        if flag in sys.argv:
            sys.argv.remove(flag)

    db = get_db(DB_BACKEND)
    if cli_flag:
        main_cli()
    elif gui_flag:
        try:
            GUIApp(db=db).run()
        finally:
            db.close()
    elif GUI_E:
        GUIApp(db=db).run()
    else:
        main_cli()


if __name__ == "__main__":
    main()
