import argparse
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy.exc import SQLAlchemyError

from app_services import AppServices
from application.di import build_container
from application.dto import ReconResult
from application.services.settings_service import update_config_file
from config import DB_BACKEND
from core.entities import SandboxRun
from db.db import ThreatDB
from presentation.colors import BOLD, CYAN, DIM, sev_text_color
from presentation.formatting import (
    format_run_timestamp,
    format_timestamp,
    rec_severity,
    short_hash,
)
from presentation.terminal import ProgressBar, is_interactive, paint


def _paint_sev(severity: str) -> str:
    """Colorize a [severity] label (plain text when not a color TTY)."""
    return paint(f"[{severity}]", sev_text_color(severity))


class CLIApp:
    """CLI entrypoints for kernel audit flows."""

    def __init__(
        self,
        db: ThreatDB,
        services: AppServices | None = None,
        verbose: bool = False,
        quiet: bool = False,
    ):
        self.db = db
        self.services = services or AppServices(
            db=db, progress=ProgressBar if not quiet else None
        )
        self.verbose = verbose
        self.quiet = quiet

    def _emit(self, *args, **kwargs) -> None:
        """Print to stdout unless running in quiet mode."""
        if not self.quiet:
            print(*args, **kwargs)

    def run_local(self, save: bool = False) -> None:
        result = self.services.run_local_recon()
        if save:
            saved = self.services.store_security_recommendations(
                result.security_recommendations
            )
            self._emit(f"Saved {saved} security recommendation(s) to DB")
        self._print_local(asdict(result))

    def run_feeds(self) -> None:
        """Fetch NIST / OSV / GitHub PoC feeds for the running kernel"""
        result = self.services.run_feeds_recon()
        self._print_feeds(asdict(result))

    def run_scan(self, save: bool = False) -> None:
        result: ReconResult = self.services.run_full_recon()
        if save:
            saved = self.services.store_security_recommendations(
                result.local.security_recommendations
            )
            self._emit(f"Saved {saved} security recommendation(s) to DB")
        self._print_local(asdict(result.local))
        self._print_feeds(asdict(result.feeds))

    def run_execution_tests(self) -> None:
        """Validate kernel CVEs by sandbox-executing PoCs"""
        report = self.services.run_execution_tests()
        if self.quiet:
            return
        print(f"Kernel: {report.kernel}")
        if report.build_date:
            print(f"Build date: {report.build_date}")
        print(f"CVE hints processed: {report.cves_processed}")

        stats = report.stats
        print(
            f"Stats: total={stats.total}, "
            f"exploits={stats.with_exploits}, "
            f"in CISA KEV={stats.in_cisa_kev}"
        )
        for entry in report.entries:
            cve_id = entry.cve_id or "N/A"
            print(f" - {cve_id}: {entry.description or 'N/A'}")
            for poc in entry.pocs:
                sandbox = poc.sandbox
                url = poc.url or "N/A"
                mode = sandbox.execution_mode if sandbox else "?"
                status = "OK" if sandbox and sandbox.success else "FAIL"
                print(f"     [{mode}] {_paint_sev(status)} {url}")

    def run_report(
        self, output: str | None = None, fmt: str = "txt"
    ) -> None:
        """Build the DB-driven report, save it and print it unless quiet."""
        from report import build_report_data, emit_report

        data = build_report_data(self.db)
        path = emit_report(
            data,
            output=output,
            fmt=fmt,
            verbose=self.verbose,
            quiet=self.quiet,
        )
        self._emit(f"Report saved to {path}")

    def run_full_poc_tests(
        self, output: str | None = None, fmt: str = "txt"
    ) -> None:
        """Full scan + sandbox PoC execution + report in one run.

        Persists the host snapshot, KEV entries, security recommendations,
        tested CVEs and their sandbox runs into the DB, then emits the
        detailed report in the requested format.
        """
        result: ReconResult = self.services.run_full_recon()
        saved = self.services.store_security_recommendations(
            result.local.security_recommendations
        )
        self._emit(f"Full scan complete, saved {saved} recommendation(s) to DB")

        exec_report = self.services.run_execution_tests()
        pocs_run = sum(len(entry.pocs) for entry in exec_report.entries)
        self._emit(
            f"Execution tests complete: {exec_report.cves_processed} "
            f"CVEs, {pocs_run} PoC run(s)"
        )
        self.run_report(output=output, fmt=fmt)

    def list_kev(self) -> None:
        if self.quiet:
            return
        kev_entries = self.services.get_cisa_kev_entries(limit=50)
        print(f"\n=== CISA KEV Catalog ({len(kev_entries)} entries) ===\n")
        for idx, entry in enumerate(kev_entries[:20], 1):
            cve_id = entry.cve_id or "N/A"
            desc = (entry.description or "")[:80]
            details = self.db.get_vulnerability_with_details(cve_id)
            kev = details.cisa_kev if details is not None else None
            date = kev.date_added if kev is not None else None
            ransomware = kev.known_ransomware if kev is not None else False
            print(f"  {idx}. {cve_id}")
            print(f"     {desc}...")
            print(f"     Added: {date} | Ransomware: {ransomware}")
            print()
        if len(kev_entries) > 20:
            print(f"  ... and {len(kev_entries) - 20} more")

    def list_sandbox_runs(self) -> None:
        """Load and print sandbox runs from the DB"""
        if self.quiet:
            return
        vulns = self.db.search(has_exploit=True, limit=200)
        total = 0
        for vuln in vulns:
            cve_id: str | None = vuln.cve_id
            if not cve_id:
                continue
            for run in self.services.db.get_sandbox_runs(cve_id):
                self._print_sandbox_run(cve_id, run)
                total += 1
        print(f"Loaded {total} sandbox run(s) from DB")

    def show_settings(self) -> None:
        if self.quiet:
            return
        import config

        names = (
            "CISA_KEV_PATH",
            "LYNIS_REPORT_FILE",
            "LYNIS_LOG_FILE",
            "LINPEAS_OUT_JSON",
            "PATH_LINPEAS",
            "LES_PATH",
            "LES_REPORT_PATH",
            "POCS_BASE_PATH",
            "DB_BACKEND",
            "ISOLATION_TIMEOUT_SEC",
            "ALLOW_HOST_EXECUTION",
            "LOG_LEVEL",
        )
        print("\n=== Current settings ===\n")
        for name in names:
            print(f"  {name} = {getattr(config, name, None)}")

    @staticmethod
    def save_settings(pairs: list[str]) -> None:
        """Update config values in place """
        config_path = Path(__file__).parent / "config.py"
        updates: dict[str, str] = {}
        for pair in pairs:
            key, _, value = pair.partition("=")
            key = key.strip()
            value = value.strip()
            if not key:
                continue
            if value in ("True", "False") or value.lstrip("-").isdigit():
                updates[key] = value
            else:
                updates[key] = f'"{value}"'
        update_config_file(config_path, updates)
        print(f"Saved {len(updates)} setting(s) to config.py")
        print("Note: Some settings may require a restart to take effect")


    def _print_local(self, local: dict[str, Any]):
        if self.quiet:
            return
        build_date = local.get("build_date")
        build_date_str = (
            format_timestamp(build_date) if isinstance(build_date, int) else "N/A"
        )
        print(
            "Running local recon...\n"
            f"  Kernel: {local.get('kernel')}\n"
            f"  System: {local.get('system')}\n"
            f"  Build date: {build_date_str}\n"
        )

        recs = local.get("security_recommendations", []) or []
        print(f"Security recommendations ({len(recs)}):")
        for rec in recs:
            sev = rec_severity(rec)[0]
            test_id = rec.get("test_id", "N/A")
            field = rec.get("field_name") or rec.get("category") or ""
            desc = rec.get("description") or ""
            print(f"  {_paint_sev(sev)} {test_id} | {field}")
            if desc:
                print(f"    {desc[:120]}")
            if rec.get("expected_value") or rec.get("actual_value"):
                print(
                    f"    Expected: {rec.get('expected_value')} | "
                    f"Actual: {rec.get('actual_value')}"
                )
            suggestion = (
                rec.get("raw_data", {}).get("details")
                or rec.get("raw_data", {}).get("solution")
            )
            if suggestion:
                print(f"    Details: {suggestion[:120]}")

        les = local.get("possible_cves", []) or []
        print(f"\nLinux Exploit Suggester CVEs ({len(les)}):")
        for cve in les:
            print(f"  - {cve.get('cve_id', 'N/A')}: {cve.get('title', '') or 'N/A'}")
            if cve.get("download_urls"):
                for url in cve["download_urls"][:3]:
                    print(f"      {url}")

        selinux_bools = local.get("selinux_booleans", []) or []
        print(f"\nSELinux booleans checked ({len(selinux_bools)}):")
        hardened = [
            b for b in selinux_bools if isinstance(b, dict) and not b.get("value")
        ]
        if hardened:
            print(
                f"  {len(hardened)} hardened (off): {', '.join(b['boolean_name'] for b in hardened[:5])}"
                + (" ..." if len(hardened) > 5 else "")
            )

        proc_caps = local.get("process_capabilities", []) or []
        print(f"\nProcesses holding capabilities ({len(proc_caps)}):")
        for cap in proc_caps[:5]:
            print(
                f"  pid {cap.get('pid')} {cap.get('process_name', '')} "
                f"CapEff={cap.get('cap_effective') or '0x0'}"
            )
        if len(proc_caps) > 5:
            print(f"  ... and {len(proc_caps) - 5} more")

        file_caps = local.get("file_capabilities", []) or []
        print(f"\nPATH executables with capabilities ({len(file_caps)}):")
        for cap in file_caps:
            print(f"  {cap.get('path')} -> {cap.get('cap_effective') or ''}")

    def _print_feeds(self, feeds: dict[str, Any]):
        if self.quiet:
            return
        print("\nRunning ReconFeeds searches...")
        self._print_stats()

        findings = feeds.get("findings", []) or []
        print(f"Vulnerabilities found: {len(findings)}")
        for f in findings:
            src = f.get("source") or "?"
            cve_id = f.get("cve_id", "N/A")
            sev = f.get("severity") or "N/A"
            cvss = f.get("cvss_score")
            desc = (f.get("description") or "No summary")[:120]
            print(f"  [{src}] {cve_id} {_paint_sev(sev)} CVSS:{cvss}: {desc}")
            for ref in (f.get("references") or [])[:2]:
                print(f"      {ref}")
            if self.verbose and f.get("raw_data"):
                print(f"      raw: {str(f['raw_data'])[:160]}")

        pocs = feeds.get("pocs", []) or []
        print(f"GitHub PoCs found: {len(pocs)}")
        for poc in pocs:
            print(
                f"  - {poc.get('repo_name', 'N/A')} ({poc.get('stars', 0)} stars): "
                f"{ (poc.get('description') or 'No description')[:110] }"
            )
            if poc.get("repo_url"):
                print(f"      {poc['repo_url']}")

    def _print_stats(self):
        stats = self.services.get_statistics()
        kev_count = stats.get("in_cisa_kev", 0)
        ransomware_count = stats.get("ransomware_related", 0)
        print(f"  CISA KEV catalog: {kev_count} entries")
        if ransomware_count:
            print(f"    Ransomware related: {ransomware_count}")

    @staticmethod
    def _print_sandbox_run(cve_id: str, run: SandboxRun):
        execution_success = run.execution_success
        crashed = run.crashed
        exit_code = run.exit_code
        platform = run.sandbox_platform or "unknown"
        hash_short = short_hash(run.exploit_file_hash)
        stdout = run.stdout or ""
        stderr = run.stderr or ""

        if crashed:
            severity = "CRASH"
        elif execution_success:
            severity = "OK"
        else:
            severity = "FAIL"

        timestamp_str = format_run_timestamp(run.run_timestamp)

        print(
            f"\n  {_paint_sev(severity)} {cve_id} [{platform}] exit:{exit_code} "
            f"hash:{hash_short} {timestamp_str} stdout:{len(stdout)} stderr:{len(stderr)}"
        )

        kernel_info = run.kernel_info or {}
        if kernel_info:
            print(f"    Kernel: {kernel_info.get('uname', kernel_info.get('date', 'N/A'))}")
        modules = run.modules or []
        if modules:
            print(f"    Modules: {', '.join(modules[:10])}"
                  + ("..." if len(modules) > 10 else ""))
        processes = run.open_processes or []
        if processes:
            print(f"    Processes: {', '.join(processes[:5])}"
                  + ("..." if len(processes) > 5 else ""))
        files = run.open_files or []
        if files:
            print(f"    Files: {', '.join(files[:5])}"
                  + ("..." if len(files) > 5 else ""))
        if stdout:
            tail = "..." if len(stdout) > 500 else ""
            print(f"    STDOUT: {stdout[:500]}{tail}")
        if (stderr or crashed) and stderr:
            tail = "..." if len(stderr) > 500 else ""
            print(f"    STDERR: {stderr[:500]}{tail}")


_QUICK_START = r"""
 _  _ ____ ____ _  _ ____ _       _  _ _  _ _    _  _    ____ _  _ ___  _ ___     ___
 |_/  |___ |__/ |\ | |___ |       |  | |  | |    |\ |    |__| |  | |  \ |  |      |__]
 | \_ |___ |  \ | \| |___ |___     \/  |__| |___ | \|    |  | |__| |__/ |  |  ___ |

     Kernel Vulnerability Auditor
"""


def _print_quick_help() -> None:
    """Compact, colorized command reference for the no-Textual CLI fallback."""
    print(paint(_QUICK_START, CYAN))
    print(paint("  CLI commands (Textual TUI is not installed):", DIM))
    print()
    rows = [
        ("--full-poc-tests", "full scan + sandbox PoCs + report in one shot"),
        ("--scan", "full scan (local recon + feeds)"),
        ("--local", "local recon only (Lynis + LES + hardening)"),
        ("--feeds", "threat-intel feeds (NIST / OSV / GitHub)"),
        ("--exec-tests", "fetch + sandbox-run PoCs"),
        ("--report", "generate the vulnerability report"),
        ("-o/--output PATH", "report output path"),
        ("--format txt|json|yaml", "report output format"),
        ("-q/--quiet", "save the report without printing it"),
        ("--list-kev", "list CISA KEV entries"),
        ("--sandbox-runs", "list stored sandbox runs"),
        ("--settings", "show current configuration"),
        ("--set KEY=VALUE", "change a config value"),
        ("--save", "persist scan results to the DB"),
        ("--db orm|memory", "choose the DB backend"),
    ]
    width = max(len(flag) for flag, _ in rows)
    for flag, desc in rows:
        print(f"    {paint(flag.ljust(width), BOLD)}  {desc}")
    print()
    print("  Examples:")
    print("    python main.py --scan --save --db orm")
    print("    python main.py --full-poc-tests -o report.yaml --format yaml")
    print("    python main.py --full-poc-tests -o report.txt -q")
    print("    python main.py --report -o report.json --format json")
    print()


def build_parser() -> argparse.ArgumentParser:
    """Build the main CLI argument parser (kept separate for tests)."""
    parser = argparse.ArgumentParser(description="Kernel Vulnerability Auditor")
    parser.add_argument(
        "--local", "-l", action="store_true", help="Run local recon (Lynis + LES)"
    )
    parser.add_argument(
        "--feeds", "-f", action="store_true", help="Fetch NIST/OSV/GitHub feeds"
    )
    parser.add_argument(
        "--scan", "-s", action="store_true", help="Full scan (local + feeds)"
    )
    parser.add_argument(
        "--report", "-r", action="store_true", help="Generate full report"
    )
    parser.add_argument(
        "--exec-tests",
        action="store_true",
        help="Run execution tests (CVE => PoC -> sandbox)",
    )
    parser.add_argument(
        "--full-poc-tests",
        action="store_true",
        help="Full scan + sandbox PoC execution tests + saved report",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        metavar="PATH",
        help="Report output path (default: report_data.<format>)",
    )
    parser.add_argument(
        "--format",
        type=str,
        default=None,
        choices=["txt", "json", "yaml"],
        help="Report output format (default: txt)",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Save the report without printing it to stdout",
    )
    parser.add_argument(
        "--sandbox-runs",
        "-b",
        action="store_true",
        help="List sandbox runs stored in the DB",
    )
    parser.add_argument(
        "--list-kev",
        action="store_true",
        help="List CISA KEV entries",
    )
    parser.add_argument(
        "--settings",
        action="store_true",
        help="Show current configuration",
    )
    parser.add_argument(
        "--set",
        nargs="+",
        metavar="KEY=VALUE",
        help="Set a config value (e.g. --set LOG_LEVEL=INFO ISOLATION_TIMEOUT_SEC=30)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose output"
    )
    parser.add_argument("--save", action="store_true", help="Save results to DB")
    parser.add_argument(
        "--db",
        type=str,
        default=DB_BACKEND,
        choices=["orm", "memory"],
        help="DB backend type (sqlite or in-memory)",
    )
    return parser


def main_cli(db: ThreatDB | None = None):
    args = build_parser().parse_args()

    container = build_container(
        DB_BACKEND,
        progress=ProgressBar if not args.quiet else None,
        db=db,
    )
    resolved_db = container.get(ThreatDB)
    app = CLIApp(
        db=resolved_db,
        services=container.get(AppServices),
        verbose=args.verbose,
        quiet=args.quiet,
    )

    command_requested = any((
        args.set,
        args.settings,
        args.list_kev,
        args.sandbox_runs,
        args.exec_tests,
        args.full_poc_tests,
        args.local,
        args.feeds,
        args.scan,
        args.report,
    ))

    if not command_requested and is_interactive():
        _print_quick_help()
        return

    fmt = args.format or "txt"
    try:
        if args.set:
            app.save_settings(args.set)
        elif args.settings:
            app.show_settings()
        elif args.list_kev:
            app.list_kev()
        elif args.sandbox_runs:
            app.list_sandbox_runs()
        elif args.exec_tests:
            app.run_execution_tests()
            if args.output or args.format:
                app.run_report(output=args.output, fmt=fmt)
        elif args.local:
            app.run_local(save=args.save)
            if args.output or args.format:
                app.run_report(output=args.output, fmt=fmt)
        elif args.feeds:
            app.run_feeds()
            if args.output or args.format:
                app.run_report(output=args.output, fmt=fmt)
        elif args.scan:
            app.run_scan(save=args.save)
            if args.output or args.format:
                app.run_report(output=args.output, fmt=fmt)
        elif args.full_poc_tests:
            app.run_full_poc_tests(output=args.output, fmt=fmt)
        elif args.report:
            app.run_report(output=args.output, fmt=fmt)
        else:
            print(
                "This tool checks the practical functionality of"
                " linux kernel exploits\n"
                "Use --help for available options"
            )
    except KeyboardInterrupt:
        print("\nInterrupted", file=sys.stderr)
        sys.exit(130)
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        RuntimeError,
        SQLAlchemyError,
        httpx.HTTPError,
    ) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


__all__ = ["CLIApp", "build_parser", "main_cli"]