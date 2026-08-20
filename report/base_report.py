import json
import logging
import re
import sys
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy.exc import SQLAlchemyError

from log_conf import LOG_FILE
from presentation.formatting import format_timestamp
from report.diff import (
    build_diff,
    collect_sandbox_modules,
    host_module_set,
    load_selinux_params,
)
from report.export import REPORT_FORMATS, emit_report, save_report

logger = logging.getLogger(f"kernel_audit.{__name__}")

try:
    import streamlit  # type: ignore[import-not-found]  # noqa: F401

    STREAMLIT_AVAILABLE = True
except ImportError:
    STREAMLIT_AVAILABLE = False

from db import get_db
from recon.local_target_recon import LocalRecon
from report.streamlit_rep import StreamlitReportRenderer


def format_report(data: dict) -> dict:
    """Shrink raw scan/feed data down to the fields the report needs,
    tallying finding sources (NIST vs OSV) so the header can show coverage."""
    feeds = data.get("feeds", {}) or {}
    findings = feeds.get("findings", [])
    pocs = feeds.get("pocs", [])

    nist_count = 0
    osv_count = 0

    for f in findings:
        src = (f.get("source") or "").upper()
        if src == "NIST":
            nist_count += 1
        elif src == "OSV":
            osv_count += 1

    return {
        "kernel": data.get("kernel", ""),
        "system": data.get("system", ""),
        "build_date": data.get("build_date", 0),
        "nist_count": nist_count,
        "osv_count": osv_count,
        "github_count": len(pocs),
    }


def save_report_json(data: dict[str, Any], filepath: str = "report_data.json") -> None:
    """save report data to JSON file"""
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    print(f"Report saved to {filepath}")


def load_report_json(filepath: str = "report_data.json") -> dict[str, Any] | None:
    """load report data from JSON file"""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return None


def fetch_all_vulnerabilities(db) -> list[dict[str, Any]]:
    """fetch all vulnerabilities with full details"""
    all_vulns = []
    offset = 0
    chunk = 50
    while True:
        batch = db.search(limit=chunk, offset=offset)
        if not batch:
            break
        for vuln in batch:
            full = db.get_vulnerability_with_details(vuln.cve_id)
            if full:
                all_vulns.append(asdict(full))
        if len(batch) < chunk:
            break
        offset += chunk
    return all_vulns


def build_kev_data(db) -> list[dict[str, Any]]:
    """build KEV data list from DB"""
    kev_list = db.get_cisa_kev_list(limit=100)
    kev_data = []
    for vuln in kev_list:
        kev_data.append(
            {
                "cve_id": vuln.cve_id,
                "description": (vuln.description or "")[:100],
                "cvss_v3_score": vuln.cvss_v3_score,
                "severity": vuln.severity,
                "criticality_score": vuln.criticality_score,
            }
        )
    return kev_data


def build_sandbox_runs(db) -> list[dict[str, Any]]:
    """build sandbox runs list from DB"""
    runs = []
    critical_vulns = db.get_critical(limit=5)
    for idx, vuln in enumerate(critical_vulns, 1):
        cve_id = vuln.cve_id
        sandbox_runs = db.get_sandbox_runs(cve_id)
        for run in sandbox_runs:
            runs.append(
                {
                    **asdict(run),
                    "id": idx,
                    "status": (
                        "SUCCESS" if run.execution_success else "MAYBE"
                    ),
                    "description": f"PoC test for {cve_id}",
                }
            )
    return runs


def build_security_recommendations(db) -> list[dict[str, Any]]:
    """build security recommendations list from DB"""
    return [asdict(r) for r in db.get_security_recommendations(limit=200)]


_LOG_LINE_RE = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \| \[\w+\s*\]"
)
# log markers that begin a scan/execution session
_SESSION_START_MARKERS = (
    "local recon started in context",
    "execution tests started in context",
)


def get_scan_times(log_file: Path = LOG_FILE) -> tuple[str | None, str | None]:
    """Derive the latest scan's start/completed times from the info logs"""
    started: str | None = None
    completed: str | None = None
    try:
        with open(log_file, encoding="utf-8") as f:
            for line in f:
                m = _LOG_LINE_RE.match(line)
                if not m:
                    continue
                ts = m.group("ts")
                lowered = line.lower()
                if any(mk in lowered for mk in _SESSION_START_MARKERS):
                    started = ts
                if started is not None:
                    completed = ts
    except FileNotFoundError:
        return None, None
    return started, completed


def get_kernel_info(lr: LocalRecon | None = None) -> dict[str, str | None] | dict[str, str]:
    """get kernel info from LocalRecon"""
    if lr is None:
        lr = LocalRecon()
    kernel: str = lr.get_kernel_version_simple()
    build_date: int = lr.get_kernel_build_date(kernel)
    system: str = lr.environment_info.get("distribution", "Linux like")

    latest = "N/A"
    import httpx  # only needed here
    try:

        resp = httpx.get(
            "https://www.kernel.org/releases.json", timeout=10.0
        ).json()
        latest = resp["latest_stable"]["version"]
    except (httpx.HTTPError, ValueError, KeyError, TypeError) as e:
        logger.warning("fetch latest kernel version failed: %s", e)

    p_build = format_timestamp(build_date, "%Y-%m-%d %H:%M:%S")

    return {
        "kernel_version": kernel,
        "distribution": system,
        "latest_version": latest,
        "build_date": p_build,
    }


def sort_vulnerabilities(vulns: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """sort vulns: with sandbox runs first
    (by year desc, crit desc), then without (by year desc, crit desc)"""
    with_runs = []
    without_runs = []

    for v in vulns:
        if v.get("sandbox_runs") and len(v["sandbox_runs"]) > 0:
            with_runs.append(v)
        else:
            without_runs.append(v)

    def sort_key(v):
        # Extract YYYY cve
        cve_id = v.get("cve_id", "")
        year = 0
        if cve_id.startswith("CVE-"):
            try:
                year = int(cve_id.split("-")[1])
            except (ValueError, IndexError):
                year = 0
        crit = v.get("criticality_score", 0) or 0
        # Sort: -year (desc), -crit (desc)
        return -year, -crit

    with_runs_sorted = sorted(with_runs, key=sort_key)
    without_runs_sorted = sorted(without_runs, key=sort_key)

    return with_runs_sorted + without_runs_sorted


def build_report_data(db=None) -> dict[str, Any]:
    """build report data structure from DB (no live host recon).

    The report is a pure DB read: kernel modules, parameters and the
    capability / SELinux recommendations come from the stored host snapshot.
    """
    if db is None:
        db = get_db("orm")

    kernel_info = get_kernel_info()
    vulns = fetch_all_vulnerabilities(db)
    sorted_vulns = sort_vulnerabilities(vulns)
    runs = build_sandbox_runs(db)
    security_recs = build_security_recommendations(db)

    started, completed = get_scan_times()
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S %Z")

    # diff sources: purely stored data — recommendations and host snapshot.
    # SELinux/capabilities are recomputed from the host snapshot
    # + static files with recommended (by RedHat) values.

    host_info_dict = None
    host_info = None
    try:
        host_info = db.get_latest_host_info()
    except SQLAlchemyError:
        logger.exception("report host info fetch failed")
    if host_info is not None:
        host_info_dict = host_info.to_dict()

    # Kernel params: stored security recommendations (category kernel) already
    # carry expected + actual captured at scan time.
    param_recs = [
        r
        for r in security_recs
        if str(r.get("category", "")).lower() == "kernel"
    ]

    host_modules = host_module_set(host_info_dict)

    sandbox_modules = collect_sandbox_modules(
        {"runs": runs, "vulnerabilities": sorted_vulns}
    )
    diff = build_diff(
        sandbox_modules,
        host_modules,
        param_recs,
        host_info=host_info_dict,
        selinux_params=load_selinux_params(),
    )

    return {
        "started": started or now,
        "completed": completed or now,
        "kernel_version": kernel_info["kernel_version"],
        "distribution": kernel_info["distribution"],
        "latest_version": kernel_info["latest_version"],
        "kev_data": build_kev_data(db),
        "runs": runs,
        "statistics": asdict(db.get_statistics()),
        "vulnerabilities": sorted_vulns,
        "security_recommendations": security_recs,
        "host_info": host_info_dict,
        "diff": diff,
    }


def main(
    verbose: bool = False,
    save_json: bool = False,
    filepath: str | None = None,
    force_cli: bool = False,
    fmt: str = "txt",
    quiet: bool = False,
):
    """main entry point for report generation"""
    db = get_db("orm")

    try:
        data = build_report_data(db)

        if STREAMLIT_AVAILABLE and not force_cli:
            if save_json:
                save_report_json(data, filepath or "report_data.json")
            StreamlitReportRenderer(data).render()
        else:
            emit_report(
                data,
                output=filepath,
                fmt=fmt,
                verbose=verbose,
                quiet=quiet,
            )

    finally:
        db.close()


def main_cli():
    """CLI argument parsing for report"""
    import argparse

    parser = argparse.ArgumentParser(description="Generate Kernel Vulnerability Report")
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose output"
    )
    parser.add_argument(
        "--save", "-s", action="store_true", help="Save report to file"
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="Output report path (default: report_data.<format>)",
    )
    parser.add_argument(
        "--format",
        type=str,
        default="txt",
        choices=list(REPORT_FORMATS),
        help=f"Report output format (default: txt) {list(REPORT_FORMATS)}",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Save the report without printing it to stdout",
    )
    parser.add_argument(
        "--load",
        "-l",
        type=str,
        default=None,
        help="Load and display existing report from JSON file",
    )
    parser.add_argument(
        "--cli",
        action="store_true",
        help="Force CLI output (default when streamlit is not installed)",
    )

    args = parser.parse_args()

    if args.load:
        data = load_report_json(args.load)
        if data is None:
            print(f"Error: Could not load report from {args.load}")
            sys.exit(1)
        if STREAMLIT_AVAILABLE and not args.cli:
            StreamlitReportRenderer(data).render()
            if args.output:
                save_report(data, args.output, args.format)
        else:
            emit_report(
                data,
                output=args.output,
                fmt=args.format,
                verbose=args.verbose,
                quiet=args.quiet,
            )
    else:
        main(
            verbose=args.verbose,
            save_json=args.save,
            filepath=args.output,
            force_cli=args.cli,
            fmt=args.format,
            quiet=args.quiet,
        )


if __name__ == "__main__":
    if STREAMLIT_AVAILABLE and len(sys.argv) == 1:
        main()
    else:
        main_cli()
