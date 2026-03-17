import sys
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    import streamlit
    STREAMLIT_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    STREAMLIT_AVAILABLE = False

from db import get_db
from recon import LocalRecon
from report_streamlit import StreamlitReportRenderer
from report_cli import CLIReportRenderer


def save_report_json(
    data: Dict[str, Any], filepath: str = "report_data.json"
) -> None:
    """save report data to JSON file"""
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    print(f"Report saved to {filepath}")


def load_report_json(
    filepath: str = "report_data.json"
) -> Optional[Dict[str, Any]]:
    """load report data from JSON file"""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return None


def fetch_all_vulnerabilities(db) -> List[Dict[str, Any]]:
    """fetch all vulnerabilities with full details"""
    all_vulns = []
    offset = 0
    chunk = 50
    while True:
        batch = db.search(limit=chunk, offset=offset)
        if not batch:
            break
        for vuln in batch:
            full = db.get_vulnerability_with_details(vuln["cve_id"])
            if full:
                all_vulns.append(full)
        if len(batch) < chunk:
            break
        offset += chunk
    return all_vulns


def build_kev_data(db) -> List[Dict[str, Any]]:
    """build KEV data list from DB"""
    kev_list = db.get_cisa_kev_list(limit=100)
    kev_data = []
    for vuln in kev_list:
        kev_data.append({
            "cve_id": vuln.get("cve_id"),
            "description": vuln.get("description", "")[:100],
            "cvss_v3_score": vuln.get("cvss_v3_score"),
            "severity": vuln.get("severity"),
            "criticality_score": vuln.get("criticality_score"),
        })
    return kev_data


def build_sandbox_runs(db) -> List[Dict[str, Any]]:
    """build sandbox runs list from DB"""
    runs = []
    critical_vulns = db.get_critical(limit=5)
    for idx, vuln in enumerate(critical_vulns, 1):
        cve_id = vuln.get("cve_id")
        sandbox_runs = db.get_sandbox_runs(cve_id)
        for run in sandbox_runs:
            runs.append({
                "id": idx,
                "status": (
                    "SUCCESS" if run.get("execution_success") else "MAYBE"
                ),
                "description": f"PoC test for {cve_id}",
                "stdout": run.get("stdout", "")[:500],
                "stderr": run.get("stderr", "")[:500],
            })
    return runs


def build_security_recommendations(db) -> List[Dict[str, Any]]:
    """build security recommendations list from DB"""
    return db.get_security_recommendations(limit=200)


def get_kernel_info() -> Dict[str, str]:
    """get kernel info from LocalRecon"""
    try:
        lr = LocalRecon()
        kernel = lr.get_kernel_version_simple()
        build_date = lr.get_kernel_build_date(kernel)
        system = lr.environment_info.get("system", "Linux")

        # retry get version FIXME
        latest = "Unknown"
        try:
            import httpx
            major = kernel.split('.')[0] if kernel else '6'
            resp = httpx.get(
                f"https://cdn.kernel.org/pub/linux/kernel/v{major}.x/"
            )
            if resp.status_code == 200:
                import re
                versions = re.findall(
                    r'change-log-(\d+\.\d+\.\d+)', resp.text, re.IGNORECASE
                )
                if versions:
                    latest = max(versions)
        except Exception:
            pass

        p_build = None
        if build_date:
            p_build = datetime.fromtimestamp(
                build_date, tz=timezone.utc
            ).strftime('%Y-%m-%d %H:%M:%S')

        return {
            "kernel_version": kernel,
            "distribution": system,
            "latest_version": latest,
            "build_date": p_build
        }
    except Exception:
        return {
            "kernel_version": "Unknown",
            "distribution": "Unknown",
            "latest_version": "Unknown",
            "build_date": None
        }


def sort_vulnerabilities(
    vulns: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """sort vulns: with sandbox runs first
    (by year desc, crit desc), then without (by year desc, crit desc)"""
    with_runs = []
    without_runs = []

    for v in vulns:
        if v.get('sandbox_runs') and len(v['sandbox_runs']) > 0:
            with_runs.append(v)
        else:
            without_runs.append(v)

    def sort_key(v):
        # Extract YYYY cve
        cve_id = v.get('cve_id', '')
        year = 0
        if cve_id.startswith('CVE-'):
            try:
                year = int(cve_id.split('-')[1])
            except (ValueError, IndexError):
                year = 0
        crit = v.get('criticality_score', 0) or 0
        # Sort: -year (desc), -crit (desc)
        return (-year, -crit)

    with_runs_sorted = sorted(with_runs, key=sort_key)
    without_runs_sorted = sorted(without_runs, key=sort_key)

    return with_runs_sorted + without_runs_sorted


def build_report_data(db=None) -> Dict[str, Any]:
    """build report data structure from DB"""
    if db is None:
        db = get_db("orm")

    kernel_info = get_kernel_info()
    vulns = fetch_all_vulnerabilities(db)
    sorted_vulns = sort_vulnerabilities(vulns)

    return {
        "started": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z"),
        "completed": datetime.now(timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S %Z"
        ),
        "kernel_version": kernel_info["kernel_version"],
        "distribution": kernel_info["distribution"],
        "latest_version": kernel_info["latest_version"],
        "kev_data": build_kev_data(db),
        "runs": build_sandbox_runs(db),
        "statistics": db.get_statistics(),
        "vulnerabilities": sorted_vulns,
        "security_recommendations": build_security_recommendations(db),
    }


def main(
    verbose: bool = False,
    save_json: bool = False,
    filepath: str = "report_data.json"
):
    """main entry point for report generation"""
    db = get_db("orm")

    try:
        data = build_report_data(db)

        if STREAMLIT_AVAILABLE:
            if save_json:
                save_report_json(data, filepath)
            StreamlitReportRenderer(data).render()
        else:
            CLIReportRenderer(data, verbose=verbose).render()
            save_report_json(data, filepath)

    finally:
        db.close()


def main_cli():
    """CLI argument parsing for report"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate Kernel Vulnerability Report"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--save", "-s", action="store_true",
        help="Save report to JSON file"
    )
    parser.add_argument(
        "--output", "-o", type=str, default="report_data.json",
        help="Output JSON file path (default: report_data.json)"
    )
    parser.add_argument(
        "--load", "-l", type=str, default=None,
        help="Load and display existing report from JSON file"
    )

    args = parser.parse_args()

    if args.load:
        data = load_report_json(args.load)
        if data is None:
            print(f"Error: Could not load report from {args.load}")
            sys.exit(1)
        if STREAMLIT_AVAILABLE:
            StreamlitReportRenderer(data).render()
        else:
            CLIReportRenderer(data, verbose=args.verbose).render()
    else:
        main(
            verbose=args.verbose, save_json=args.save,
            filepath=args.output
        )


if __name__ == "__main__":
    if STREAMLIT_AVAILABLE and len(sys.argv) == 1:
        main()
    else:
        main_cli()
