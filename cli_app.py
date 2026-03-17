import argparse
from dataclasses import asdict

from app_services import AppServices
from config import DB_BACKEND
from db import get_db


class CLIApp:
    """CLI entrypoints for kernel audit flows."""

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
        kev_count = stats.get("in_cisa_kev", 0)

        print(
            "\n=== RW intermediate results ===\n"
            f"Kernel: {report['kernel']}\n"
            f"System: {report['system']}\n"
            f"Build Date: {report['build_date']}\n\n"
            "Vulnerabilities:\n"
            f"  NIST: {report['nist_count']}\n"
            f"  OSV: {report['osv_count']}\n"
            f"  GitHub PoC: {report['github_count']}\n"
            f"  CISA KEV: {kev_count}\n\n"
            "Report generated."
        )

    def _print_scan_result(self, result: dict):
        print(
            "Running local recon...\n"
            f"  Kernel: {result['kernel']}\n"
            f"  System: {result['system']}\n"
            f"  Build date: {result['build_date']}\n"
        )

        print("Running ReconFeeds searches...")

        stats = self.services.get_statistics()
        kev_count = stats.get("in_cisa_kev", 0)
        ransomware_count = stats.get("ransomware_related", 0)
        print(f"  CISA KEV catalog: {kev_count} entries")
        if ransomware_count:
            print(f"    Ransomware related: {ransomware_count}")

        nist = result.get("nist")
        if isinstance(nist, dict):
            count = len(nist.get("vulnerabilities", []))
            print(f"  NIST vulnerabilities found: {count}")
            if self.verbose and nist:
                for vuln in nist.get("vulnerabilities", [])[:5]:
                    cve_id = vuln.get("cve", {}).get("cveId", "N/A")
                    desc = vuln.get("cve", {}).get(
                        "descriptions", [{}])[0].get("value", "N/A")[:100]
                    print(f"    - {cve_id}: {desc}...")
        else:
            print(f"  NIST: {nist}")

        osv = result.get("osv")
        if isinstance(osv, dict):
            count = len(osv.get("vulns", []))
            print(f"  OSV vulnerabilities found: {count}")
            if self.verbose and osv:
                for vuln in osv.get("vulns", [])[:5]:
                    vuln_id = vuln.get("id", "N/A")
                    summary = vuln.get("summary", "N/A")[:100]
                    print(f"    - {vuln_id}: {summary}...")
        else:
            print(f"  OSV: {osv}")

        github = result.get("github")
        if isinstance(github, list):
            print(f"  GitHub repos found: {len(github)}")
            if self.verbose and github:
                for repo in github[:5]:
                    name = repo.get("full_name", "N/A")
                    stars = repo.get("stars", 0)
                    desc = repo.get("description", "N/A") or "No description"
                    print(f"    - {name} ({stars} stars): {desc[:80]}...")
        else:
            print(f"  GitHub: {github}")


def main_cli():
    parser = argparse.ArgumentParser(
        description="Kernel Vulnerability Auditor")
    parser.add_argument(
        "--scan", "-s", action="store_true",
        help="Perform vulnerability scan")
    parser.add_argument(
        "--report", "-r", action="store_true", help="Generate report")
    parser.add_argument(
        "--exec-tests", action="store_true",
        help="Run execution tests (CVE => PoC -> sandbox)")
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable verbose output")
    parser.add_argument(
        "--cve", type=str, default="6.1.0",
        help="CVE ID for GitHub PoC search by kernel version")
    parser.add_argument(
        "--save", action="store_true", help="Save results to DB")
    parser.add_argument(
        "--list-kev", action="store_true", help="List CISA KEV entries")
    parser.add_argument(
        "--db", type=str, default=DB_BACKEND,
        choices=["simple", "orm", "memory"],
        help="DB backend type and way, sqlite, redis, or just in memory",
    )

    args = parser.parse_args()

    db = get_db(args.db)
    app = CLIApp(verbose=args.verbose, db=db)

    if args.list_kev:
        kev_entries = app.services.get_cisa_kev_entries(limit=50)
        print(f"\n=== CISA KEV Catalog ({len(kev_entries)} entries) ===\n")
        for idx, entry in enumerate(kev_entries[:20], 1):
            cve_id = entry.get("cve_id", "N/A")
            desc = entry.get("description", "")[:80]
            date = entry.get("cisa_kev", {}).get("date_added", "N/A")
            ransomware = entry.get(
                "cisa_kev", {}
            ).get("known_ransomware", False)
            print(f"  {idx}. {cve_id}")
            print(f"     {desc}...")
            print(f"     Added: {date} | Ransomware: {ransomware}")
            print()
        if len(kev_entries) > 20:
            print(f"  ... and {len(kev_entries) - 20} more")
    elif args.exec_tests:
        report = app.services.run_execution_tests()
        print(f"Kernel: {report['kernel']}")
        if report.get("build_date"):
            print(f"Build date: {report['build_date']}")
        print(f"CVE hints processed: {report.get('cves_processed', 0)}")
        stats = report.get("stats", {})
        print(
            f"Stats: total={stats.get('total')}, "
            f"exploits={stats.get('with_exploits')}, "
            f"in CISA KEV={stats.get('in_cisa_kev')}"
        )
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
        print(
            "This tool checks the practical functionality of"
            " linux kernel exploits\n"
            "Use --help for available options"
        )

    # TODO: close DB connections after report cuz in memory


__all__ = ["CLIApp", "main_cli"]
