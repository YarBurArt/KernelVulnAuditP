import sys
import argparse
from datetime import datetime, timezone
from typing import Any
try:
    import flet as ft
    GUI_E = True
except (ImportError, ModuleNotFoundError):
    GUI_E = False

from recon import LocalRecon, ReconFeeds
from db import get_db


class AppServices:
    """trying to get readable service logic"""
    def __init__(self, db=None):
        self.lr = LocalRecon()
        self.rf = ReconFeeds()
        self.db = db or get_db("memory")

    def run_local_recon(self) -> dict:
        kernel = self.lr.get_kernel_version_simple()
        build_date = self.lr.get_kernel_build_date(kernel)
        return {
            "kernel": kernel,
            "system": self.lr.environment_info.get("system"),
            "build_date": build_date
        }

    def run_full_recon(self, kern_ver: str = "6.1.0") -> dict:
        local: dict = self.run_local_recon()
        nist = self.rf.nist_search(
            local["kernel"], local["build_date"]
        )
        osv: dict = self.rf.osv_search(local["kernel"])
        github: dict = self.rf.github_search(local["kernel"])
        return {**local, "nist": nist, "osv": osv, "github": github}

    def save_recon_results(self, results: dict) -> int:
        """write recon results to DB,
        returns count of saved vulnerabilities."""
        # TODO: upsert vulns from nist/osv,
        # add github refs, return count
        return 0

    def get_cached_recon(self, kernel: str):
        """Fetch cached recon results from DB by kernel version."""
        # TODO: query DB for cached vulns by kernel version
        return None

    def generate_report(self, kern_v: str = "6.18.0"):
        data = self.run_full_recon(kern_v)
        return self._format_report(data)

    def get_statistics(self):
        """Return DB statistics for report."""
        # TODO: return self.db.get_statistics()
        return {
            'total': 0,
            'with_exploits': 0,
            'in_cisa_kev': 0,
            'ransomware_related': 0,
            'avg_cvss': 0.0,
        }

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
        ft.app(target=self._main_page)

    def _main_page(self, page: ft.Page):
        self.page = page
        page.title = "Kernel Vulnerability Auditor"
        page.window_width = 650
        page.window_height = 600
        page.theme_mode = ft.ThemeMode.DARK

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
        theme_icon = ft.icons.Icons.LIGHT_MODE if is_dark else ft.icons.Icons.DARK_MODE

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
            expand=True, border=ft.border.all(1),
        )
        self.page.add(log_container)
        self.page.add(ft.Row([
            ft.Button("Start Local", on_click=self._start_local),
            ft.Button("Recon ti feeds", on_click=self._start_recon),
            # TODO: add save handler
            ft.Button("Save to DB", on_click=self._save_to_db),
        ], alignment=ft.MainAxisAlignment.START, spacing=10))
        self.page.update()

    def _navigate_to_report(self, _):
        self.page.clean()
        self._create_nav_bar()
        self.page.add(ft.Text("Generating vulnerability report..."))
        # TODO: fetch and display DB stats
        self.page.add(ft.Text("Report generated..."))

    def _start_local(self, _):
        self.log.controls.clear()
        self._append_log("Starting local recon...")
        try:
            result = self.services.run_local_recon()
            result['build_date'] = datetime.fromtimestamp(
                result['build_date'], tz=timezone.utc
            ).strftime('%Y-%m-%d %H:%M:%S %Z')  # format time
            self._append_log(result)
            self._append_log("Local recon finished.")
        except Exception as e:
            self._append_log(f"Local recon error: {e}")

    def _start_recon(self, _):
        self.log.controls.clear()
        self._append_log("Starting full recon (local -> feeds)...")
        try:
            result = self.services.run_full_recon()
            self._append_log({
                "kernel": result["kernel"], "build_date": result["build_date"]
            })
            self._append_log({
                "nist": result["nist"]} if isinstance(
                    result["nist"], dict) else result["nist"])
            self._append_log({
                "osv": result["osv"]} if isinstance(
                    result["osv"], dict) else result["osv"])
            self._append_log({
                "github": result["github"]} if isinstance(
                    result["github"], dict) else result["github"])
            self._append_log("Recon feeds finished.")
            # TODO: user prompt to save results to DB
        except Exception as e:
            self._append_log(f"Recon feeds error: {e}")

    def _save_to_db(self, _):
        """Save current recon results to DB."""
        # TODO: call services.save_recon_results() and log count
        pass

    def _get_cell_text(self, v: Any) -> str:
        if isinstance(v, list) and v and isinstance(v[0], dict):
            cell = "\n".join([", ".join(
                f"{ik}: {iv}" for ik, iv in it.items()
            ) for it in v])
        elif isinstance(v, dict):
            cell = ", ".join(f"{ik}: {iv}" for ik, iv in v.items())
        else:
            cell = str(v)
        return cell

    def _append_log(self, item):
        if isinstance(item, str):
            self.log.controls.append(ft.Text(item))
        elif isinstance(item, dict):
            rows = []
            for k, v in item.items():
                cell: str = self._get_cell_text(v)
                rows.append(ft.DataRow(
                    cells=[ft.DataCell(ft.Text(str(k))),
                           ft.DataCell(ft.Text(cell))]
                ))
            table = ft.DataTable(
                columns=[ft.DataColumn(ft.Text("Key")),
                         ft.DataColumn(ft.Text("Value"))],
                rows=rows,)
            self.log.controls.append(table)
        elif isinstance(item, list) and item and isinstance(item[0], dict):
            keys = sorted({k for r in item for k in r.keys()})
            cols = [ft.DataColumn(ft.Text(k)) for k in keys]
            rows = []
            for r in item:
                cells = [ft.DataCell(
                    ft.Text(str(r.get(k, "")))
                ) for k in keys]
                rows.append(ft.DataRow(cells=cells))
            table = ft.DataTable(columns=cols, rows=rows)
            self.log.controls.append(table)
        else:
            self.log.controls.append(ft.Text(str(item)))
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
        self._print_scan_result(result)
        # TODO: save to DB if requested

    def run_report(self, cve_id: str = "6.1.0"):
        report = self.services.generate_report(cve_id)
        # TODO: fetch and merge DB stats
        print("\n=== RW intermediate results ===\n"
              f"Kernel: {report['kernel']}\n"
              f"System: {report['system']}\n"
              f"Build Date: {report['build_date']}\n\n"
              "Vulnerabilities:\n"
              f"  NIST: {report['nist_count']}\n"
              f"  OSV: {report['osv_count']}\n"
              f"  GitHub PoC: {report['github_count']}\n\n"
              "Report generated.")
        # TODO: print DB stats

    def _print_scan_result(self, result: dict):
        print("Running local recon...\n"
              f"  Kernel: {result['kernel']}\n"
              f"  System: {result['system']}\n"
              f"  Build date: {result['build_date']}\n")

        print("Running ReconFeeds searches...")

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
        "--verbose", "-v", action="store_true", help="Enable verbose output")
    parser.add_argument(
        "--cve", type=str, default="6.1.0",
        help="CVE ID for GitHub PoC search by kernel version")
    parser.add_argument(
        "--save", action="store_true", help="Save results to DB")
    parser.add_argument(
        "--db", type=str, default="simple",
        choices=["simple", "orm", "memory"],
        help="DB backend type and way, sqlite, redis, or just in memory")

    args = parser.parse_args()

    db = get_db("memory")  # faster for test, for real better orm
    app = CLIApp(verbose=args.verbose, db=db)

    if args.scan:
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

    if cli_flag:
        main_cli()
    elif gui_flag:
        db = get_db("memory")
        try:
            GUIApp(db=db).run()
        finally:
            db.close()
    elif GUI_E:
        GUIApp().run()
    else:
        main_cli()


if __name__ == "__main__":
    main()
