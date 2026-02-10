import sys
import argparse
try:
    import flet as ft
    GUI_E = True
except (ImportError, ModuleNotFoundError):
    GUI_E = False

from recon import LocalRecon, ReconFeeds


def main_gui():
    """gui base router of app life"""
    def main_page(page: ft.Page):
        page.title = "Kernel Vulnerability Auditor"
        page.window_width = 800
        page.window_height = 600

        log = ft.Column(scroll=ft.ScrollMode.AUTO)
        lr = LocalRecon()
        rf = ReconFeeds()

        def append_log(item):
            if isinstance(item, str):
                log.controls.append(ft.Text(item))
            elif isinstance(item, dict):
                rows = []
                for k, v in item.items():
                    if isinstance(v, list) and v and isinstance(v[0], dict):
                        cell = "\n".join([", ".join(
                            f"{ik}: {iv}" for ik, iv in it.items()
                        ) for it in v])
                    elif isinstance(v, dict):
                        cell = ", ".join(f"{ik}: {iv}" for ik, iv in v.items())
                    else:
                        cell = str(v)
                    rows.append(ft.DataRow(
                        cells=[ft.DataCell(ft.Text(str(k))),
                        ft.DataCell(ft.Text(cell))]
                    ))
                table = ft.DataTable(
                    columns=[ft.DataColumn(ft.Text("Key")),
                             ft.DataColumn(ft.Text("Value"))],
                    rows=rows,)
                log.controls.append(table)
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
                log.controls.append(table)
            else:
                log.controls.append(ft.Text(str(item)))
            page.update()

        def start_local(_):
            log.controls.clear()
            append_log("Starting local recon...")
            try:
                kernel = lr.get_kernel_version_simple()
                append_log({"kernel": kernel,
                    "system": lr.environment_info.get("system")})
                build_date = lr.get_kernel_build_date(kernel)
                append_log({"build_date": build_date})
                append_log("Local recon finished.")
            except Exception as e:
                append_log(f"Local recon error: {e}")

        def start_recon(_):
            log.controls.clear()
            append_log("Starting full recon (local -> feeds)...")
            try:
                append_log("Running local recon step...")
                kernel = lr.get_kernel_version_simple()
                build_date = lr.get_kernel_build_date(kernel)
                append_log({"kernel": kernel, "build_date": build_date})
                append_log("Running ReconFeeds searches...")
                nist_result = rf.nist_search(kernel, build_date)
                append_log({"nist": nist_result} if isinstance(
                    nist_result, dict) else nist_result)
                osv_result = rf.osv_search(kernel)
                append_log({"osv": osv_result} if isinstance(
                    osv_result, dict) else osv_result)
                github_result = rf.github_search("CVE-2024-1086")
                append_log({"github": github_result} if isinstance(
                    github_result, dict) else github_result)
                append_log("Recon feeds finished.")
            except Exception as e:
                append_log(f"Recon feeds error: {e}")

        def navigate_to_scan(_):
            page.clean()
            create_nav_bar()
            page.add(ft.Text("Running vulnerability scan..."))
            log_container = ft.Container(
                content=log,
                height=360,           
                padding=10,
                expand=True,        
                border=ft.border.all(1,),
            )
            page.add(log_container)
            page.add(ft.Row([
                ft.Button("Start Local", on_click=start_local),
                ft.Button("Recon ti feeds", on_click=start_recon),
            ], alignment=ft.MainAxisAlignment.START, spacing=10))
            page.add(ft.Text("Scan controls above."))
            page.update()

        def navigate_to_report(_):
            page.clean()
            create_nav_bar()
            page.add(ft.Text("Generating vulnerability report..."))
            page.add(ft.Text("Report generated..."))

        def create_nav_bar():
            nav_bar = ft.Row([
                ft.Button("Scan", on_click=navigate_to_scan),
                ft.Button("Report", on_click=navigate_to_report),
            ])
            page.add(nav_bar)

        create_nav_bar()
        page.add(ft.Text("Welcome to Kernel Vulnerability Auditor", size=24))

    ft.app(target=main_page)



def main_cli():
    """cli base router of app life"""
    parser = argparse.ArgumentParser(
        description="Kernel Vulnerability Auditor"
    )
    parser.add_argument("--scan", "-s", action="store_true",
                        help="Perform vulnerability scan")
    parser.add_argument("--report", "-r", action="store_true",
                        help="Generate report")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable verbose output")

    args = parser.parse_args()

    if args.scan:
        pass
    elif args.report:
        pass
    else:
        print("This tool checks the practical "
              "functionality of linux kernel exploits\n"
              "Use --help for available options")


def main():
    """tries GUI first, falls back to CLI if Flet unavailable"""
    if "--gui" in sys.argv and GUI_E:
        sys.argv.remove("--gui")  # rem from argparse
        main_gui()
    elif GUI_E:
        main_gui()
    else:
        main_cli()


if __name__ == "__main__":
    main()
