import sys
import argparse

try:
    import flet as ft
    GUI_E = True
except (ImportError, ModuleNotFoundError):
    GUI_E = False


def main_gui():
    """gui base router of app life"""
    def main_page(page: ft.Page):
        page.title = "Kernel Vulnerability Auditor"
        page.window_width = 800
        page.window_height = 600
        # TODO: log service
        
        def navigate_to_scan(_):
            page.clean()
            create_nav_bar()
            page.add(ft.Text("Running vulnerability scan..."))
            # TODO: start recon, search xpl, isolate and execute
            page.add(ft.Text("Scan completed..."))

        def navigate_to_report(_):
            page.clean()
            create_nav_bar()
            page.add(ft.Text("Generating vulnerability report..."))
            # TODO: run report.py with streamlit 
            page.add(ft.Text("Report generated..."))

        def create_nav_bar():
            nav_bar = ft.Row([
                ft.ElevatedButton("Scan", on_click=navigate_to_scan),
                ft.ElevatedButton("Report", on_click=navigate_to_report),
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
