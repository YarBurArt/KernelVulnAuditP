import subprocess
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

from core import flatten_dict_value, format_timestamp, update_config_file

try:
    import flet as ft

    GUI_E = True
except (ImportError, ModuleNotFoundError):
    GUI_E = False
    ft = None  # type: ignore

from app_services import AppServices
from config import (
    ALLOW_HOST_EXECUTION, CISA_KEV_PATH, DB_BACKEND, ISOLATION_TIMEOUT_SEC,
    LES_PATH, LES_REPORT_PATH, LINPEAS_OUT_JSON, LYNIS_LOG_FILE,
    LYNIS_REPORT_FILE, PATH_LINPEAS, POCS_BASE_PATH,
)


class GUIApp:
    """Flet-based GUI wrapper."""

    def __init__(self, db=None):
        self.services = AppServices(db=db)
        self.log = None
        self.page = None

    def run(self):
        if not GUI_E:
            raise RuntimeError("Flet is not available; cannot launch GUI.")
        ft.run(main=self._main_page)

    def _main_page(self, page: "ft.Page"):
        self.page = page
        page.title = "Kernel Vulnerability Auditor"
        page.window_width = 650
        page.window_height = 600
        page.theme_mode = ft.ThemeMode.DARK
        page.padding = 20
        page.spacing = 15

        page.theme = ft.Theme(button_theme=ft.ButtonTheme(
            style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=4))
        ))

        self.log = ft.Column(scroll=ft.ScrollMode.AUTO)
        self._create_nav_bar()
        page.add(ft.Text("Welcome to Kernel Vulnerability Auditor", size=24))

    def _toggle_theme(self, _):
        if self.page.theme_mode == ft.ThemeMode.DARK:
            self.page.theme_mode = ft.ThemeMode.LIGHT
        else:
            self.page.theme_mode = ft.ThemeMode.DARK
        self.page.update()

    def _create_nav_bar(self):
        is_dark = self.page.theme_mode == ft.ThemeMode.DARK
        theme_icon = ft.icons.Icons.LIGHT_MODE if is_dark \
            else ft.icons.Icons.DARK_MODE

        nav_bar = ft.Row(
            [
                ft.Button("Scan", on_click=self._navigate_to_scan),
                ft.Button("Report", on_click=self._navigate_to_report),
                ft.Button("Settings", on_click=self._navigate_to_settings),
                ft.Container(expand=True),
                ft.Button(
                    content=ft.Icon(theme_icon, size=20),
                    on_click=self._toggle_theme
                ),
            ]
        )
        self.page.add(nav_bar)

    def _navigate_to_scan(self, _):
        self.page.clean()
        self.page.scroll = None
        self._create_nav_bar()
        self.page.add(ft.Text("Running vulnerability scan..."))
        log_container = ft.Container(
            content=self.log, height=360, padding=10, expand=True,
            alignment=ft.Alignment.CENTER_LEFT
        )
        self.page.add(log_container)
        self.page.add(ft.Row([
            ft.Button("Start Local", on_click=self._start_local),
            ft.Button("Recon ti feeds", on_click=self._start_feeds),
            ft.Button("Full Recon", on_click=self._start_recon),
            ft.Button("Run Execution Tests",
                      on_click=self._run_execution_tests),
            ft.Button("Save to DB", on_click=self._save_to_db),
        ], alignment=ft.MainAxisAlignment.START, spacing=10,
        ))
        self.page.update()

    def _navigate_to_settings(self, _):
        self.page.clean()
        self.page.scroll = ft.ScrollMode.AUTO
        self._create_nav_bar()
        self.page.add(ft.Text("Settings", size=24))
        self.page.add(ft.Text(
            "Edit configuration settings", size=14, color=ft.Colors.GREY))
        self.page.add(ft.Container(height=10))

        self._settings_fields = {}
        settings_form = self._build_settings_form()
        self.page.add(settings_form)
        self.page.add(ft.Container(height=20))
        self.page.add(ft.Text(
            "You need to restart the app to apply",
            size=14, color=ft.Colors.GREY))
        self.page.add(ft.Row([
            ft.Button("Save Settings", on_click=self._save_settings),
            ft.Button(
                "Cancel", on_click=lambda _: self._navigate_to_scan(None)),
        ], spacing=10,
        ))
        self.page.update()

    def _build_settings_form(self):

        form = ft.Column(spacing=15)

        form.controls.append(ft.Dropdown(
            label="DB Backend", value=DB_BACKEND,
            options=[
                ft.dropdown.Option("orm", "ORM (SQLite)"),
                ft.dropdown.Option("simple", "Simple (SQLite)"),
                ft.dropdown.Option("memory", "In-Memory"),
            ], expand=True,
        ))
        self._settings_fields["DB_BACKEND"] = form.controls[-1]

        form.controls.append(ft.TextField(
            label="Isolation Timeout (seconds)",
            value=str(ISOLATION_TIMEOUT_SEC),
            keyboard_type=ft.KeyboardType.NUMBER,
            expand=True,
        ))
        self._settings_fields["ISOLATION_TIMEOUT_SEC"] = form.controls[-1]

        form.controls.append(ft.Switch(
            label="Allow Host Execution (risky)", value=ALLOW_HOST_EXECUTION
        ))
        self._settings_fields["ALLOW_HOST_EXECUTION"] = form.controls[-1]

        form.controls.append(ft.Divider())
        form.controls.append(ft.Text(
            "File Paths", size=16, weight=ft.FontWeight.BOLD
        ))

        path_fields = [
            ("CISA_KEV_PATH", CISA_KEV_PATH, "CISA KEV Path"),
            ("LYNIS_REPORT_FILE", LYNIS_REPORT_FILE, "Lynis Report File"),
            ("LYNIS_LOG_FILE", LYNIS_LOG_FILE, "Lynis Log File"),
            ("LINPEAS_OUT_JSON", LINPEAS_OUT_JSON, "Linpeas Output JSON"),
            ("PATH_LINPEAS", PATH_LINPEAS, "Linpeas Script Path"),
            ("LES_PATH", LES_PATH, "LES Script Path"),
            ("LES_REPORT_PATH", LES_REPORT_PATH, "LES Report Path"),
            ("POCS_BASE_PATH", POCS_BASE_PATH, "POCs Base Path"),
        ]

        for key, value, label in path_fields:
            form.controls.append(ft.TextField(
                label=label, value=value, expand=True))
            self._settings_fields[key] = form.controls[-1]

        return form

    def _save_settings(self, _):
        try:
            config_path = Path(__file__).parent / "config.py"

            updates = {
                "DB_BACKEND": f'"{self._settings_fields["DB_BACKEND"].value}"',
                "ISOLATION_TIMEOUT_SEC":
                    self._settings_fields["ISOLATION_TIMEOUT_SEC"].value,
                "ALLOW_HOST_EXECUTION":
                    str(self._settings_fields["ALLOW_HOST_EXECUTION"].value),
            }

            for key in [
                "CISA_KEV_PATH", "LYNIS_REPORT_FILE", "LYNIS_LOG_FILE",
                "LINPEAS_OUT_JSON", "PATH_LINPEAS", "LES_PATH",
                "LES_REPORT_PATH", "POCS_BASE_PATH",
            ]:
                updates[key] = f'"{self._settings_fields[key].value}"'

            update_config_file(config_path, updates)

            self._append_log("Settings saved successfully!")
            self._append_log(
                "Note: Some settings may require restart to take effect"
            )
        except Exception as e:
            self._append_log(f"Error saving settings: {e}")

    def _navigate_to_report(self, _):
        self.page.clean()
        self.page.scroll = ft.ScrollMode.AUTO
        self._create_nav_bar()
        self.page.add(ft.Text("Generating vulnerability report...", size=24))

        log_container = ft.Container(
            content=self.log, height=360, padding=10, expand=True,
            alignment=ft.Alignment.CENTER_LEFT
        )
        self.page.add(log_container)

        try:
            report_path = Path(__file__).parent / "report.py"
            if not report_path.exists():
                raise FileNotFoundError("report.py not found")

            streamlit_available = False
            try:
                import streamlit

                streamlit_available = True
            except (ImportError, ModuleNotFoundError):
                pass

            if streamlit_available:
                self._append_log("Launching Streamlit report...")
                try:
                    subprocess.Popen(
                        [
                            sys.executable, "-m"
                            "streamlit", "run", str(report_path)
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    self._append_log(
                        "Streamlit report launched in "
                        "browser at http://localhost:8501")
                    self._append_log(
                        "Close this window to stop the report server")
                except Exception as e:
                    self._append_log(f"Streamlit launch failed: {e}")
                    self._append_log("Falling back to CLI report...")
                    self._run_cli_report()
            else:
                self._append_log(
                    "Streamlit not available, running CLI report...")
                self._run_cli_report()

        except Exception as e:
            self._append_log(f"Report error: {e}")
            self._run_cli_report()

        self.page.update()

    def _run_cli_report(self):
        try:
            from db import get_db
            from report import CLIReportRenderer, build_report_data

            db = get_db("orm")
            data = build_report_data(db)
            db.close()

            renderer = CLIReportRenderer(data, verbose=True)
            output = renderer._build_full_report()
            self._append_log(output)
            self._append_log("Report generated (CLI mode)")
        except Exception as e:
            self._append_log(f"CLI report error: {e}")

    def _start_local(self, _):
        self.log.controls.clear()
        self._append_log("Starting local recon...")
        try:
            result_dt = self.services.run_local_recon()
            result = asdict(result_dt)
            if result["build_date"] is not None:
                result["build_date"] = format_timestamp(result["build_date"])
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
        pass  # FIXME:

    def _get_cell_text(self, v: Any) -> str:
        return flatten_dict_value(v)

    def _is_url(self, text: str) -> bool:
        if not isinstance(text, str):
            return False
        return text.startswith(("http://", "https://")) and len(text) > 8

    def _make_link(self, url: str) -> "ft.Container":
        def open_url(_):
            if self.page:
                self.page.launch_url(url)

        return ft.Container(
            content=ft.Text(
                url, selectable=True, text_align=ft.TextAlign.LEFT,
                color=ft.Colors.BLUE,
                style=ft.TextStyle(decoration=ft.TextDecoration.UNDERLINE),
            ), ink=True, on_click=open_url,
        )

    def _build_control(self, data):
        if isinstance(data, dict):
            return self._build_dict(data)

        if isinstance(data, list):
            return self._build_list(data)

        return self._build_value(data)

    def _build_value(self, value):
        return ft.Text(
            str(value), selectable=True, text_align=ft.TextAlign.LEFT)

    def _build_dict(self, data: dict):
        tiles = []
        for key, value in data.items():
            tile = ft.ExpansionTile(
                title=ft.Text(
                    str(key), weight=ft.FontWeight.BOLD,
                    text_align=ft.TextAlign.LEFT),
                controls=[self._build_control(value)],
            )
            tiles.append(tile)

        return ft.Column(controls=tiles, tight=True, expand=True)

    def _build_list(self, data: list):
        if not data:
            return self._build_value("[]")
        if all(isinstance(item, dict) for item in data):
            return self._build_table(data)
        return ft.Column(
            controls=[self._build_control(item) for item in data],
            tight=True
        )

    def _build_table(self, data: list[dict]):
        keys = sorted({k for row in data for k in row.keys()})

        columns = [ft.DataColumn(
            label=ft.Text(
                key, weight=ft.FontWeight.BOLD,
                text_align=ft.TextAlign.LEFT
            ), numeric=False,
        ) for key in keys]

        rows = []
        for row in data:
            cells = []
            for key in keys:
                val = row.get(key, "")
                if self._is_url(val):
                    cells.append(ft.DataCell(self._make_link(val)))
                else:
                    cells.append(ft.DataCell(ft.Text(
                        self._get_cell_text(val),
                        selectable=True, text_align=ft.TextAlign.LEFT
                    )))
            rows.append(ft.DataRow(cells=cells))

        return ft.DataTable(
            columns=columns, rows=rows, expand=True, column_spacing=20)

    def _append_log(self, item):
        control = self._build_control(item)
        self.log.controls.append(control)
        self.page.update()


__all__ = ["GUIApp", "GUI_E"]
