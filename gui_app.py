import asyncio
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from core import flatten_dict_value, update_config_file
from db import ThreatDB

try:
    import flet as ft

    GUI_E = True
except ImportError, ModuleNotFoundError:
    GUI_E = False

from app_services import AppServices
from config import (  # just for gui settings
    ALLOW_HOST_EXECUTION,
    CISA_KEV_PATH,
    DB_BACKEND,
    ISOLATION_TIMEOUT_SEC,
    LES_PATH,
    LES_REPORT_PATH,
    LINPEAS_OUT_JSON,
    LOG_LEVEL,
    LYNIS_LOG_FILE,
    LYNIS_REPORT_FILE,
    PATH_LINPEAS,
    POCS_BASE_PATH,
)


class GUIApp:
    """Flet-based GUI wrapper."""

    def __init__(self, db: ThreatDB):
        self.services = AppServices(db=db)
        self.log: ft.Column | None = None
        self._page: ft.Page | None = None

    def run(self):
        if not GUI_E:
            raise RuntimeError("Flet is not available; cannot launch GUI.")
        assert ft is not None
        ft.run(main=self._main_page)

    @property
    def page(self) -> ft.Page:
        assert self._page is not None
        return self._page

    def _main_page(self, page: ft.Page):
        self._page = page
        page.title = "Kernel Vulnerability Auditor"
        page.window.width = 950
        page.window.height = 600
        page.theme_mode = ft.ThemeMode.DARK
        page.padding = 20
        page.spacing = 15

        page.theme = ft.Theme(
            button_theme=ft.ButtonTheme(
                style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=4))
            )
        )

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
        theme_icon = ft.icons.Icons.LIGHT_MODE if is_dark else ft.icons.Icons.DARK_MODE

        nav_bar = ft.Row(
            [
                ft.Button("Scan", on_click=self._navigate_to_scan),
                ft.Button("Report", on_click=self._navigate_to_report),
                ft.Button("Settings", on_click=self._navigate_to_settings),
                ft.Container(expand=True),
                ft.Button(
                    content=ft.Icon(theme_icon, size=20), on_click=self._toggle_theme
                ),
            ]
        )
        self.page.add(nav_bar)

    def _navigate_to_settings(self, _):
        self.page.clean()
        self.page.scroll = ft.ScrollMode.AUTO
        self._create_nav_bar()
        self.page.add(ft.Text("Settings", size=24))
        self.page.add(
            ft.Text("Edit configuration settings", size=14, color=ft.Colors.GREY)
        )
        self.page.add(ft.Container(height=10))

        self._settings_fields = {}
        settings_form = self._build_settings_form()
        self.page.add(settings_form)
        self.page.add(ft.Container(height=20))
        self.page.add(
            ft.Text(
                "You need to restart the app to apply", size=14, color=ft.Colors.GREY
            )
        )
        self.page.add(
            ft.Row(
                [
                    ft.Button("Save Settings", on_click=self._save_settings),
                    ft.Button(
                        "Cancel", on_click=lambda _: self._navigate_to_scan(None)
                    ),
                ],
                spacing=10,
            )
        )
        self.page.update()

    def _build_settings_form(self):

        form = ft.Column(spacing=15)

        form.controls.append(
            ft.Dropdown(
                label="DB Backend",
                value=DB_BACKEND,
                options=[
                    ft.dropdown.Option("orm", "ORM (SQLite)"),
                    ft.dropdown.Option("simple", "Simple (SQLite)"),
                    ft.dropdown.Option("memory", "In-Memory"),
                ],
                expand=True,
            )
        )
        self._settings_fields["DB_BACKEND"] = form.controls[-1]

        form.controls.append(
            ft.Dropdown(
                label="Log Level",
                value=LOG_LEVEL,
                options=[
                    ft.dropdown.Option("DEBUG"),
                    ft.dropdown.Option("INFO"),
                    ft.dropdown.Option("WARNING"),
                    ft.dropdown.Option("ERROR"),
                    ft.dropdown.Option("CRITICAL"),
                ],
                expand=True,
            )
        )
        self._settings_fields["LOG_LEVEL"] = form.controls[-1]

        form.controls.append(
            ft.TextField(
                label="Isolation Timeout (seconds)",
                value=str(ISOLATION_TIMEOUT_SEC),
                keyboard_type=ft.KeyboardType.NUMBER,
                expand=True,
            )
        )
        self._settings_fields["ISOLATION_TIMEOUT_SEC"] = form.controls[-1]

        form.controls.append(
            ft.Switch(label="Allow Host Execution (risky)", value=ALLOW_HOST_EXECUTION)
        )
        self._settings_fields["ALLOW_HOST_EXECUTION"] = form.controls[-1]

        form.controls.append(ft.Divider())
        form.controls.append(ft.Text("File Paths", size=16, weight=ft.FontWeight.BOLD))

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
            form.controls.append(ft.TextField(label=label, value=value, expand=True))
            self._settings_fields[key] = form.controls[-1]

        return form

    def _save_settings(self, _):
        try:
            config_path = Path(__file__).parent / "config.py"

            updates = {
                "DB_BACKEND": f'"{self._settings_fields["DB_BACKEND"].value}"',
                "ISOLATION_TIMEOUT_SEC": self._settings_fields[
                    "ISOLATION_TIMEOUT_SEC"
                ].value,
                "ALLOW_HOST_EXECUTION": str(
                    self._settings_fields["ALLOW_HOST_EXECUTION"].value
                ),
                "LOG_LEVEL": f'"{self._settings_fields["LOG_LEVEL"].value}"',
            }

            for key in [
                "CISA_KEV_PATH",
                "LYNIS_REPORT_FILE",
                "LYNIS_LOG_FILE",
                "LINPEAS_OUT_JSON",
                "PATH_LINPEAS",
                "LES_PATH",
                "LES_REPORT_PATH",
                "POCS_BASE_PATH",
            ]:
                updates[key] = f'"{self._settings_fields[key].value}"'

            update_config_file(config_path, updates)

            self._append_log("Settings saved successfully!")
            self._append_log("Note: Some settings may require restart to take effect")
        except Exception as e:
            self._append_log(f"Error saving settings: {e}")

    def _navigate_to_report(self, _):
        self.page.clean()
        self.page.scroll = ft.ScrollMode.AUTO
        self._create_nav_bar()
        self.page.add(ft.Text("Generating vulnerability report...", size=24))

        log_container = ft.Container(
            content=self.log,
            height=360,
            padding=10,
            expand=True,
            alignment=ft.Alignment.CENTER_LEFT,
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
            except ImportError, ModuleNotFoundError:
                pass

            if streamlit_available:
                self._append_log("Launching Streamlit report...")
                try:
                    subprocess.Popen(
                        [sys.executable, "-mstreamlit", "run", str(report_path)],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    self._append_log(
                        "Streamlit report launched in browser at http://localhost:8501"
                    )
                    self._append_log("Close this window to stop the report server")
                except Exception as e:
                    self._append_log(f"Streamlit launch failed: {e}")
                    self._append_log("Falling back to CLI report...")
                    self._run_cli_report()
            else:
                self._append_log("Streamlit not available, running CLI report...")
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
            output = renderer.build_full_report()
            self._append_log(output)
            self._append_log("Report generated (CLI mode)")
        except Exception as e:
            self._append_log(f"CLI report error: {e}")

    def _save_to_db(self, _):
        pass  # FIXME:

    @staticmethod
    def _get_cell_text(v: Any) -> str:
        return flatten_dict_value(v)

    @staticmethod
    def _is_url(text: str) -> bool:
        if not isinstance(text, str):
            return False
        return text.startswith(("http://", "https://")) and len(text) > 8

    def _make_link(self, url: str) -> "ft.Container":
        def open_url(_):
            if self.page:
                self.page.launch_url(url)

        return ft.Container(
            content=ft.Text(
                url,
                selectable=True,
                text_align=ft.TextAlign.LEFT,
                color=ft.Colors.BLUE,
                style=ft.TextStyle(decoration=ft.TextDecoration.UNDERLINE),
            ),
            ink=True,
            on_click=open_url,
        )

    def _build_control(self, data):
        if isinstance(data, dict):
            return self._build_dict(data)

        if isinstance(data, list):
            return self._build_list(data)

        return self._build_value(data)

    @staticmethod
    def _build_value(value):
        return ft.Text(str(value), selectable=True, text_align=ft.TextAlign.LEFT)

    def _build_dict(self, data: dict):
        tiles: list[ft.Control] = []
        for key, value in data.items():
            tile = ft.ExpansionTile(
                title=ft.Text(
                    str(key), weight=ft.FontWeight.BOLD, text_align=ft.TextAlign.LEFT
                ),
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
            controls=[self._build_control(item) for item in data], tight=True
        )

    def _build_table(self, data: list[dict]):
        keys = sorted({k for row in data for k in row.keys()})

        columns = [
            ft.DataColumn(
                label=ft.Text(
                    key, weight=ft.FontWeight.BOLD, text_align=ft.TextAlign.LEFT
                ),
                numeric=False,
            )
            for key in keys
        ]

        rows = []
        for row in data:
            cells = []
            for key in keys:
                val = row.get(key, "")
                if self._is_url(val):
                    cells.append(ft.DataCell(self._make_link(val)))
                else:
                    cells.append(
                        ft.DataCell(
                            ft.Text(
                                self._get_cell_text(val),
                                selectable=True,
                                text_align=ft.TextAlign.LEFT,
                            )
                        )
                    )
            rows.append(ft.DataRow(cells=cells))

        return ft.DataTable(columns=columns, rows=rows, expand=True, column_spacing=20)

    def _append_log(self, item):
        control = self._build_control(item)
        assert self.log is not None
        self.log.controls.append(control)
        self.page.update()

    def _initialize_scan_state(self):
        """sets up the UI containers for the scan views"""
        # Use strictly monospace for data
        self.mono_style = ft.TextStyle(
            font_family="monospace", size=12, color=ft.Colors.ON_SURFACE
        )

        self.metric_fail_badge = ft.Text(
            "CRIT: 0",
            color=ft.Colors.RED_700,
            weight=ft.FontWeight.W_700,
            font_family="monospace",
        )

        self.metric_warn_badge = ft.Text(
            "WARN: 0",
            color=ft.Colors.ORANGE_700,
            weight=ft.FontWeight.W_700,
            font_family="monospace",
        )

        self.metric_cve_badge = ft.Text(
            "CVE: 0",
            color=ft.Colors.RED_400,
            weight=ft.FontWeight.W_700,
            font_family="monospace",
        )

        self.metric_sandbox_badge = ft.Text(
            "RUNS: 0",
            color=ft.Colors.CYAN_400,
            weight=ft.FontWeight.W_700,
            font_family="monospace",
        )

        # ListViews are highly optimized in Flet for long lists.
        self.audit_list = ft.ListView(
            expand=True, spacing=2, padding=10, auto_scroll=False
        )
        self.cve_list = ft.ListView(
            expand=True, spacing=2, padding=10, auto_scroll=False
        )
        self.sandbox_list = ft.ListView(
            expand=True, spacing=2, padding=10, auto_scroll=False
        )
        self.console_stream = ft.ListView(
            expand=True, spacing=0, padding=10, auto_scroll=True
        )

        self.progress_bar = ft.ProgressBar(
            visible=False,
            color=ft.Colors.PRIMARY,
            bgcolor=ft.Colors.SURFACE_CONTAINER_HIGHEST,
        )
        self.progress_label = ft.Text(
            "",
            size=11,
            font_family="monospace",
            color=ft.Colors.ON_SURFACE_VARIANT,
        )

        self.fail_count = 0
        self.warn_count = 0
        self.cve_count = 0
        self.sandbox_count = 0

    def _navigate_to_scan(self, _):
        self.page.clean()
        self.page.scroll = None
        self._create_nav_bar()
        self._initialize_scan_state()

        recon_group = ft.Container(
            content=ft.Row(
                [
                    ft.Button(
                        "Local Recon",
                        on_click=self._start_local,
                        style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=2)),
                    ),
                    ft.Button(
                        "TI Feeds",
                        on_click=self._start_feeds,
                        style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=2)),
                    ),
                ],
                spacing=8,
            ),
            padding=ft.Padding.symmetric(horizontal=8, vertical=6),
            border=ft.Border.all(1, ft.Colors.OUTLINE_VARIANT),
            border_radius=2,
            bgcolor=ft.Colors.SURFACE_CONTAINER_LOW,
        )
        metrics_panel = ft.Container(
            content=ft.Row(
                [
                    self.metric_fail_badge,
                    ft.VerticalDivider(width=15, color=ft.Colors.OUTLINE_VARIANT),
                    self.metric_warn_badge,
                    ft.VerticalDivider(width=15, color=ft.Colors.OUTLINE_VARIANT),
                    self.metric_cve_badge,
                    ft.VerticalDivider(width=15, color=ft.Colors.OUTLINE_VARIANT),
                    self.metric_sandbox_badge,
                ],
                alignment=ft.MainAxisAlignment.START,
            ),
            padding=ft.Padding.symmetric(horizontal=12, vertical=6),
            border=ft.Border.all(1, ft.Colors.OUTLINE_VARIANT),
            border_radius=2,
            bgcolor=ft.Colors.SURFACE_CONTAINER_LOW,
        )
        # Minimal action bar
        actions_row = ft.Row(
            [
                recon_group,
                ft.Button(
                    "Full Cycle",
                    on_click=self._start_recon,
                    style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=2)),
                ),
                ft.Button(
                    "Exec Tests",
                    on_click=self._run_execution_tests,
                    style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=2)),
                ),
                ft.Container(expand=True),
                metrics_panel,
            ],
            alignment=ft.MainAxisAlignment.START,
            spacing=8,
        )

        progress_row = ft.Column(
            [self.progress_bar, self.progress_label],
            spacing=2,
            visible=False,
        )
        self._progress_row = progress_row

        self.scan_tabs = ft.Tabs(
            length=4,
            selected_index=3,
            animation_duration=150,
            expand=True,
            content=ft.Column(
                expand=True,
                controls=[
                    ft.TabBar(
                        tabs=[
                            ft.Tab(label="Kernel Hardening"),
                            ft.Tab(label="Exploit Vectors"),
                            ft.Tab(label="Sandbox Runs"),
                            ft.Tab(label="Engine stdout"),
                        ]
                    ),
                    ft.TabBarView(
                        expand=True,
                        controls=[
                            self.audit_list,
                            self.cve_list,
                            self.sandbox_list,
                            ft.Container(
                                content=self.console_stream,
                                bgcolor="#0d1117",
                                border=ft.Border.all(1, ft.Colors.OUTLINE_VARIANT),
                            ),
                        ],
                    ),
                ],
            ),
        )
        separator = ft.Container(height=1, bgcolor=ft.Colors.BLACK, padding=0, margin=0)
        self.page.add(separator, actions_row, progress_row, self.scan_tabs)
        self.page.update()

    def _log_terminal(self, message: str, level: str = "INFO"):
        """streams raw output without clearing the view"""
        color = ft.Colors.ON_SURFACE_VARIANT
        if level == "FAIL":
            color = ft.Colors.ERROR
        elif level == "OK":
            color = ft.Colors.PRIMARY

        self.console_stream.controls.append(
            ft.Text(
                f"[{level}] {message}",
                font_family="monospace",
                size=11,
                color=color,
                selectable=True,
            )
        )
        self.page.update()

    @staticmethod
    def _audit_priority(rec) -> tuple[int, str]:
        """minimal simple priority check of kern params"""
        try:
            expected = int(rec.expected_value)
            actual = int(rec.actual_value)
            diff = abs(expected - actual)

            if diff >= 2:
                return 0, "CRIT"
            if diff == 1:
                return 1, "WARN"

        except TypeError, ValueError:
            pass

        return 2, "INFO"

    def _append_audit_item(self, rec):
        """Appends a strictly formatted dataclass row to the audit view."""

        severity = "INFO"
        indicator_color = ft.Colors.GREEN_700

        try:
            diff = abs(int(float(rec.expected_value)) - int(float(rec.actual_value)))

            if diff >= 2:
                severity = "CRIT"
                indicator_color = ft.Colors.RED_700
            elif diff == 1:
                severity = "WARN"
                indicator_color = ft.Colors.ORANGE_700

        except TypeError, ValueError:
            indicator_color = (
                ft.Colors.ERROR
                if rec.status == "FAIL"
                else ft.Colors.WARNING
                if rec.status == "WARNING"
                else ft.Colors.GREEN_700
            )

        header = ft.Row(
            [
                ft.Container(width=4, height=14, bgcolor=indicator_color),
                ft.Text(
                    f"[{severity}]",
                    width=55,
                    style=self.mono_style,
                    color=indicator_color,
                    weight=ft.FontWeight.W_700,
                ),
                ft.Text(
                    f"[{rec.test_id}]",
                    width=100,
                    style=self.mono_style,
                    color=ft.Colors.ON_SURFACE_VARIANT,
                ),
                ft.Text(
                    rec.field_name or rec.category,
                    width=230,
                    style=self.mono_style,
                    weight=ft.FontWeight.W_600,
                ),
                ft.Text(rec.description, expand=True, style=self.mono_style),
            ],
            spacing=5,
        )

        detail_content = ft.Container(
            content=ft.Column(
                [
                    ft.Text(
                        f"Expected: {rec.expected_value} | Actual: {rec.actual_value}",
                        style=self.mono_style,
                    ),
                    ft.Text(
                        f"Details: {rec.raw_data.get('suggestion', rec.raw_data.get('solution', 'N/A'))}",
                        style=self.mono_style,
                        color=ft.Colors.ON_SURFACE_VARIANT,
                    ),
                ],
                spacing=2,
            ),
            padding=ft.Padding.only(left=90, top=5, bottom=10),
            visible=bool(rec.expected_value or rec.actual_value),
        )

        self.audit_list.controls.append(
            ft.ExpansionTile(
                title=header,
                controls=[detail_content],
                controls_padding=0,
                collapsed_text_color=ft.Colors.ON_SURFACE,
                text_color=ft.Colors.ON_SURFACE,
            )
        )

        if severity == "CRIT":
            self.fail_count += 1
            self.metric_fail_badge.value = f"CRIT: {self.fail_count}"
        elif severity == "WARN":
            self.warn_count += 1
            self.metric_warn_badge.value = f"WARN: {self.warn_count}"

    def _append_cve_item(
        self, source: str, cve_id: str, title: str, details: str, urls: list
    ):
        header = ft.Row(
            [
                ft.Container(width=4, height=14, bgcolor=ft.Colors.ERROR_CONTAINER),
                ft.Text(
                    f"[{source}]",
                    width=60,
                    style=self.mono_style,
                    color=ft.Colors.ON_SURFACE_VARIANT,
                ),
                ft.Text(
                    cve_id,
                    width=120,
                    style=self.mono_style,
                    color=ft.Colors.ERROR,
                    weight=ft.FontWeight.W_600,
                ),
                ft.Text(
                    title,
                    expand=True,
                    style=self.mono_style,
                    overflow=ft.TextOverflow.ELLIPSIS,
                ),
            ],
            spacing=5,
        )

        links_col = (
            ft.Column([self._make_link(u) for u in urls], spacing=2)
            if urls
            else ft.Container()
        )

        self.cve_list.controls.append(
            ft.ExpansionTile(
                title=header,
                controls=[
                    ft.Container(
                        content=ft.Column(
                            [
                                ft.Text(
                                    details, style=self.mono_style, selectable=True
                                ),
                                links_col,
                            ],
                            spacing=5,
                        ),
                        padding=ft.Padding.only(left=70, bottom=10),
                    )
                ],
            )
        )

        self.cve_count += 1
        self.metric_cve_badge.value = f"CVE: {self.cve_count}"

    def _append_sandbox_item(self, run: dict):
        execution_success = run.get("execution_success", False)
        crashed = run.get("crashed", False)
        exit_code = run.get("exit_code")
        sandbox_platform = run.get("sandbox_platform", "unknown")
        run_timestamp = run.get("run_timestamp")
        exploit_file_hash = run.get("exploit_file_hash", "")
        stdout = run.get("stdout", "")
        stderr = run.get("stderr", "")
        modules = run.get("modules", [])
        kernel_info = run.get("kernel_info", {})
        resources = run.get("resources", {})
        open_processes = run.get("open_processes", [])
        open_files = run.get("open_files", [])

        if crashed:
            severity = "CRASH"
            indicator_color = ft.Colors.RED_700
        elif execution_success:
            severity = "OK"
            indicator_color = ft.Colors.GREEN_700
        else:
            severity = "FAIL"
            indicator_color = ft.Colors.ORANGE_700

        timestamp_str = ""
        if run_timestamp:
            try:
                dt = datetime.fromisoformat(run_timestamp.replace("Z", "+00:00"))
                timestamp_str = dt.strftime("%H:%M:%S")
            except Exception:
                timestamp_str = (
                    run_timestamp[:19] if len(run_timestamp) >= 19 else run_timestamp
                )

        hash_short = exploit_file_hash[:12] if exploit_file_hash else "N/A"

        header = ft.Row(
            [
                ft.Container(width=4, height=14, bgcolor=indicator_color),
                ft.Text(
                    f"[{severity}]",
                    width=55,
                    style=self.mono_style,
                    color=indicator_color,
                    weight=ft.FontWeight.W_700,
                ),
                ft.Text(
                    f"[{sandbox_platform}]",
                    width=80,
                    style=self.mono_style,
                    color=ft.Colors.ON_SURFACE_VARIANT,
                ),
                ft.Text(
                    f"exit:{exit_code}",
                    width=60,
                    style=self.mono_style,
                    color=ft.Colors.ON_SURFACE_VARIANT,
                ),
                ft.Text(
                    hash_short,
                    width=100,
                    style=self.mono_style,
                    color=ft.Colors.ON_SURFACE_VARIANT,
                ),
                ft.Text(
                    timestamp_str,
                    width=60,
                    style=self.mono_style,
                    color=ft.Colors.ON_SURFACE_VARIANT,
                ),
                ft.Text(
                    f"stdout:{len(stdout)} stderr:{len(stderr)}",
                    expand=True,
                    style=self.mono_style,
                ),
            ],
            spacing=5,
        )

        detail_items = []
        if kernel_info:
            detail_items.append(
                ft.Text(
                    f"Kernel: {kernel_info.get('uname', kernel_info.get('date', 'N/A'))}",
                    style=self.mono_style,
                )
            )
        if resources:
            meminfo = resources.get("meminfo", "")
            cpuinfo = resources.get("cpuinfo", "")
            if meminfo:
                detail_items.append(
                    ft.Text(
                        f"Memory: {meminfo.split(chr(10))[0] if chr(10) in meminfo else meminfo[:80]}",
                        style=self.mono_style,
                        color=ft.Colors.ON_SURFACE_VARIANT,
                    )
                )
            if cpuinfo:
                detail_items.append(
                    ft.Text(
                        f"CPU: {cpuinfo.split(chr(10))[0] if chr(10) in cpuinfo else cpuinfo[:80]}",
                        style=self.mono_style,
                        color=ft.Colors.ON_SURFACE_VARIANT,
                    )
                )
        if modules:
            detail_items.append(
                ft.Text(
                    f"Modules: {', '.join(modules[:10])}{'...' if len(modules) > 10 else ''}",
                    style=self.mono_style,
                    color=ft.Colors.ON_SURFACE_VARIANT,
                )
            )
        if open_processes:
            detail_items.append(
                ft.Text(
                    f"Processes: {', '.join(open_processes[:5])}{'...' if len(open_processes) > 5 else ''}",
                    style=self.mono_style,
                    color=ft.Colors.ON_SURFACE_VARIANT,
                )
            )
        if open_files:
            detail_items.append(
                ft.Text(
                    f"Files: {', '.join(open_files[:5])}{'...' if len(open_files) > 5 else ''}",
                    style=self.mono_style,
                    color=ft.Colors.ON_SURFACE_VARIANT,
                )
            )
        if stdout:
            detail_items.append(
                ft.Text(
                    f"STDOUT:\n{stdout[:2000]}{'...' if len(stdout) > 2000 else ''}",
                    style=self.mono_style,
                    selectable=True,
                )
            )
        if stderr:
            detail_items.append(
                ft.Text(
                    f"STDERR:\n{stderr[:2000]}{'...' if len(stderr) > 2000 else ''}",
                    style=self.mono_style,
                    selectable=True,
                    color=ft.Colors.ERROR,
                )
            )

        detail_content = ft.Container(
            content=ft.Column(detail_items, spacing=2),
            padding=ft.Padding.only(left=90, top=5, bottom=10),
        )

        self.sandbox_list.controls.append(
            ft.ExpansionTile(
                title=header,
                controls=[detail_content],
                controls_padding=0,
                collapsed_text_color=ft.Colors.ON_SURFACE,
                text_color=ft.Colors.ON_SURFACE,
            )
        )

        self.sandbox_count += 1
        self.metric_sandbox_badge.value = f"RUNS: {self.sandbox_count}"
        self.page.update()

    def _start_local(self, _):
        self._log_terminal("Initiating local telemetry acquisition...", "INFO")
        self._show_progress("Running local recon...")
        self.page.run_task(self._process_local_scan)

    async def _process_local_scan(self):
        try:
            self._log_terminal("Current lynis conf can be a bit slow", "INFO")
            result_dt = await asyncio.to_thread(self.services.run_local_recon)

            if hasattr(result_dt, "security_recommendations"):
                sorted_recs = sorted(
                    result_dt.security_recommendations, key=self._audit_priority
                )

                for rec in sorted_recs:
                    self._append_audit_item(rec)

            if hasattr(result_dt, "possible_cves"):
                for cve in result_dt.possible_cves:
                    self._append_cve_item(
                        "LES", cve.cve_id, cve.title, cve.details, cve.download_urls
                    )

            self._log_terminal(
                f"Local recon complete. Kernel: {result_dt.kernel}", "OK"
            )
            self.page.update()
        except Exception as e:
            self._log_terminal(f"Local subsystem exploration failure: {str(e)}", "FAIL")
        finally:
            self._hide_progress()

    def _start_feeds(self, _):
        self._log_terminal("Fetching intelligence feeds (NIST/OSV/GitHub)...", "INFO")
        self.page.run_task(self._process_feeds)

    async def _process_feeds(self):
        self._show_progress("Fetching threat intel feeds...", None)
        try:
            result = await asyncio.to_thread(self.services.run_feeds_recon)

            # FIXME: nist wrong format
            for item in getattr(result, "nist", []):
                self._append_cve_item(
                    "NIST",
                    item.get("cve_id", "N/A"),
                    item.get("description", "No summary"),
                    str(item),
                    [],
                )

            for item in getattr(result, "github", []):
                urls = [item.get("url")] if item.get("url") else []
                self._append_cve_item(
                    "GHSA",
                    "N/A",
                    item.get("summary", "No summary"),
                    item.get("details", ""),
                    urls,
                )

            self._log_terminal("Threat feeds sync complete.", "OK")
            self.page.update()
        except Exception as e:
            self._log_terminal(
                f"Feed intelligence pipeline fetch aborted: {str(e)}", "FAIL"
            )
        finally:
            self._hide_progress()

    def _start_recon(self, _):
        self._log_terminal("Full cycle recon initiated...", "INFO")
        self._start_local(None)
        self._start_feeds(None)

    def _run_execution_tests(self, _):
        self._log_terminal("Invoking sandbox execution verification...", "INFO")
        self.page.run_task(self._process_execution_tests)

    async def _process_execution_tests(self):
        self._show_progress("Running sandbox execution tests...", None)
        try:
            report = await asyncio.to_thread(self.services.run_execution_tests)
            self._log_terminal(f"Verification payload complete:\n{report}", "OK")
            self._load_sandbox_runs()
        except Exception as e:
            self._log_terminal(f"Verification pipeline aborted: {str(e)}", "FAIL")
        finally:
            self._hide_progress()

    def _show_progress(self, label: str, value: float | None = None):
        self._progress_row.visible = True
        self.progress_label.value = label
        if value is not None:
            self.progress_bar.value = value
        else:
            self.progress_bar.value = None
        self.page.update()

    def _hide_progress(self):
        self._progress_row.visible = False
        self.progress_label.value = ""
        self.progress_bar.value = None
        self.page.update()

    def _load_sandbox_runs(self):
        """load sandbox run only from db"""
        try:
            vulns = self.services.db.search(has_exploit=True, limit=200)
            total_runs = 0
            for vuln in vulns:
                cve_id = vuln.get("cve_id")
                if not cve_id:
                    continue
                runs = self.services.db.get_sandbox_runs(cve_id)
                for run in runs:
                    self._append_sandbox_item(run)
                    total_runs += 1
            self._log_terminal(f"Loaded {total_runs} sandbox run(s) from DB", "INFO")
        except Exception as e:
            self._log_terminal(f"Failed to load sandbox runs: {e}", "FAIL")


__all__ = ["GUIApp", "GUI_E"]
