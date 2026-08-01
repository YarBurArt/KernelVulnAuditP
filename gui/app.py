import gi

gi.require_version("Gtk", "4.0")
import subprocess
import sys
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, cast

from gi.repository import GLib, Gtk, Pango

from app_services import AppServices
from config import (
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
from core import flatten_dict_value, update_config_file
from db.db import ThreatDB

GUI_E = True


class GUIApp:
    """GTK4-based GUI for Kernel Vulnerability Auditor"""

    _CSS = """
    .crit-badge   { color: #e01b24; font-weight: bold; font-family: monospace; font-size: 12px; }
    .warn-badge   { color: #ff7800; font-weight: bold; font-family: monospace; font-size: 12px; }
    .cve-badge    { color: #ff5f5f; font-weight: bold; font-family: monospace; font-size: 12px; }
    .runs-badge   { color: #2ec27e; font-weight: bold; font-family: monospace; font-size: 12px; }
    .mono         { font-family: monospace; font-size: 11px; }
    .mono-bold    { font-family: monospace; font-weight: 600; font-size: 11px; }
    .terminal-view{ background: #0d1117; color: #c9d1d9; font-family: monospace; font-size: 11px; }
    .terminal-fail{ color: #ff5f5f; }
    .terminal-ok  { color: #2ec27e; }
    .terminal-info{ color: #8b949e; }
    .indicator-crit { background: #e01b24; min-width: 4px; }
    .indicator-warn { background: #ff7800; min-width: 4px; }
    .indicator-ok   { background: #26a269; min-width: 4px; }
    .link-label   { color: #58a6ff; text-decoration: underline; }
    headerbar windowcontrols button.titlebutton { color: #ffffff; }
    headerbar windowcontrols button.titlebutton > image { color: #ffffff; }
    """

    def __init__(self, db: ThreatDB):
        self.services = AppServices(db=db)

        # UI refs populated in _on_activate
        self._window: Gtk.ApplicationWindow | None = None
        self._main_stack: Gtk.Stack | None = None

        # Scan page refs
        self._audit_list: Gtk.ListBox | None = None
        self._cve_list: Gtk.ListBox | None = None
        self._sandbox_list: Gtk.ListBox | None = None
        self._console_view: Gtk.TextView | None = None
        self._console_buffer: Gtk.TextBuffer | None = None
        self._progress_bar: Gtk.ProgressBar | None = None
        self._progress_label: Gtk.Label | None = None
        self._progress_box: Gtk.Box | None = None

        # Metrics-like for status
        self._fail_label: Gtk.Label | None = None
        self._warn_label: Gtk.Label | None = None
        self._cve_label: Gtk.Label | None = None
        self._sandbox_label: Gtk.Label | None = None
        self.fail_count = 0
        self.warn_count = 0
        self.cve_count = 0
        self.sandbox_count = 0
        self._settings_fields: dict[str, Any] = {}
        self._report_buffer: Gtk.TextBuffer | None = None

        self._css_provider = Gtk.CssProvider()
        self._css_provider.load_from_data(self._CSS.encode())

    def run(self):
        app = Gtk.Application(application_id="org.kernelvulnauditp.GUI")
        app.connect("activate", self._on_activate)
        app.run(None)

    def _on_activate(self, app: Gtk.Application):
        self._window = Gtk.ApplicationWindow(
            application=app, title="Kernel Vulnerability Auditor"
        )
        assert self._window is not None
        self._window.set_default_size(1100, 750)

        # CSS and icon theme when display is available
        display = self._window.get_display()
        if display is not None:
            Gtk.StyleContext.add_provider_for_display(
                display,
                self._css_provider,
                Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
            )
        gtk_settings = Gtk.Settings.get_for_display(display) if display else None
        if gtk_settings is not None:
            gtk_settings.set_property("gtk-icon-theme-name", "Adwaita")

        self._window.set_titlebar(self._build_header_bar())

        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self._window.set_child(root)

        self._main_stack = Gtk.Stack()
        assert self._main_stack is not None
        self._main_stack.set_transition_type(Gtk.StackTransitionType.SLIDE_LEFT_RIGHT)
        self._main_stack.connect("notify::visible-child-name", self._on_stack_changed)
        root.append(self._main_stack)

        self._main_stack.add_titled(self._build_scan_page(), "scan", "Scan")
        self._main_stack.add_titled(self._build_report_page(), "report", "Report")
        self._main_stack.add_titled(self._build_settings_page(), "settings", "Settings")

        self._window.present()

    def _build_header_bar(self) -> Gtk.HeaderBar:
        header = Gtk.HeaderBar()
        header.set_show_title_buttons(True)

        for label, page in (
            ("Scan", "scan"),
            ("Report", "report"),
            ("Settings", "settings"),
        ):
            btn = Gtk.Button(label=label)
            btn.connect(
                "clicked",
                lambda _b, name=page: (
                    self._main_stack.set_visible_child_name(name)
                    if self._main_stack
                    else None
                ),
            )
            header.pack_start(btn)
        return header

    def _on_stack_changed(self, stack: Gtk.Stack, _pspec):
        if stack.get_visible_child_name() == "report":
            if self._report_buffer is not None:
                self._report_buffer.set_text("")
            self._generate_report(None)

    def _build_scan_page(self) -> Gtk.Widget:
        builder = Gtk.Builder()
        ui_path = Path("gui/scan_page.ui")
        if not ui_path.exists():
            raise FileNotFoundError(
                f"UI file not found at {ui_path}. Ensure it is next to app.py."
            )
        builder.add_from_file(str(ui_path))

        self._audit_list = cast(Gtk.ListBox, builder.get_object("audit_list"))
        self._cve_list = cast(Gtk.ListBox, builder.get_object("cve_list"))
        self._sandbox_list = cast(Gtk.ListBox, builder.get_object("sandbox_list"))
        self._console_view = cast(Gtk.TextView, builder.get_object("console_view"))
        assert self._console_view is not None
        self._console_buffer = self._console_view.get_buffer()

        for tag, color in (
            ("fail", "#ff5f5f"),
            ("ok", "#2ec27e"),
            ("info", "#8b949e"),
        ):
            assert self._console_buffer is not None
            self._console_buffer.create_tag(tag, foreground=color)

        self._progress_box = cast(Gtk.Box, builder.get_object("progress_box"))
        self._progress_bar = cast(Gtk.ProgressBar, builder.get_object("progress_bar"))
        self._progress_label = cast(Gtk.Label, builder.get_object("progress_label"))

        self._fail_label = cast(Gtk.Label, builder.get_object("fail_label"))
        self._warn_label = cast(Gtk.Label, builder.get_object("warn_label"))
        self._cve_label = cast(Gtk.Label, builder.get_object("cve_label"))
        self._sandbox_label = cast(Gtk.Label, builder.get_object("sandbox_label"))

        local_btn = cast(Gtk.Button, builder.get_object("local_btn"))
        local_btn.connect("clicked", self._start_local)

        feeds_btn = cast(Gtk.Button, builder.get_object("feeds_btn"))
        feeds_btn.connect("clicked", self._start_feeds)

        full_btn = cast(Gtk.Button, builder.get_object("full_btn"))
        full_btn.connect("clicked", self._start_recon)

        exec_btn = cast(Gtk.Button, builder.get_object("exec_btn"))
        exec_btn.connect("clicked", self._run_execution_tests)

        return cast(Gtk.Widget, builder.get_object("scan_page"))

    def _build_report_page(self) -> Gtk.Widget:
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        page.set_margin_top(8)
        page.set_margin_bottom(8)
        page.set_margin_start(8)
        page.set_margin_end(8)

        title = Gtk.Label(label="Vulnerability Report")
        title.add_css_class("title-2")
        page.append(title)

        self._report_text = Gtk.TextView()
        self._report_text.set_editable(False)
        self._report_text.set_monospace(True)
        self._report_text.set_vexpand(True)
        self._report_buffer = self._report_text.get_buffer()

        sw = Gtk.ScrolledWindow()
        sw.set_vexpand(True)
        sw.set_child(self._report_text)
        page.append(sw)

        gen_btn = Gtk.Button(label="Regenerate Report")
        gen_btn.connect("clicked", self._generate_report)
        gen_btn.add_css_class("suggested-action")
        gen_btn.set_halign(Gtk.Align.START)
        page.append(gen_btn)

        return page

    def _generate_report(self, _btn):
        self._append_report_text("Launching report generation...\n")

        def target():
            try:
                report_path = Path(__file__).parent.parent / "report.py"
                if not report_path.exists():
                    raise FileNotFoundError("report.py not found")

                try:
                    import streamlit  # noqa: F401
                except ImportError:
                    pass
                else:
                    GLib.idle_add(
                        self._append_report_text, "Launching Streamlit report...\n"
                    )
                    subprocess.Popen(
                        [sys.executable, "-m", "streamlit", "run", str(report_path)],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    GLib.idle_add(
                        self._append_report_text,
                        "Streamlit report launched at http://localhost:8501\n",
                    )
                    GLib.idle_add(
                        self._append_report_text,
                        "Close this window to stop the report server\n",
                    )
                    return

                GLib.idle_add(
                    self._append_report_text,
                    "Streamlit not available, running CLI report...\n",
                )
                output = self._run_cli_report_sync()
                GLib.idle_add(self._append_report_text, output)
            except Exception as e:
                GLib.idle_add(self._append_report_text, f"Report error: {e}\n")
                output = self._run_cli_report_sync()
                GLib.idle_add(self._append_report_text, output)

        threading.Thread(target=target, daemon=True).start()

    @staticmethod
    def _run_cli_report_sync() -> str:
        try:
            from db import get_db
            from report import CLIReportRenderer, build_report_data

            db = get_db("orm")
            data = build_report_data(db)
            db.close()

            renderer = CLIReportRenderer(data, verbose=True)
            return renderer.build_full_report() + "\nReport generated (CLI mode)\n"
        except Exception as e:
            return f"CLI report error: {e}\n"

    def _append_report_text(self, text: str):
        buf = self._report_buffer
        if buf is None:
            return
        end = buf.get_end_iter()
        buf.insert(end, text)

    def _build_settings_page(self) -> Gtk.Widget:
        builder = Gtk.Builder()
        ui_path = Path(__file__).parent / "settings_page.ui"
        if not ui_path.exists():
            raise FileNotFoundError(
                f"UI file not found at {ui_path}. Ensure it is next to app.py."
            )
        builder.add_from_file(str(ui_path))

        db_dropdown = cast(Gtk.DropDown, builder.get_object("db_dropdown"))
        log_dropdown = cast(Gtk.DropDown, builder.get_object("log_dropdown"))
        to_entry = cast(Gtk.Entry, builder.get_object("to_entry"))
        exec_switch = cast(Gtk.Switch, builder.get_object("exec_switch"))

        db_map = {0: "orm", 1: "memory"}
        log_map = {0: "DEBUG", 1: "INFO", 2: "WARNING", 3: "ERROR", 4: "CRITICAL"}

        db_dropdown.set_selected({"orm": 0, "memory": 1}.get(DB_BACKEND, 0))
        log_dropdown.set_selected(
            {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3, "CRITICAL": 4}.get(
                LOG_LEVEL, 1
            )
        )
        to_entry.set_text(str(ISOLATION_TIMEOUT_SEC))
        exec_switch.set_active(ALLOW_HOST_EXECUTION)

        self._settings_fields["DB_BACKEND"] = (db_dropdown, db_map)
        self._settings_fields["LOG_LEVEL"] = (log_dropdown, log_map)
        self._settings_fields["ISOLATION_TIMEOUT_SEC"] = to_entry
        self._settings_fields["ALLOW_HOST_EXECUTION"] = exec_switch

        path_ids = [
            ("CISA_KEV_PATH", "entry_cisa", CISA_KEV_PATH),
            ("LYNIS_REPORT_FILE", "entry_lynis_rep", LYNIS_REPORT_FILE),
            ("LYNIS_LOG_FILE", "entry_lynis_log", LYNIS_LOG_FILE),
            ("LINPEAS_OUT_JSON", "entry_linpeas_out", LINPEAS_OUT_JSON),
            ("PATH_LINPEAS", "entry_linpeas_path", PATH_LINPEAS),
            ("LES_PATH", "entry_les", LES_PATH),
            ("LES_REPORT_PATH", "entry_les_rep", LES_REPORT_PATH),
            ("POCS_BASE_PATH", "entry_pocs", POCS_BASE_PATH),
        ]

        for key, id_str, value in path_ids:
            entry = cast(Gtk.Entry, builder.get_object(id_str))
            entry.set_text(value)
            self._settings_fields[key] = entry

        save_btn = cast(Gtk.Button, builder.get_object("save_btn"))
        save_btn.connect("clicked", self._save_settings)
        cancel_btn = cast(Gtk.Button, builder.get_object("cancel_btn"))
        cancel_btn.connect(
            "clicked",
            lambda _: (
                self._main_stack.set_visible_child_name("scan")
                if self._main_stack
                else None
            ),
        )

        return cast(Gtk.Widget, builder.get_object("settings_page_sw"))

    def _save_settings(self, _btn):
        try:
            config_path = Path(__file__).parent.parent / "config.py"

            db_dropdown, db_map = self._settings_fields["DB_BACKEND"]
            log_dropdown, log_map = self._settings_fields["LOG_LEVEL"]

            updates = {
                "DB_BACKEND": f'"{db_map[db_dropdown.get_selected()]}"',
                "ISOLATION_TIMEOUT_SEC": self._settings_fields[
                    "ISOLATION_TIMEOUT_SEC"
                ].get_text(),
                "ALLOW_HOST_EXECUTION": str(
                    self._settings_fields["ALLOW_HOST_EXECUTION"].get_active()
                ),
                "LOG_LEVEL": f'"{log_map[log_dropdown.get_selected()]}"',
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
                updates[key] = f'"{self._settings_fields[key].get_text()}"'

            update_config_file(config_path, updates)
            self._log_terminal("Settings saved successfully!", "OK")
            self._log_terminal(
                "Note: Some settings may require restart to take effect", "INFO"
            )
        except Exception as e:
            self._log_terminal(f"Error saving settings: {e}", "FAIL")

    def _run_async(self, fn, on_done=None, on_error=None):
        """Run task in a background thread and marshal results to GTK main loop"""

        def target():
            try:
                result = fn()
                if on_done is not None:
                    cb = on_done

                    def _done_cb():
                        cb(result)
                        return False

                    GLib.idle_add(_done_cb)
            except Exception as exc:
                if on_error is not None:
                    cb = on_error

                    def _cb(exc=exc):
                        cb(exc)
                        return False

                    GLib.idle_add(_cb)
                else:

                    def _cb(exc=exc):
                        self._log_terminal(f"Async error: {exc}", "FAIL")
                        return False

                    GLib.idle_add(_cb)

        threading.Thread(target=target, daemon=True).start()

    def _start_local(self, _btn):
        self._log_terminal("Initiating local telemetry acquisition...", "INFO")
        self._show_progress("Running local recon...")
        self._run_async(self.services.run_local_recon, self._on_local_done)

    def _on_local_done(self, result_dt):
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
        self._log_terminal(f"Local recon complete. Kernel: {result_dt.kernel}", "OK")
        self._hide_progress()

    def _start_feeds(self, _btn):
        self._log_terminal("Fetching intelligence feeds (NIST/OSV/GitHub)...", "INFO")
        self._show_progress("Fetching threat intel feeds...")
        self._run_async(self.services.run_feeds_recon, self._on_feeds_done)

    def _on_feeds_done(self, result):
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
        self._hide_progress()

    def _start_recon(self, _btn):
        self._log_terminal("Full cycle recon initiated...", "INFO")
        self._start_local(None)
        self._start_feeds(None)

    def _run_execution_tests(self, _btn):
        self._log_terminal("Invoking sandbox execution verification...", "INFO")
        self._show_progress("Running sandbox execution tests...")
        self._run_async(self.services.run_execution_tests, self._on_exec_done)

    def _on_exec_done(self, report):
        self._log_terminal(f"Verification payload complete:\n{report}", "OK")
        self._load_sandbox_runs()
        self._hide_progress()

    def _show_progress(self, label: str, value: float | None = None):
        if self._progress_box is None:
            return
        self._progress_box.set_visible(True)
        if self._progress_label is not None:
            self._progress_label.set_label(label)
        if value is not None:
            if self._progress_bar is not None:
                self._progress_bar.set_fraction(value)
        else:
            if self._progress_bar is not None:
                self._progress_bar.pulse()

    def _hide_progress(self):
        if self._progress_box is None:
            return
        self._progress_box.set_visible(False)
        if self._progress_label is not None:
            self._progress_label.set_label("")
        if self._progress_bar is not None:
            self._progress_bar.set_fraction(0.0)

    @staticmethod
    def _audit_priority(rec) -> tuple[int, str]:
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
        if self._audit_list is None:
            return
        severity = "INFO"
        indicator_css = "indicator-ok"

        try:
            diff = abs(int(float(rec.expected_value)) - int(float(rec.actual_value)))
            if diff >= 2:
                severity = "CRIT"
                indicator_css = "indicator-crit"
            elif diff == 1:
                severity = "WARN"
                indicator_css = "indicator-warn"
        except TypeError, ValueError:
            if rec.status == "FAIL":
                severity = "CRIT"
                indicator_css = "indicator-crit"
            elif rec.status == "WARNING":
                severity = "WARN"
                indicator_css = "indicator-warn"

        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=5)

        indicator = Gtk.Box()
        indicator.set_size_request(4, 14)
        indicator.add_css_class(indicator_css)

        sev_lbl = Gtk.Label(label=f"[{severity}]")
        sev_lbl.set_width_chars(6)
        sev_lbl.add_css_class(
            "crit-badge"
            if severity == "CRIT"
            else "warn-badge"
            if severity == "WARN"
            else "mono"
        )

        id_lbl = Gtk.Label(label=f"[{rec.test_id}]")
        id_lbl.set_width_chars(12)
        id_lbl.add_css_class("mono")

        field_lbl = Gtk.Label(label=rec.field_name or rec.category)
        field_lbl.set_width_chars(30)
        field_lbl.set_xalign(0.0)
        field_lbl.add_css_class("mono-bold")

        desc_lbl = Gtk.Label(label=rec.description)
        desc_lbl.set_xalign(0.0)
        desc_lbl.set_hexpand(True)
        desc_lbl.set_ellipsize(Pango.EllipsizeMode.END)
        desc_lbl.add_css_class("mono")

        header.append(indicator)
        header.append(sev_lbl)
        header.append(id_lbl)
        header.append(field_lbl)
        header.append(desc_lbl)

        details = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        details.set_margin_start(60)
        details.set_margin_top(4)
        details.set_margin_bottom(8)

        if rec.expected_value or rec.actual_value:
            val_lbl = Gtk.Label(
                label=f"Expected: {rec.expected_value} | Actual: {rec.actual_value}"
            )
            val_lbl.set_xalign(0.0)
            val_lbl.add_css_class("mono")
            details.append(val_lbl)

        suggestion = rec.raw_data.get(
            "suggestion",
            rec.raw_data.get("details", rec.raw_data.get("solution", "N/A")),
        )

        if self._is_url(suggestion):
            sugg_lbl = self._make_link(suggestion)
        else:
            sugg_lbl = Gtk.Label(label=f"Details: {suggestion}")
            sugg_lbl.set_xalign(0.0)
            sugg_lbl.add_css_class("mono")
        details.append(sugg_lbl)

        expander = Gtk.Expander()
        expander.set_label_widget(header)
        expander.set_child(details)

        row = Gtk.ListBoxRow()
        row.set_child(expander)
        self._audit_list.append(row)

        if severity == "CRIT":
            self.fail_count += 1
            if self._fail_label is not None:
                self._fail_label.set_label(f"CRIT: {self.fail_count}")
        elif severity == "WARN":
            self.warn_count += 1
            if self._warn_label is not None:
                self._warn_label.set_label(f"WARN: {self.warn_count}")

    def _append_cve_item(
        self, source: str, cve_id: str, title: str, details: str, urls: list
    ):
        if self._cve_list is None:
            return
        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=5)

        indicator = Gtk.Box()
        indicator.set_size_request(4, 14)
        indicator.add_css_class("indicator-crit")

        src_lbl = Gtk.Label(label=f"[{source}]")
        src_lbl.set_width_chars(8)
        src_lbl.add_css_class("mono")

        cve_lbl = Gtk.Label(label=cve_id)
        cve_lbl.set_width_chars(15)
        cve_lbl.set_xalign(0.0)
        cve_lbl.add_css_class("mono-bold")

        title_lbl = Gtk.Label(label=title)
        title_lbl.set_xalign(0.0)
        title_lbl.set_hexpand(True)
        title_lbl.set_ellipsize(Pango.EllipsizeMode.END)
        title_lbl.add_css_class("mono")

        header.append(indicator)
        header.append(src_lbl)
        header.append(cve_lbl)
        header.append(title_lbl)

        detail_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        detail_box.set_margin_top(4)
        detail_box.set_margin_bottom(8)

        details_lbl = Gtk.Label(label=details)
        details_lbl.set_xalign(0.0)
        details_lbl.set_wrap(True)
        details_lbl.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
        details_lbl.set_selectable(True)
        details_lbl.add_css_class("mono")
        detail_box.append(details_lbl)

        for url in urls:
            link = Gtk.LinkButton.new_with_label(url, url)
            link.add_css_class("mono")
            detail_box.append(link)

        expander = Gtk.Expander()
        expander.set_label_widget(header)
        expander.set_child(detail_box)

        row = Gtk.ListBoxRow()
        row.set_child(expander)
        self._cve_list.append(row)

        self.cve_count += 1
        if self._cve_label is not None:
            self._cve_label.set_label(f"CVE: {self.cve_count}")

    def _append_sandbox_item(self, run: dict):
        if self._sandbox_list is None:
            return
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
            indicator_css = "indicator-crit"
        elif execution_success:
            severity = "OK"
            indicator_css = "indicator-ok"
        else:
            severity = "FAIL"
            indicator_css = "indicator-warn"

        timestamp_str = ""
        if run_timestamp:
            try:
                dt = datetime.fromisoformat(run_timestamp.replace("Z", "+00:00"))
                timestamp_str = dt.strftime("%H:%M:%S")
            except Exception:
                assert run_timestamp is not None
                timestamp_str = (
                    run_timestamp[:19] if len(run_timestamp) >= 19 else run_timestamp
                )

        hash_short = exploit_file_hash[:12] if exploit_file_hash else "N/A"

        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=5)

        indicator = Gtk.Box()
        indicator.set_size_request(4, 14)
        indicator.add_css_class(indicator_css)

        sev_lbl = Gtk.Label(label=f"[{severity}]")
        sev_lbl.set_width_chars(7)
        sev_lbl.add_css_class(
            "crit-badge"
            if severity == "CRASH"
            else "runs-badge"
            if severity == "OK"
            else "warn-badge"
        )

        plat_lbl = Gtk.Label(label=f"[{sandbox_platform}]")
        plat_lbl.set_width_chars(10)
        plat_lbl.add_css_class("mono")

        exit_lbl = Gtk.Label(label=f"exit:{exit_code}")
        exit_lbl.set_width_chars(8)
        exit_lbl.add_css_class("mono")

        hash_lbl = Gtk.Label(label=hash_short)
        hash_lbl.set_width_chars(14)
        hash_lbl.add_css_class("mono")

        time_lbl = Gtk.Label(label=timestamp_str)
        time_lbl.set_width_chars(8)
        time_lbl.add_css_class("mono")

        io_lbl = Gtk.Label(label=f"stdout:{len(stdout)} stderr:{len(stderr)}")
        io_lbl.set_hexpand(True)
        io_lbl.set_xalign(0.0)
        io_lbl.add_css_class("mono")

        header.append(indicator)
        header.append(sev_lbl)
        header.append(plat_lbl)
        header.append(exit_lbl)
        header.append(hash_lbl)
        header.append(time_lbl)
        header.append(io_lbl)

        details = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        details.set_margin_start(70)
        details.set_margin_top(4)
        details.set_margin_bottom(8)

        if kernel_info:
            k_lbl = Gtk.Label(
                label=f"Kernel: {kernel_info.get('uname', kernel_info.get('date', 'N/A'))}"
            )
            k_lbl.set_xalign(0.0)
            k_lbl.add_css_class("mono")
            details.append(k_lbl)

        if resources:
            meminfo = resources.get("meminfo", "")
            cpuinfo = resources.get("cpuinfo", "")
            if meminfo:
                first = meminfo.split("\n")[0] if "\n" in meminfo else meminfo[:80]
                m_lbl = Gtk.Label(label=f"Memory: {first}")
                m_lbl.set_xalign(0.0)
                m_lbl.add_css_class("mono")
                details.append(m_lbl)
            if cpuinfo:
                first = cpuinfo.split("\n")[0] if "\n" in cpuinfo else cpuinfo[:80]
                c_lbl = Gtk.Label(label=f"CPU: {first}")
                c_lbl.set_xalign(0.0)
                c_lbl.add_css_class("mono")
                details.append(c_lbl)

        if modules:
            txt = ", ".join(modules[:10]) + ("..." if len(modules) > 10 else "")
            m_lbl = Gtk.Label(label=f"Modules: {txt}")
            m_lbl.set_xalign(0.0)
            m_lbl.add_css_class("mono")
            details.append(m_lbl)

        if open_processes:
            txt = ", ".join(open_processes[:5]) + (
                "..." if len(open_processes) > 5 else ""
            )
            p_lbl = Gtk.Label(label=f"Processes: {txt}")
            p_lbl.set_xalign(0.0)
            p_lbl.add_css_class("mono")
            details.append(p_lbl)

        if open_files:
            txt = ", ".join(open_files[:5]) + ("..." if len(open_files) > 5 else "")
            f_lbl = Gtk.Label(label=f"Files: {txt}")
            f_lbl.set_xalign(0.0)
            f_lbl.add_css_class("mono")
            details.append(f_lbl)

        if stdout:
            out_lbl = Gtk.Label(
                label=f"STDOUT:\n{stdout[:2000]}{'...' if len(stdout) > 2000 else ''}"
            )
            out_lbl.set_xalign(0.0)
            out_lbl.set_selectable(True)
            out_lbl.set_wrap(True)
            out_lbl.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
            out_lbl.add_css_class("mono")
            details.append(out_lbl)

        if stderr:
            err_lbl = Gtk.Label(
                label=f"STDERR:\n{stderr[:2000]}{'...' if len(stderr) > 2000 else ''}"
            )
            err_lbl.set_xalign(0.0)
            err_lbl.set_selectable(True)
            err_lbl.set_wrap(True)
            err_lbl.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
            err_lbl.add_css_class("mono")
            err_lbl.add_css_class("terminal-fail")
            details.append(err_lbl)

        expander = Gtk.Expander()
        expander.set_label_widget(header)
        expander.set_child(details)

        row = Gtk.ListBoxRow()
        row.set_child(expander)
        self._sandbox_list.append(row)

        self.sandbox_count += 1
        if self._sandbox_label is not None:
            self._sandbox_label.set_label(f"RUNS: {self.sandbox_count}")

    def _log_terminal(self, message: str, level: str = "INFO"):
        tag = {
            "FAIL": "fail",
            "OK": "ok",
            "INFO": "info",
        }.get(level, "info")

        buf = self._console_buffer
        if buf is None:
            return
        end = buf.get_end_iter()
        buf.insert_with_tags_by_name(end, f"[{level}] {message}\n", tag)

        insert = buf.get_insert()
        if self._console_view is not None:
            self._console_view.scroll_to_mark(insert, 0.0, False, 0.0, 0.0)

    def _append_log(self, item):
        """Compatibility shim: old code called this with strings/dicts."""
        text = str(item) if not isinstance(item, str) else item
        self._log_terminal(text, "INFO")

    def _load_sandbox_runs(self):
        try:
            vulns = self.services.db.search(has_exploit=True, limit=200)
            total = 0
            for vuln in vulns:
                cve_id: str | None = vuln.get("cve_id")
                if not cve_id:
                    continue
                assert cve_id is not None
                for run in self.services.db.get_sandbox_runs(cve_id):
                    self._append_sandbox_item(run)
                    total += 1
            self._log_terminal(f"Loaded {total} sandbox run(s) from DB", "INFO")
        except Exception as e:
            self._log_terminal(f"Failed to load sandbox runs: {e}", "FAIL")

    def _save_to_db(self, _):
        pass  # FIXME

    @staticmethod
    def _get_cell_text(v: Any) -> str:
        return flatten_dict_value(v)

    @staticmethod
    def _is_url(text: str) -> bool:
        if not isinstance(text, str):
            return False
        return text.startswith(("http://", "https://")) and len(text) > 8

    @staticmethod
    def _make_link(url: str) -> Gtk.LinkButton:
        return Gtk.LinkButton.new_with_label(url, url)


__all__ = ["GUI_E", "GUIApp"]
