"""Scan page controller, wires AppServices concurrent results into the TUI page"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

from textual.containers import VerticalScroll
from textual.css.query import NoMatches

from core import format_execution_report
from gui.entities.sandbox_runs import SandboxRun
from gui.entities.scan_result import FeedsSnapshot, ScanSnapshot
from gui.entities.services import Services
from gui.shared.formatting import dedupe_links, rec_severity
from gui.widgets.audit_item import AuditItem, CapsItem
from gui.widgets.cve_item import CveItem
from gui.widgets.references_bar import ReferencesBar
from gui.widgets.sandbox_item import SandboxItem
from report.diff import build_capability_section
from term import unicode_glyph

if TYPE_CHECKING:
    from gui.tui import KernelVulnTUI

logger = logging.getLogger("kernel_audit.gui")

AUDIT = "audit_list"
SELINUX = "selinux_list"
CAPS = "caps_list"
CVE = "cve_list"
SANDBOX = "sandbox_list"


class ScanController:
    """Runs scan flows and renders their results into the scan page lists on each tab"""

    def __init__(self, app: KernelVulnTUI, services: Services) -> None:
        self._app = app
        self.services = services
        self._recon_done: set[str] = set()
        self._running: set[str] = set()
        self._recon_summaries: dict[str, str] = {}

    def start_local(self) -> None:
        self._running.add("local")
        self._app.set_stage("local", "running")
        self._app.log_terminal("Initiating local telemetry acquisition...", "INFO")
        self._app.show_progress("Running local recon...")
        self._run(self.services.run_local_recon, self._on_local_done, "local")

    def start_feeds(self) -> None:
        self._running.add("feeds")
        self._app.set_stage("feeds", "running")
        self._app.log_terminal("Fetching intelligence feeds (KEV/NIST/OSV/GitHub)...", "INFO")
        self._app.show_progress("Fetching threat intel feeds...")
        self._run(self.services.run_feeds_recon, self._on_feeds_done, "feeds")

    def start_recon(self) -> None:
        self._recon_done = set()
        self._running.update(("local", "feeds", "full"))
        for key in ("local", "feeds", "full"):
            self._app.set_stage(key, "running")
        self._app.log_terminal("Full cycle recon initiated...", "INFO")
        self._app.show_progress("Full cycle recon initiated...")
        self._run(
            self.services.run_local_recon, self._on_local_done, "local", parent="full"
        )
        self._run(
            self.services.run_feeds_recon, self._on_feeds_done, "feeds", parent="full"
        )

    def start_exec(self) -> None:
        self._running.add("exec")
        self._app.set_stage("exec", "running")
        self._app.log_terminal("Invoking sandbox execution verification...", "INFO")
        self._app.show_progress("Running sandbox execution tests...")
        self._run(self.services.run_execution_tests, self._on_exec_done, "exec")

    def _run(
        self,
        fn,
        on_done,
        key: str,
        parent: str | None = None,
    ) -> None:
        """Run fn off the UI thread, on failure fail only its own stage tree"""

        def _on_err(exc: Exception) -> None:
            self._app.hide_progress()
            msg = str(exc).strip() or repr(exc)
            self._app.log_terminal(f"Async error: {msg}", "FAIL")
            for k in (key, parent):
                if k is None:
                    continue
                self._running.discard(k)
                self._app.set_stage(k, "fail")

        self._app.run_task(fn, on_done, _on_err)

    @staticmethod
    def _findings(recs: list) -> list:
        """filter non-actionable rows (CRIT/WARN)"""
        ranked = [
            (rec_severity(rec)[0], str(rec.field_name or rec.category or "").lower(), rec)
            for rec in recs or []
            if rec_severity(rec)[0] != "INFO"
        ]
        order = {"CRIT": 0, "WARN": 1}
        ranked.sort(key=lambda item: (order.get(item[0], 2), item[1]))
        return [item[2] for item in ranked]

    @staticmethod
    def _field_width(recs: list) -> int:
        """widest field label in the list, so the diff column lines up for TUI table like"""
        width = 12
        for rec in recs or []:
            name = str(rec.field_name or rec.category or "")
            width = max(width, len(name))
        return min(width + 1, 64)

    @staticmethod
    def _value_widths(recs: list) -> tuple[int, int]:
        """Per-list expected/actual column widths, without gap"""
        exp_w = act_w = 1
        for rec in recs or []:
            expected = str(getattr(rec, "expected_value", "") or "").strip()
            actual = str(getattr(rec, "actual_value", "") or "").strip()
            exp_w = max(exp_w, len(expected))
            act_w = max(act_w, len(actual or "missing"))
        return min(exp_w, 16), min(act_w, 24)

    @staticmethod
    def _cap_rows_from_recs(recs: list) -> list[dict]:
        """Capability findings as report-style diff rows for dedup later"""
        rows: list[dict] = []
        for rec in recs or []:
            names = sorted({c for c in str(rec.actual_value or "").split(",") if c})
            if not names:
                continue
            key = str(rec.field_name or rec.category or "?")
            source = str(getattr(rec, "source", "") or "")
            raw = getattr(rec, "raw_data", {}) or {}
            if isinstance(raw, dict) and source == "proc":
                detail = f"process capabilities (owner: {raw.get('username') or '?'})"
            else:
                owner = "?"
                m = re.search(r"owner:\s*([^)]+)", str(rec.description or ""))
                if m:
                    owner = m.group(1).strip()
                detail = f"file capabilities (owner: {owner})"
            rows.append(
                {
                    "type": "capability",
                    "key": key,
                    "expected": "none",
                    "actual": ",".join(names),
                    "status": str(rec.status or "WARNING").upper(),
                    "detail": detail,
                }
            )
        return rows

    def _on_local_done(self, result) -> None:
        summary = ""
        try:
            for name in (AUDIT, SELINUX, CAPS, CVE):
                self._clear(name)

            crit = warn = 0
            snapshot = ScanSnapshot.from_local(result)
            audit = self._findings(snapshot.audit)
            selinux = self._findings(snapshot.selinux)
            caps_findings = self._findings(snapshot.caps)
            cap_groups = build_capability_section(
                self._cap_rows_from_recs(caps_findings)
            )["rows"]

            for rec in audit + selinux:
                severity, _ = rec_severity(rec)
                crit += severity == "CRIT"
                warn += severity == "WARN"
            for group in cap_groups:
                if str(group.get("status") or "").lower() == "fail":
                    crit += 1
                else:
                    warn += 1

            self._set_references(AUDIT, snapshot.audit)
            exp_w, act_w = self._value_widths(audit)
            self._mount(
                AUDIT,
                [AuditItem(rec, self._field_width(audit), exp_w, act_w) for rec in audit],
            )
            self._set_references(SELINUX, snapshot.selinux)
            exp_w, act_w = self._value_widths(selinux)
            self._mount(
                SELINUX,
                [
                    AuditItem(rec, self._field_width(selinux), exp_w, act_w)
                    for rec in selinux
                ],
            )
            self._set_references(CAPS, snapshot.caps)

            # calculate suitable width for capabilities
            cap_name_lengths = [
                len(str(group.get("right") or "")) for group in cap_groups
            ]
            max_cap_name_width = max(cap_name_lengths, default=12)
            cap_width = min(max_cap_name_width + 1, 64)

            self._mount(CAPS, [CapsItem(group, cap_width) for group in cap_groups])
            cve_items = [
                CveItem(
                    "LES",
                    cve.cve_id,
                    cve.title,
                    cve.details,
                    list(cve.download_urls or []),
                )
                for cve in sorted(
                    snapshot.cves, key=lambda c: str(c.cve_id or "").lower()
                )
            ]
            self._mount(CVE, cve_items)

            self._app.log_terminal(
                f"Local recon complete. Kernel: {snapshot.kernel}", "OK"
            )
            self._app.set_metrics(crit=crit, warn=warn, cve=len(cve_items))
            summary = (
                f"{len(audit) + len(selinux) + len(cap_groups)} hardening"
                f", {len(cve_items)} CVEs"
            )
        except (TypeError, ValueError, AttributeError, KeyError, NoMatches, OSError):
            logger.exception("local recon render failed")
            self._app.log_terminal("Local recon render error", "FAIL")
        finally:
            self._app.hide_progress()
            self._finish_stage("local", summary)

    def _on_feeds_done(self, result) -> None:
        summary = ""
        try:
            snapshot = FeedsSnapshot.from_feeds(result)
            cve_list = self._list(CVE)
            items: list[CveItem] = []
            for finding in snapshot.findings:
                items.append(
                    CveItem(
                        finding.source or "NIST",
                        finding.cve_id,
                        finding.description or "No summary",
                        str(finding.raw_data)
                        if finding.raw_data
                        else (finding.description or ""),
                        list(finding.references or []),
                    )
                )
            for poc in snapshot.pocs:
                urls = [poc.repo_url] if poc.repo_url else []
                items.append(
                    CveItem(
                        "GHSA",
                        poc.cve_id or "N/A",
                        poc.repo_name or "No summary",
                        poc.description or "",
                        urls,
                    )
                )
            if items:
                cve_list.mount(*items)
            cve_list.sort_children(key=lambda c: str(getattr(c, "cve_id", "")).lower())

            self._app.log_terminal("Threat feeds sync complete.", "OK")
            self._app.set_metrics(cve=len(cve_list.children))
            summary = f"{len(cve_list.children)} CVEs"
        except (TypeError, ValueError, AttributeError, KeyError, NoMatches, OSError):
            logger.exception("feeds recon render failed")
            self._app.log_terminal("Feeds recon render error", "FAIL")
        finally:
            self._app.hide_progress()
            self._finish_stage("feeds", summary)

    def _on_exec_done(self, report: dict) -> None:
        summary = ""
        try:
            entries = report.get("entries", [])
            runs = sum(len(entry.get("pocs", [])) for entry in entries)
            self._app.log_terminal(
                f"Verification payload complete: {len(entries)} CVEs, {runs} PoC runs",
                "OK",
            )
            logger.debug(
                "Execution report:\n%s",
                format_execution_report(report),
                extra={"skip_console": True},
            )
            self._clear(SANDBOX)
            sandbox_runs = SandboxRun.from_exec_report(report)
            sandbox_runs.sort(
                key=lambda r: (str(r.cve_id or "").lower(), r.run_timestamp)
            )
            self._mount(SANDBOX, [SandboxItem(run) for run in sandbox_runs])
            failed = sum(1 for run in sandbox_runs if not run.execution_success)
            self._app.set_metrics(runs=len(sandbox_runs))
            summary = f"{len(sandbox_runs)} PoC runs"
            if failed:
                summary += f", {failed} failed"
        except (TypeError, ValueError, AttributeError, KeyError, NoMatches, OSError):
            logger.exception("exec tests render failed")
            self._app.log_terminal("Exec tests render error", "FAIL")
        finally:
            self._app.hide_progress()
            self._finish_stage("exec", summary)

    def _finish_stage(self, key: str, summary: str = "") -> None:
        """Mark a stage done; if local+feeds done, the full cycle is done too."""
        self._recon_done.add(key)
        self._running.discard(key)
        self._app.set_stage(key, "done")
        if summary:
            self._recon_summaries[key] = summary
            self._app.set_stage_summary(key, summary)
        if {"local", "feeds"} <= self._recon_done:
            self._running.discard("full")
            self._app.set_stage("full", "done")
            local = self._recon_summaries.get("local", "")
            feeds = self._recon_summaries.get("feeds", "")
            if local or feeds:
                self._app.set_stage_summary(
                    "full",
                    f" {unicode_glyph('·', '.')} ".join(p for p in (local, feeds) if p),
                )
    def _list(self, name: str) -> VerticalScroll:
        return self._app.get_scan_list(name)

    def _clear(self, name: str) -> None:
        scroll = self._list(name)
        scroll.remove_children(scroll.children)

    def _mount(self, name: str, items: list) -> None:
        if items:
            self._list(name).mount(*items)

    def _set_references(self, name: str, recs: list) -> None:
        """Render deduplicated References block at the top of a tab"""
        scroll = self._list(name)
        for refs in list(scroll.query(ReferencesBar)):
            refs.remove()
        links = dedupe_links(recs)
        if links:
            scroll.mount(ReferencesBar(links))