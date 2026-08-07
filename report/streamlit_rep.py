"""Streamlit renderer for kernel vulnerability reports."""

from typing import Any

from core import dict_to_display_rows
from report.diff import (
    DIFF_SECTIONS,
    build_diff_columns,
    count_findings,
)


def _dedup_links(rows: list[dict[str, Any]]) -> list[str]:
    """Deduplicated, non-empty link list across table rows (stable order).

    Supports both a single link and a links list on each row.
    """
    seen: list[str] = []
    for row in rows or []:
        for link in [
            row.get("link"),
            *list(row.get("links", []) or []),
        ]:
            link = str(link or "").strip()
            if link and link not in seen:
                seen.append(link)
    return seen

try:
    import streamlit as st  # type: ignore[import-not-found]
except ImportError:
    st = None  # type: ignore


class StreamlitReportRenderer:
    """Render report using Streamlit web UI."""

    def __init__(self, data: dict[str, Any]):
        self.data = data

    def render(self) -> None:
        """init render full report."""
        if st is None:
            return
        st.set_page_config(page_title="Kernel Vulnerability Report", layout="wide")
        st.title("System Scan Report")

        self._render_header()
        self._render_kev_stats()
        self._render_execution_logs()
        self._render_db_stats()
        self._render_vulnerabilities()
        self._render_hardening_diff()

    def _render_header(self) -> None:
        """Render header metrics split into two rows."""
        assert st is not None

        r1a, r1b, r1c = st.columns(3)
        r1a.metric("Kernel", self.data.get("kernel_version", "N/A"))
        r1b.metric("Distribution", self.data.get("distribution", "N/A"))
        r1c.metric("Latest Version", self.data.get("latest_version", "N/A"))

        r2a, r2b, r2c = st.columns(3)
        r2a.metric("Started", self.data.get("started", "N/A"))
        r2b.metric("Completed", self.data.get("completed", "N/A"))
        r2c.empty()

    def _render_kev_stats(self) -> None:
        """Render KEV stats section."""
        kev_data = self.data.get("kev_data", [])
        assert st is not None
        with st.expander(f"KEV Stats ({len(kev_data)})"):
            if kev_data:
                st.markdown(
                    """
                    <style>
                        .stTable { overflow-x: auto; }
                        table td { white-space: normal !important; }
                        td { max-width: 400pt; min-width: 100pt; }
                    </style>
                """,
                    unsafe_allow_html=True,
                )
                st.table(dict_to_display_rows(kev_data))
            else:
                st.info("No CVE data available")

    def _render_execution_logs(self) -> None:
        """Render execution logs section."""
        assert st is not None
        st.subheader("Execution Logs")
        runs = self.data.get("runs", [])
        for idx, run in enumerate(runs):
            run_key = run.get("id", f"run_{idx}")
            with st.expander(f"Run {run_key} - [{run.get('status', 'UNKNOWN')}]"):
                st.write(run.get("description", "No description"))
                col_out, col_err = st.columns(2)
                col_out.text_area(
                    "STDOUT",
                    run.get("stdout", ""),
                    height=100,
                    key=f"out_{run_key}_{idx}",
                )
                col_err.write("STDERR")
                if run.get("stderr"):
                    col_err.error(run["stderr"])
                else:
                    col_err.write("No errors")

    def _render_db_stats(self) -> None:
        """Render database statistics."""
        stats = self.data.get("statistics", {})
        if not stats:
            return
        assert st is not None
        st.subheader("Database Statistics")
        s1, s2, s3, s4 = st.columns(4)
        s1.metric("Total Vulnerabilities", stats.get("total", 0))
        s2.metric("With Exploits", stats.get("with_exploits", 0))
        s3.metric("In CISA KEV", stats.get("in_cisa_kev", 0))
        s4.metric("Avg CVSS", f"{stats.get('avg_cvss', 0):.2f}")

    @staticmethod
    def _render_exploits(exploits: list[dict[str, Any]]) -> None:
        """Render exploits/POCs section."""
        if not exploits:
            return
        assert st is not None
        with st.expander(f"Exploits / POCs ({len(exploits)})"):
            for expl in exploits:
                c1, c2, c3 = st.columns([1, 1, 3])
                c1.text(expl.get("exploit_type", "POC"))
                c2.text(expl.get("source", "Unknown"))
                url = expl.get("url")
                if url:
                    c3.markdown(f"[{url}]({url})")
                else:
                    c3.text("N/A")
            st.divider()

    @staticmethod
    def _render_references(references: list[dict[str, Any]]) -> None:
        """Render references section."""
        if not references:
            return
        assert st is not None
        with st.expander(f"References ({len(references)})"):
            for ref in references:
                c1, c2, c3 = st.columns([1, 1, 3])
                c1.text(ref.get("ref_type", "OTHER"))
                c2.text(ref.get("source", "Unknown"))
                url = ref.get("url")
                if url:
                    c3.markdown(f"[{url}]({url})")
                else:
                    c3.text("N/A")

    def _render_sandbox_run(self, run: dict[str, Any]) -> None:
        """Render single sandbox run."""
        success = run.get("execution_success", False)
        exit_code = run.get("exit_code", -1)

        assert st is not None
        if success:
            st.success(f"Execution successful (exit code: {exit_code})")
        elif exit_code == 0:
            st.warning("Execution completed with warnings")
        else:
            st.warning(f"Execution uncertain (exit code: {exit_code})")

        c1, c2 = st.columns(2)
        c1.info(f"Platform: {run.get('sandbox_platform') or 'Unknown'}")
        hash_val = run.get("exploit_file_hash") or "N/A"
        hash_display = hash_val[:16] + "..." if hash_val != "N/A" else hash_val
        c2.info(f"Hash: {hash_display}")

        if run.get("notes"):
            st.caption(f"Notes: {run.get('notes')}")

        self._render_sandbox_io(run)
        self._render_sandbox_artifacts(run)
        st.divider()

    @staticmethod
    def _render_sandbox_io(run: dict[str, Any]) -> None:
        """Render sandbox I/O section."""
        assert st is not None
        with st.expander("View I/O"):
            stdout = run.get("stdout")
            if stdout:
                st.text_area("STDOUT", stdout, height=100)
            stderr = run.get("stderr")
            if stderr:
                st.error(f"STDERR:\n{stderr}")
            stdin = run.get("stdin")
            if stdin:
                st.code(stdin, language="bash")

    @staticmethod
    def _render_sandbox_artifacts(run: dict[str, Any]) -> None:
        """Render sandbox processes and files."""
        procs = run.get("open_processes") or []
        assert st is not None
        if procs:
            st.write("Processes:", ", ".join(procs))
        files = run.get("open_files") or []
        if files:
            st.write("Files:", ", ".join(files))
        kinfo = run.get("kernel_info") or {}
        if kinfo:
            with st.expander("Kernel Info"):
                for k, v in kinfo.items():
                    if isinstance(v, str) and len(v) > 200:
                        st.text(f"{k}:")
                        st.code(v[:1000], language="text")
                    else:
                        st.text(f"{k}: {v}")

    def _render_sandbox_runs(self, sandbox_runs: list[dict[str, Any]]) -> None:
        """Render sandbox runs section."""
        if not sandbox_runs:
            return
        assert st is not None
        with st.expander(f"Sandbox Runs ({len(sandbox_runs)})"):
            all_modules = set()
            for run in sandbox_runs:
                mods = run.get("modules") or []
                if isinstance(mods, list):
                    all_modules.update(mods)
            if all_modules:
                with st.expander(f"Kernel Modules ({len(all_modules)})"):
                    st.write(", ".join(sorted(all_modules)))
            for run in sandbox_runs:
                self._render_sandbox_run(run)

    def _render_vulnerability(self, vuln: dict[str, Any]) -> None:
        """Render single vulnerability."""
        assert st is not None
        with st.expander(
            f"{vuln.get('cve_id')} - {vuln.get('severity', 'N/A')} "
            f"(CVSS: {vuln.get('cvss_v3_score', 'N/A')})"
        ):
            st.write(vuln.get("description", "No description"))
            c1, c2, c3 = st.columns(3)
            c1.metric("Criticality", f"{vuln.get('criticality_score', 0)}/100")
            c2.metric("Exploits", vuln.get("exploit_count", 0))
            c3.metric("In KEV", "Yes" if vuln.get("in_cisa_kev") else "No")

            self._render_exploits(vuln.get("exploits", []))
            self._render_references(vuln.get("references", []))
            self._render_sandbox_runs(vuln.get("sandbox_runs", []))

    def _render_vulnerabilities(self) -> None:
        """Render all vulnerabilities."""
        vulns = self.data.get("vulnerabilities", [])
        if not vulns:
            return
        assert st is not None
        st.subheader(f"Vulnerabilities ({len(vulns)})")
        for vuln in vulns:
            self._render_vulnerability(vuln)

    _DIFF_SECTIONS = DIFF_SECTIONS

    @staticmethod
    def _status_color(status: str) -> str:
        """CSS text color for a status (never a background)."""
        up = status.upper()
        if up in ("FAIL", "NEW", "CRIT", "CRITICAL", "MISMATCH"):
            return "#b00020"
        if up in ("WARNING", "WARN", "MISSING", "REMOVED"):
            return "#b26a00"
        if up in ("OK", "SUCCESS"):
            return "#1b7a3d"
        return "inherit"

    @staticmethod
    def _two_column_table(table: dict) -> str:
        """Build an HTML table for a two-column comparison (cuz no pandas).

        Only the differing Current (right) cell's text is colored by the
        row status severity (red = FAIL/mismatch/new, yellow = WARNING/missing/removed, green = ok/perfect)
        Non-ok rows show their detail below the row.
        """
        headers, rows = table["headers"], table["rows"]
        left_h, right_h = headers

        out = [
            (
                "<table style='width:100%; border-collapse:collapse;"
                " font-family:monospace; font-size:0.85em;'>"
            ),
            (
                "<tr><th style='text-align:left; padding:4px 8px;'>Parameter</th>"
                f"<th style='text-align:left; padding:4px 8px;'>{left_h}</th>"
                f"<th style='text-align:left; padding:4px 8px;'>{right_h}</th></tr>"
            ),
        ]
        for row in rows:
            key = str(row.get("key", "?"))
            left = str(row.get("left") or "")
            right = str(row.get("right") or "")
            status = str(row.get("status", "")).upper()
            color = StreamlitReportRenderer._status_color(status)
            detail = str(row.get("detail", "") or "")
            is_finding = status not in ("OK", "SUCCESS", "")

            right_cell = (
                f"<td style='padding:2px 8px; color:{color};"
                f" font-weight:bold;'>{right}</td>"
                if is_finding
                else f"<td style='padding:2px 8px;'>{right}</td>"
            )
            detail_row = (
                f"<tr><td colspan='3' style='padding:2px 8px; "
                f"color:#555; font-size:0.85em;'>↳ {detail}</td></tr>"
                if detail and is_finding
                else ""
            )
            out.append(
                f"<tr><td style='padding:2px 8px;'>{key}</td>"
                f"<td style='padding:2px 8px;'>{left}</td>"
                f"{right_cell}</tr>"
                f"{detail_row}"
            )
        out.append("</table>")
        return "".join(out)

    def _render_hardening_diff(self) -> None:
        """Render the unified hardening & divergence comparison.

        Sections come from the recomputed comparison model: kernel parameters,
        capabilities, SELinux booleans (recommended vs current) and the
        host/sandbox kernel-module divergence. Counts reflect real findings
        only (correctly satisfied checks are not counted).
        """
        diff = self.data.get("diff") or []
        if not diff:
            return
        assert st is not None
        st.subheader(f"Hardening & Diff ({count_findings(diff)} findings)")

        sections = build_diff_columns(diff)
        st.caption(
            "Recommended vs Current where noted; modules show host/sandbox "
            "divergence grouped by direction. Finding text is colored by "
            "severity (red=fail, yellow=warning, green=ok)."
        )

        for diff_type in self._DIFF_SECTIONS:
            section = sections.get(diff_type)
            if not section:
                continue
            count = count_findings(section["rows"])
            with st.expander(f"{section['label']} ({count} findings)"):
                layout = section.get("layout")
                if layout == "module":
                    st.markdown(self._module_groups(section))
                elif layout == "capability":
                    st.markdown(
                        self._capability_table(section), unsafe_allow_html=True
                    )
                else:
                    st.markdown(
                        self._two_column_table(section), unsafe_allow_html=True
                    )
                refs = section.get("references")
                if refs:
                    st.markdown(
                        self._references_table(refs), unsafe_allow_html=True
                    )
                else:
                    links = _dedup_links(section["rows"])
                    if links:
                        for link in links:
                            st.markdown(f"- {link}")

    @staticmethod
    def _module_groups(section: dict) -> str:
        """Compact grouped module listing."""
        lines = []
        for group in section.get("groups", []):
            lines.append(f"**{group['title']} ({len(group['items'])}):**")
            lines.append("`" + ", ".join(group["items"]) + "`")
        return "\n\n".join(lines)

    @staticmethod
    def _capability_table(section: dict) -> str:
        """Capability table: cap set + holder count, then
        per-process holders below each row in two columns."""
        rows = section.get("rows", [])
        if not rows:
            return ""
        out = [
            (
                "<table style='width:100%; border-collapse:collapse;"
                " font-family:monospace; font-size:0.85em;'>"
            ),
            (
                "<tr><th style='text-align:left; padding:4px 8px;'>"
                "Capability set</th>"
                "<th style='text-align:left; padding:4px 8px;'>Holders</th></tr>"
            ),
        ]
        for row in rows:
            status = str(row.get("status", "")).upper()
            color = StreamlitReportRenderer._status_color(status)
            key = str(row.get("key", "?"))
            holder_count = str(row.get("left") or row.get("count") or 1)
            out.append(
                f"<tr><td style='padding:2px 8px; color:{color};"
                f" font-weight:bold;'>{key}</td>"
                f"<td style='padding:2px 8px;'>{holder_count}</td></tr>"
            )
            detail = str(row.get("detail", "") or "")
            if detail:
                holders = StreamlitReportRenderer._columns_html(detail.splitlines())
                out.append(
                    "<tr><td colspan='2' style='padding:2px 8px; "
                    "color:#555; font-size:0.85em;'>" + holders + "</td></tr>"
                )
        out.append("</table>")
        return "".join(out)

    @staticmethod
    def _columns_html(lines: list[str]) -> str:
        """Two-column holder grid, so long names wrap
        inside their cell instead of smearing the alignment."""
        if not lines:
            return ""
        half = (len(lines) + 1) // 2
        left, right = lines[:half], lines[half:]
        n = max(len(left), len(right))
        cells = []
        for i in range(n):
            a = f"↳ {left[i]}" if i < len(left) else ""
            b = f"↳ {right[i]}" if i < len(right) else ""
            cells.append(
                "<tr>"
                f"<td style='padding:1px 8px; vertical-align:top;'>{a}</td>"
                f"<td style='padding:1px 8px; vertical-align:top;'>{b}</td>"
                "</tr>"
            )
        return (
            "<table style='width:100%; border-collapse:collapse;'>"
            + "".join(cells)
            + "</table>"
        )

    @staticmethod
    def _references_table(references: list[dict[str, str]]) -> str:
        """Capability references as a what | how works | why dangerous table."""
        if not references:
            return ""
        rows = [
            (
                "<table style='width:100%; border-collapse:collapse;"
                " font-family:monospace; font-size:0.85em;'>"
            ),
            (
                "<tr><th style='text-align:left; padding:4px 8px;'>Capability</th>"
                "<th style='text-align:left; padding:4px 8px;'>How it works</th>"
                "<th style='text-align:left; padding:4px 8px;'>Why dangerous</th></tr>"
            ),
        ]
        for ref in references:
            how = f"<a href='{ref['how']}' target='_blank'>MAN / capabilities.7</a>"
            why_label = "Hacktricks" if ref.get("escalates") else "Hacktricks (info)"
            if ref.get("why"):
                why = f"<a href='{ref['why']}' target='_blank'>{why_label}</a>"
            else:
                why = "<span style='color:#888;'>no documented section</span>"
            rows.append(
                f"<tr><td style='padding:2px 8px;'>{ref['what']}</td>"
                f"<td style='padding:2px 8px;'>{how}</td>"
                f"<td style='padding:2px 8px;'>{why}</td></tr>"
            )
        rows.append("</table>")
        return "".join(rows)
