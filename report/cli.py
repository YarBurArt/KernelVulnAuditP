"""CLI renderer for kernel vulnerability reports, shown also in gui"""

import textwrap
from typing import Any, ClassVar

import term
from core import dedupe_links, is_ok_status, status_severity
from report.diff import (
    DIFF_SECTIONS,
    build_diff_columns,
    count_findings,
)


class CLIReportRenderer:
    """Render report using plain text CLI output."""

    #: severity text -> ANSI color (used when color is enabled)
    _SEV_COLORS: ClassVar[dict[str, str]] = {
        "CRIT": term.CRIT,
        "CRITICAL": term.CRIT,
        "HIGH": term.CRIT,
        "FAIL": term.CRIT,
        "MAYBE": term.WARN,
        "WARN": term.WARN,
        "WARNING": term.WARN,
        "MEDIUM": term.WARN,
        "OK": term.OK,
        "SUCCESS": term.OK,
        "LOW": term.OK,
        "INFO": term.INFO,
        "UNKNOWN": term.GRAY,
    }

    def __init__(
        self, data: dict[str, Any], verbose: bool = False, color: bool = False
    ):
        self.data = data
        self.verbose = verbose
        self.color = color

    def _c(self, text: str, color: str = "", *, bold: bool = False) -> str:
        """Colorize text only when color output is requested."""
        if not self.color:
            return text
        return term.paint(text, color, bold=bold)

    def _sev(self, severity: str) -> str:
        """Colorize a [severity] label."""
        color = self._SEV_COLORS.get(str(severity).upper())
        return self._c(f"[{severity}]", color or "")

    def render(self) -> None:
        """Render full report, paging through less when on a TTY."""
        term.pager(self.build_full_report())

    def build_full_report(self) -> str:
        """Build complete report string."""
        kev_data = self.data.get("kev_data", [])
        runs = self.data.get("runs", [])
        stats = self.data.get("statistics", {})
        vulns = self.data.get("vulnerabilities", [])
        diff = self.data.get("diff") or []

        header = self._build_header()
        kev_section = self._build_kev_section(kev_data)
        runs_section = self._build_runs_section(runs)
        stats_section = self._build_stats_section(stats)
        vuln_section = self._build_vuln_section(vulns)
        hardening_section = self._build_hardening_diff_section(diff)

        return (
            f"{header}\n"
            f"--- KEV Stats ({len(kev_data)}) ---\n"
            f"{kev_section}\n"
            f"--- Execution Logs ({len(runs)} runs) ---{runs_section}\n"
            f"{stats_section}"
            f"{vuln_section}"
            f"{hardening_section}\n"
            + "=" * 60
            + "\n"
            + "                    END OF REPORT\n"
            + "=" * 60
            + "\n"
        )

    def _build_header(self) -> str:
        """Build report header."""
        title = "KERNEL VULNERABILITY AUDIT REPORT"
        if self.color:
            title = term.paint(title, bold=True)
        return (
            "\n"
            + "=" * 60
            + "\n"
            + f"           {title}\n"
            + "=" * 60
            + "\n\n"
            + f"Scan Started:    {self.data.get('started', 'N/A')}\n"
            + f"Scan Completed:  {self.data.get('completed', 'N/A')}\n"
            + f"Kernel Version:  {self.data.get('kernel_version', 'N/A')}\n"
            + f"Distribution:    {self.data.get('distribution', 'N/A')}\n"
            + f"Latest Version:  {self.data.get('latest_version', 'N/A')}\n\n"
        )

    def _build_kev_section(self, kev_data: list[dict[str, Any]]) -> str:
        """Build KEV section string, only what is vulnerable for host"""
        if not kev_data:
            return "  No CVE data available\n"

        if self.verbose:
            section = ""
            for idx, kev in enumerate(kev_data[:10], 1):
                cve_id = kev.get("cve_id", "N/A")
                desc = kev.get("description", "N/A")[:60]
                section += f"  {idx}. {cve_id}: {desc}...\n"
            if len(kev_data) > 10:
                section += f"  ... and {len(kev_data) - 10} more\n"
            return section
        return f"  {len(kev_data)} CVEs in CISA KEV list\n"

    def _build_runs_section(self, runs: list[dict[str, Any]]) -> str:
        """Build execution logs section string."""
        section = ""
        for run in runs:
            status = run.get("status", "UNKNOWN")
            run_id = run.get("id", "?")
            desc = run.get("description", "No description")
            section += f"\n  Run {run_id} - {self._sev(status)}\n"
            section += f"    Description: {desc}\n"
            if self.verbose:
                stdout = run.get("stdout", "")
                stderr = run.get("stderr", "")
                if stdout:
                    section += (
                        f"    STDOUT: {stdout[:200]}"
                        f"{'...' if len(stdout) > 200 else ''}\n"
                    )
                if stderr:
                    section += (
                        f"    STDERR: {stderr[:200]}"
                        f"{'...' if len(stderr) > 200 else ''}\n"
                    )
        return section

    @staticmethod
    def _build_stats_section(stats: dict[str, Any]) -> str:
        """Build database statistics section string."""
        if not stats:
            return ""

        section = (
            f"\n--- Database Statistics ---\n"
            f"  Total Vulnerabilities: {stats.get('total', 0)}\n"
            f"  With Exploits:         {stats.get('with_exploits', 0)}\n"
            f"  In CISA KEV:           {stats.get('in_cisa_kev', 0)}\n"
            f"  Ransomware Related:    {stats.get('ransomware_related', 0)}\n"
            f"  Critical Count:        {stats.get('critical_count', 0)}\n"
            f"  Average CVSS:          {stats.get('avg_cvss', 0):.2f}\n"
        )

        by_sev = stats.get("by_severity", {})
        if by_sev:
            section += "  By Severity:\n"
            for sev, count in sorted(by_sev.items()):
                section += f"    {sev}: {count}\n"
        return section

    @staticmethod
    def _build_exploits_section(exploits: list[dict[str, Any]]) -> str:
        """Build exploits section string."""
        if not exploits:
            return ""

        section = f"\n  Exploits / POCs ({len(exploits)}):\n"
        for idx, expl in enumerate(exploits, 1):
            section += (
                f"    {idx}. [{expl.get('exploit_type', 'POC')}] "
                f"`{expl.get('source', 'Unknown')}`\n"
                f"       {expl.get('url', 'N/A')}\n"
            )
            if expl.get("verified"):
                section += "       Verified\n"
        return section

    @staticmethod
    def _build_references_section(references: list[dict[str, Any]]) -> str:
        """Build references section string."""
        if not references:
            return ""

        section = f"\n  References ({len(references)}):\n"
        for ref in references:
            ref_type = ref.get("ref_type", "OTHER")
            section += (
                f"    [{ref_type}] `{ref.get('source', 'Unknown')}`\n"
                f"       {ref.get('url', 'N/A')}\n"
            )
        return section

    def _build_sandbox_section(self, sandbox_runs: list[dict[str, Any]]) -> str:
        """Build sandbox runs section string."""
        if not sandbox_runs:
            return ""

        section = f"\n  Sandbox Runs ({len(sandbox_runs)}):\n"
        for run in sandbox_runs:
            success = run.get("execution_success", False)
            exit_code = run.get("exit_code", -1)

            if success:
                status = f"SUCCESS (exit: {exit_code})"
            elif exit_code == 0:
                status = "COMPLETED WITH WARNINGS"
            else:
                status = f"MAYBE (exit: {exit_code})"

            status_color = term.OK if "SUCCESS" in status else term.WARN
            section += (
                f"    {self._c(status, status_color)} | "
                f"{run.get('sandbox_platform') or 'Unknown'}\n"
            )

            if run.get("notes"):
                section += f"    Notes: {run.get('notes')}\n"

            hash_val = run.get("exploit_file_hash")
            if hash_val:
                section += f"    Hash: {hash_val[:16]}...\n"

            if self.verbose:
                stdout = run.get("stdout") or ""
                stderr = run.get("stderr") or ""
                if stdout:
                    section += (
                        f"    STDOUT: {stdout[:200]}"
                        f"{'...' if len(stdout) > 200 else ''}\n"
                    )
                if stderr:
                    section += (
                        f"    STDERR: {stderr[:200]}"
                        f"{'...' if len(stderr) > 200 else ''}\n"
                    )

        return section

    def _build_vuln_section(self, vulns: list[dict[str, Any]]) -> str:
        """Build vulnerabilities section string."""
        if not vulns:
            return ""

        section = f"\n--- Vulnerabilities ({len(vulns)}) ---\n"
        for vuln in vulns:
            sev = vuln.get("severity", "N/A")
            section += (
                f"\n{'=' * 50}\n"
                f"  {vuln.get('cve_id', 'N/A')} {self._sev(sev)}\n"
                f"  CVSS: {vuln.get('cvss_v3_score', 'N/A')} | "
                f"Criticality: {vuln.get('criticality_score', 0)}/100\n"
                f"  {vuln.get('description', 'No description')[:150]}\n"
            )

            section += self._build_exploits_section(vuln.get("exploits", []))
            section += self._build_references_section(vuln.get("references", []))
            section += self._build_sandbox_section(vuln.get("sandbox_runs", []))

        return section

    _DIFF_SECTIONS = DIFF_SECTIONS

    #: severity class -> ANSI color (from core.status_severity classification)
    _SEV_CLASS_COLORS: ClassVar[dict[str, str]] = {
        "CRIT": term.CRIT,
        "WARN": term.WARN,
        "OK": term.OK,
        "INFO": term.GRAY,
    }

    @staticmethod
    def _row_status_color(status: str) -> str:
        """CLI color for a two-column row based on its status.

        red = FAIL/mismatch/new, yellow = WARNING/missing/removed,
        green = ok/perfect for the current state of host
        """
        return CLIReportRenderer._SEV_CLASS_COLORS[status_severity(status)]

    def _render_two_column(self, table: dict) -> str:
        """Render a two-column comparison table with aligned columns"""
        headers, rows = table["headers"], table["rows"]
        left_h, right_h = headers
        out = ""

        left_w = max(
            [len(str(r["left"])) for r in rows] + [len(left_h)]
        )
        right_w = max(
            [len(str(r["right"])) for r in rows] + [len(right_h)]
        )
        key_w = max(
            [len(str(r["key"])) for r in rows] + [len("Parameter")]
        )

        header = (
            f"  {'Parameter':<{key_w}}  {left_h:<{left_w}}  {right_h}"
        )
        out += header + "\n" + "  " + "-" * (key_w + left_w + right_w + 4) + "\n"

        for r in rows:
            key = str(r["key"])
            left = str(r["left"])
            right = str(r["right"])
            color = self._row_status_color(r.get("status", ""))
            if self.color and r.get("changed"):
                right = self._c(right, color)
            out += f"  {key:<{key_w}}  {left:<{left_w}}  {right}\n"
            detail = str(r.get("detail", "") or "")
            status = str(r.get("status", "") or "")
            if detail and (self.verbose or not is_ok_status(status)):
                out += f"  {'':<{key_w}}  {'':<{left_w}}  ↳ {detail}\n"
        return out

    def _build_hardening_diff_section(self, diff: list[dict[str, Any]]) -> str:
        """Build the unified hardening & divergence comparison section"""
        if not diff:
            return ""
        sections = build_diff_columns(diff)
        total = sum(
            count_findings(section["rows"]) for section in sections.values()
        )
        out = f"\n--- Hardening & Diff ({total} findings) ---\n"
        out += "  Recommended vs Current where noted; modules show host/sandbox\n"
        out += "  divergence grouped by direction. Finding text is colored by\n"
        out += "  severity (red=fail, yellow=warning, green=ok).\n"

        for kind in self._DIFF_SECTIONS:
            section = sections.get(kind)
            if not section:
                continue
            count = count_findings(section["rows"])
            out += f"\n  {section['label']} ({count} findings):\n"
            layout = section.get("layout")
            if layout == "module":
                out += self._render_module_groups(section)
            elif layout == "capability":
                out += self._render_capability_groups(section)
            else:
                out += self._render_two_column(section)
            refs = section.get("references")
            if refs:
                out += self._render_references_table(refs)
            else:
                links = dedupe_links(section["rows"])
                if links:
                    out += f"  References:\n    {', '.join(links)}\n"
        return out

    @staticmethod
    def _render_module_groups(section: dict) -> str:
        """Compact grouped module listing."""
        out = ""
        for group in section.get("groups", []):
            out += (
                f"    ↳ {group['title']} ({len(group['items'])}):\n"
                f"      {', '.join(group['items'])}\n"
            )
        return out

    def _render_capability_groups(self, section: dict) -> str:
        """Capability table (like SELinux): cap set + holder count.
        Holder lines are laid out in two columns to save vertical space."""
        rows = section.get("rows", [])
        if not rows:
            return ""
        out = ""

        left_w = max(
            [len(str(r["left"])) for r in rows] + [len("Holders")]
        )
        key_w = min(
            max(len(str(r["key"])) for r in rows),
            60,
        )

        out += (
            f"  {'Capability set':<{key_w}}  {'Holders':<{left_w}}\n"
            + "  "
            + "-" * (key_w + left_w + 2)
            + "\n"
        )
        for row in rows:
            status = str(row.get("status", "") or "")
            color = self._row_status_color(status)
            cap_label = self._c(str(row.get("key") or "?"), color)
            holder_count = str(row.get("left") or row.get("count") or 1)
            out += f"  {cap_label:<{key_w}}  {holder_count:<{left_w}}\n"
            detail = str(row.get("detail", "") or "")
            if detail:
                holder_lines = detail.splitlines()
                for line in self._columns(holder_lines, width=100):
                    out += line + "\n"
        out += "\n"
        return out

    @staticmethod
    def _columns(lines: list[str], width: int = 100) -> list[str]:
        """Lay a flat list out as two balanced columns of text lines.

        Rewraps long lines so every column cell fits the available width;
        returns rows where the left and right halves are joined on one line.
        """
        if not lines:
            return []
        col = max(1, (width - 3) // 2)
        left = []
        right = []
        half = (len(lines) + 1) // 2
        for row in lines[:half]:
            left.extend(textwrap.wrap(row, width=col) or [""])
        for row in lines[half:]:
            right.extend(textwrap.wrap(row, width=col) or [""])
        n = max(len(left), len(right))
        left += [""] * (n - len(left))
        right += [""] * (n - len(right))
        result = []
        for l, r in zip(left, right):
            if r:
                result.append(f"      ↳ {l:<{col}}   {r}")
            elif l:
                result.append(f"      ↳ {l}")
            else:
                result.append("")
        return result

    def _render_references_table(self, references: list[dict[str, str]]) -> str:
        """Capability references as what | how works | why dangerous.

        When color is on, the how and why cells are short text wrapped
        in OSC-8 terminal hyperlinks (clickable in capable terminals),
        short label renders even where hyperlinks are unsupported.
        """
        if not references:
            return ""

        def link(label: str, url: str) -> str:
            if self.color:
                return f"\x1b]8;;{url}\x1b\\{label}\x1b]8;;\x1b\\"
            return url

        how_label = "MAN / capabilities.7"
        why_label = "Hacktricks"
        what_w = max(len(r["what"]) for r in references) + 2
        how_w = len(how_label) + 2
        out = "  References:\n"
        out += (
            f"    {'Capability':<{what_w}}  {'How it works':<{how_w}}"
            "  Why dangerous\n"
        )
        out += "    " + "-" * (what_w + how_w + 6) + "\n"
        for ref in references:
            why = (
                link(why_label, ref["why"]) if ref.get("why") else "-"
            )
            out += (
                f"    {ref['what']:<{what_w}}  {link(how_label, ref['how']):<{how_w}}"
                f"  {why}\n"
            )
        return out
