"""CLI renderer for kernel vulnerability reports."""

from typing import Any, Dict, List


class CLIReportRenderer:
    """Render report using plain text CLI output."""

    def __init__(self, data: Dict[str, Any], verbose: bool = False):
        self.data = data
        self.verbose = verbose

    def render(self) -> None:
        """Render full report."""
        print(self._build_full_report())

    def _build_full_report(self) -> str:
        """Build complete report string."""
        kev_data = self.data.get("kev_data", [])
        runs = self.data.get("runs", [])
        stats = self.data.get("statistics", {})
        vulns = self.data.get("vulnerabilities", [])
        recs = self.data.get("security_recommendations", [])

        header = self._build_header()
        kev_section = self._build_kev_section(kev_data)
        runs_section = self._build_runs_section(runs)
        stats_section = self._build_stats_section(stats)
        vuln_section = self._build_vuln_section(vulns)
        rec_section = self._build_recommendations_section(recs, stats)

        return (
            f"{header}\n"
            f"--- KEV Stats ({len(kev_data)}) ---\n"
            f"{kev_section}\n"
            f"--- Execution Logs ({len(runs)} runs) ---{runs_section}\n"
            f"{stats_section}"
            f"{vuln_section}"
            f"{rec_section}\n"
            "=" * 60 + "\n"
            "                    END OF REPORT\n"
            "=" * 60 + "\n"
        )

    def _build_header(self) -> str:
        """Build report header."""
        return (
            "\n" + "=" * 60 + "\n"
            "           KERNEL VULNERABILITY AUDIT REPORT\n"
            "=" * 60 + "\n\n"
            f"Scan Started:    {self.data.get('started', 'N/A')}\n"
            f"Scan Completed:  {self.data.get('completed', 'N/A')}\n"
            f"Kernel Version:  {self.data.get('kernel_version', 'N/A')}\n"
            f"Distribution:    {self.data.get('distribution', 'N/A')}\n"
            f"Latest Version:  {self.data.get('latest_version', 'N/A')}\n\n"
        )

    def _build_kev_section(self, kev_data: List[Dict[str, Any]]) -> str:
        """Build KEV section string."""
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
        else:
            return f"  {len(kev_data)} CVEs in CISA KEV list\n"

    def _build_runs_section(self, runs: List[Dict[str, Any]]) -> str:
        """Build execution logs section string."""
        section = ""
        for run in runs:
            status = run.get("status", "UNKNOWN")
            run_id = run.get("id", "?")
            desc = run.get("description", "No description")
            section += f"\n  Run {run_id} - [{status}]\n"
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

    def _build_stats_section(self, stats: Dict[str, Any]) -> str:
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

    def _build_exploits_section(self, exploits: List[Dict[str, Any]]) -> str:
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
            if expl.get('verified'):
                section += "       Verified\n"
        return section

    def _build_references_section(
        self, references: List[Dict[str, Any]]
    ) -> str:
        """Build references section string."""
        if not references:
            return ""

        section = f"\n  References ({len(references)}):\n"
        for ref in references:
            ref_type = ref.get('ref_type', 'OTHER')
            section += (
                f"    [{ref_type}] `{ref.get('source', 'Unknown')}`\n"
                f"       {ref.get('url', 'N/A')}\n"
            )
        return section

    def _build_sandbox_section(
        self, sandbox_runs: List[Dict[str, Any]]
    ) -> str:
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

            section += (
                f"    {status} | "
                f"{run.get('sandbox_platform') or 'Unknown'}\n"
            )

            if run.get('notes'):
                section += f"    Notes: {run.get('notes')}\n"

            hash_val = run.get('exploit_file_hash')
            if hash_val:
                section += f"    Hash: {hash_val[:16]}...\n"

            if self.verbose and run.get('stdout'):
                section += f"    STDOUT: {run.get('stdout')[:200]}...\n"
            if self.verbose and run.get('stderr'):
                section += f"    STDERR: {run.get('stderr')[:200]}...\n"

        return section

    def _build_vuln_section(self, vulns: List[Dict[str, Any]]) -> str:
        """Build vulnerabilities section string."""
        if not vulns:
            return ""

        section = f"\n--- Vulnerabilities ({len(vulns)}) ---\n"
        for vuln in vulns:
            section += (
                f"\n{'=' * 50}\n"
                f"  {vuln.get('cve_id', 'N/A')} "
                f"[{vuln.get('severity', 'N/A')}]\n"
                f"  CVSS: {vuln.get('cvss_v3_score', 'N/A')} | "
                f"Criticality: {vuln.get('criticality_score', 0)}/100\n"
                f"  {vuln.get('description', 'No description')[:150]}\n"
            )

            section += self._build_exploits_section(
                vuln.get("exploits", []))
            section += self._build_references_section(
                vuln.get("references", []))
            section += self._build_sandbox_section(
                vuln.get("sandbox_runs", []))

        return section

    def _build_recommendations_section(
        self, recs: List[Dict[str, Any]], stats: Dict[str, Any]
    ) -> str:
        """Build security recommendations section string."""
        if not recs:
            return ""

        rec_stats = stats.get("security_recommendations", {})
        section = f"\n--- Security Recommendations ({len(recs)}) ---\n"

        if rec_stats:
            section += f"  Total: {rec_stats.get('total', 0)}\n"
            by_status = rec_stats.get("by_status", {})
            if by_status:
                section += "  By Status:\n"
                for status, count in sorted(by_status.items()):
                    section += f"    {status}: {count}\n"
            by_severity = rec_stats.get("by_severity", {})
            if by_severity:
                section += "  By Severity:\n"
                for sev, count in sorted(by_severity.items()):
                    section += f"    {sev}: {count}\n"

        for rec in recs:
            status = rec.get("status", "UNKNOWN")
            severity = rec.get("severity", "INFO")
            test_id = rec.get("test_id", "N/A")
            category = rec.get("category", "N/A")
            desc = rec.get("description", "N/A")[:100]
            expected = rec.get("expected_value", "N/A")
            actual = rec.get("actual_value", "N/A")

            section += (
                f"\n  [{status}] `{test_id}` - {severity}\n"
                f"    Category: {category}\n"
                f"    Description: {desc}\n"
                f"    Expected: {expected}\n"
                f"    Actual: {actual}\n"
            )

        return section
