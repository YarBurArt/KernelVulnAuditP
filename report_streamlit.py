"""Streamlit renderer for kernel vulnerability reports."""

from typing import Any, Dict, List

try:
    import streamlit as st
except (ImportError, ModuleNotFoundError):
    st = None  # type: ignore


class StreamlitReportRenderer:
    """Render report using Streamlit web UI."""

    def __init__(self, data: Dict[str, Any]):
        self.data = data

    def render(self) -> None:
        """Render full report."""
        if st is None:
            return
        st.set_page_config(
            page_title="Kernel Vulnerability Report", layout="wide"
        )
        st.title("System Scan Report")

        self._render_header()
        self._render_kev_stats()
        self._render_execution_logs()
        self._render_db_stats()
        self._render_vulnerabilities()
        self._render_security_recommendations()

    def _render_header(self) -> None:
        """Render header metrics."""
        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Started", self.data.get("started", "N/A"))
        c2.metric("Completed", self.data.get("completed", "N/A"))
        c3.metric("Kernel", self.data.get("kernel_version", "N/A"))
        c4.metric("Distribution", self.data.get("distribution", "N/A"))
        c5.metric("Latest Version", self.data.get("latest_version", "N/A"))

    def _render_kev_stats(self) -> None:
        """Render KEV stats section."""
        kev_data = self.data.get("kev_data", [])
        with st.expander(f"KEV Stats ({len(kev_data)})"):
            if kev_data:
                st.markdown("""
                    <style>
                        .stTable { overflow-x: auto; }
                        table td { white-space: normal !important; }
                        td { max-width: 400pt; min-width: 100pt; }
                    </style>
                """, unsafe_allow_html=True)
                transposed = [
                    [k] + [d[k] for d in kev_data]
                    for k in kev_data[0].keys()
                ]
                st.table(transposed)
            else:
                st.info("No CVE data available")

    def _render_execution_logs(self) -> None:
        """Render execution logs section."""
        st.subheader("Execution Logs")
        runs = self.data.get("runs", [])
        for idx, run in enumerate(runs):
            run_key = run.get('id', f'run_{idx}')
            with st.expander(
                f"Run {run_key} - [{run.get('status', 'UNKNOWN')}]"
            ):
                st.write(run.get("description", "No description"))
                col_out, col_err = st.columns(2)
                col_out.text_area(
                    "STDOUT", run.get("stdout", ""),
                    height=100, key=f"out_{run_key}_{idx}"
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
        st.subheader("Database Statistics")
        s1, s2, s3, s4 = st.columns(4)
        s1.metric("Total Vulnerabilities", stats.get("total", 0))
        s2.metric("With Exploits", stats.get("with_exploits", 0))
        s3.metric("In CISA KEV", stats.get("in_cisa_kev", 0))
        s4.metric("Avg CVSS", f"{stats.get('avg_cvss', 0):.2f}")

    def _render_exploits(self, exploits: List[Dict[str, Any]]) -> None:
        """Render exploits/POCs section."""
        if not exploits:
            return
        with st.expander(f"Exploits / POCs ({len(exploits)})"):
            for expl in exploits:
                c1, c2, c3 = st.columns([1, 1, 3])
                c1.text(expl.get('exploit_type', 'POC'))
                c2.text(expl.get('source', 'Unknown'))
                url = expl.get('url')
                if url:
                    c3.markdown(f"[{url}]({url})")
                else:
                    c3.text("N/A")
            st.divider()

    def _render_references(self, references: List[Dict[str, Any]]) -> None:
        """Render references section."""
        if not references:
            return
        with st.expander(f"References ({len(references)})"):
            for ref in references:
                c1, c2, c3 = st.columns([1, 1, 3])
                c1.text(ref.get('ref_type', 'OTHER'))
                c2.text(ref.get('source', 'Unknown'))
                url = ref.get('url')
                if url:
                    c3.markdown(f"[{url}]({url})")
                else:
                    c3.text("N/A")

    def _render_sandbox_run(self, run: Dict[str, Any]) -> None:
        """Render single sandbox run."""
        success = run.get("execution_success", False)
        exit_code = run.get("exit_code", -1)

        if success:
            st.success(f"Execution successful (exit code: {exit_code})")
        elif exit_code == 0:
            st.warning("Execution completed with warnings")
        else:
            st.warning(f"Execution uncertain (exit code: {exit_code})")

        c1, c2 = st.columns(2)
        c1.info(f"Platform: {run.get('sandbox_platform') or 'Unknown'}")
        hash_val = run.get('exploit_file_hash') or 'N/A'
        hash_display = hash_val[:16] + "..." if hash_val != 'N/A' else hash_val
        c2.info(f"Hash: {hash_display}")

        if run.get('notes'):
            st.caption(f"Notes: {run.get('notes')}")

        self._render_sandbox_io(run)
        self._render_sandbox_artifacts(run)
        st.divider()

    def _render_sandbox_io(self, run: Dict[str, Any]) -> None:
        """Render sandbox I/O section."""
        with st.expander("View I/O"):
            stdout = run.get('stdout')
            if stdout:
                st.text_area("STDOUT", stdout, height=100)
            stderr = run.get('stderr')
            if stderr:
                st.error(f"STDERR:\n{stderr}")
            stdin = run.get('stdin')
            if stdin:
                st.code(stdin, language="bash")

    def _render_sandbox_artifacts(self, run: Dict[str, Any]) -> None:
        """Render sandbox processes and files."""
        procs = run.get('open_processes') or []
        if procs:
            st.write("Processes:", ", ".join(procs))
        files = run.get('open_files') or []
        if files:
            st.write("Files:", ", ".join(files))

    def _render_sandbox_runs(
        self, sandbox_runs: List[Dict[str, Any]]
    ) -> None:
        """Render sandbox runs section."""
        if not sandbox_runs:
            return
        with st.expander(f"Sandbox Runs ({len(sandbox_runs)})"):
            for run in sandbox_runs:
                self._render_sandbox_run(run)

    def _render_vulnerability(self, vuln: Dict[str, Any]) -> None:
        """Render single vulnerability."""
        with st.expander(
            f"{vuln.get('cve_id')} - {vuln.get('severity', 'N/A')} "
            f"(CVSS: {vuln.get('cvss_v3_score', 'N/A')})"
        ):
            st.write(vuln.get("description", "No description"))
            c1, c2, c3 = st.columns(3)
            c1.metric(
                "Criticality", f"{vuln.get('criticality_score', 0)}/100"
            )
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
        st.subheader(f"Vulnerabilities ({len(vulns)})")
        for vuln in vulns:
            self._render_vulnerability(vuln)

    def _render_security_recommendations(self) -> None:
        """Render security recommendations section."""
        recs = self.data.get("security_recommendations", [])
        if not recs:
            return

        st.subheader(f"Security Recommendations ({len(recs)})")

        stats = self.data.get("statistics", {}).get(
            "security_recommendations", {})
        if stats:
            c1, c2, c3 = st.columns(3)
            c1.metric("Total", stats.get("total", 0))
            by_status = stats.get("by_status", {})
            c2.metric("Warnings", by_status.get("WARNING", 0))
            c3.metric("Failures", by_status.get("FAIL", 0))

        with st.expander(f"Recommendations ({len(recs)})"):
            for rec in recs:
                status = rec.get("status", "UNKNOWN")
                severity = rec.get("severity", "INFO")

                if status == "FAIL":
                    st.error(
                        f"**[{status}]** `{rec.get('test_id')}` - {severity}"
                    )
                elif status == "WARNING":
                    st.warning(
                        f"**[{status}]** `{rec.get('test_id')}` - {severity}"
                    )
                else:
                    st.success(
                        f"**[{status}]** `{rec.get('test_id')}` - {severity}"
                    )

                st.write(f"**Category:** {rec.get('category', 'N/A')}")
                st.write(f"**Description:** {rec.get('description', 'N/A')}")

                c1, c2 = st.columns(2)
                c1.code(f"Expected: {rec.get('expected_value', 'N/A')}")
                c2.code(f"Actual: {rec.get('actual_value', 'N/A')}")

                st.divider()
