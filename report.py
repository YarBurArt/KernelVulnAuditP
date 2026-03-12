import sys
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    import streamlit as st
    STREAMLIT_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    STREAMLIT_AVAILABLE = False

from db import get_db
from recon import LocalRecon


class StreamlitReportRenderer:
    """render report using Streamlit web UI"""

    def __init__(self, data: Dict[str, Any]):
        self.data = data

    def render(self) -> None:
        """render full report"""
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
        """render header metrics"""
        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Started", self.data.get("started", "N/A"))
        c2.metric("Completed", self.data.get("completed", "N/A"))
        c3.metric("Kernel", self.data.get("kernel_version", "N/A"))
        c4.metric("Distribution", self.data.get("distribution", "N/A"))
        c5.metric("Latest Version", self.data.get("latest_version", "N/A"))

    def _render_kev_stats(self) -> None:
        """render KEV stats section"""
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
        """render execution logs section"""
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
        """render database statistics"""
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
        """render exploits/POCs section"""
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
        """render references section"""
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
        """render single sandbox run"""
        success = run.get("execution_success", False)
        exit_code = run.get("exit_code", -1)

        if success:
            st.success(f"Execution successful (exit code: {exit_code})")
        elif exit_code == 0:
            st.warning(f"Execution completed with warnings")
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
        """render sandbox I/O section"""
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
        """render sandbox processes and files"""
        procs = run.get('open_processes') or []
        if procs:
            st.write("Processes:", ", ".join(procs))
        files = run.get('open_files') or []
        if files:
            st.write("Files:", ", ".join(files))

    def _render_sandbox_runs(
        self, sandbox_runs: List[Dict[str, Any]]
    ) -> None:
        """render sandbox runs section"""
        if not sandbox_runs:
            return
        with st.expander(f"Sandbox Runs ({len(sandbox_runs)})"):
            for run in sandbox_runs:
                self._render_sandbox_run(run)

    def _render_vulnerability(self, vuln: Dict[str, Any]) -> None:
        """render single vulnerability"""
        with st.expander(
            f"{vuln.get('cve_id')} - {vuln.get('severity', 'N/A')} "
            f"(CVSS: {vuln.get('cvss_v3_score', 'N/A')})"
        ):
            st.write(vuln.get("description", "No description"))
            c1, c2, c3 = st.columns(3)
            c1.metric(
                "Criticality", 
                f"{vuln.get('criticality_score', 0)}/100")
            c2.metric("Exploits", vuln.get("exploit_count", 0))
            c3.metric("In KEV", "Yes" if vuln.get("in_cisa_kev") else "No")

            self._render_exploits(vuln.get("exploits", []))
            self._render_references(vuln.get("references", []))
            self._render_sandbox_runs(vuln.get("sandbox_runs", []))

    def _render_vulnerabilities(self) -> None:
        """render all vulnerabilities"""
        vulns = self.data.get("vulnerabilities", [])
        if not vulns:
            return
        st.subheader(f"Vulnerabilities ({len(vulns)})")
        for vuln in vulns:
            self._render_vulnerability(vuln)

    def _render_security_recommendations(self) -> None:
        """render security recommendations section"""
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


class CLIReportRenderer:
    """render report using plain text CLI output"""

    def __init__(self, data: Dict[str, Any], verbose: bool = False):
        self.data = data
        self.verbose = verbose

    def render(self) -> None:
        """render full report"""
        print(self._build_full_report())

    def _build_full_report(self) -> str:
        """build complete report string"""
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
        """build report header"""
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
        """build KEV section string"""
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
        """build execution logs section string"""
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
        """build database statistics section string"""
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
        """build exploits section string"""
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
        """build references section string"""
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
        """build sandbox runs section string"""
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
        """build vulnerabilities section string"""
        if not vulns:
            return ""

        section = f"\n--- Vulnerabilities ({len(vulns)}) ---\n"
        for vuln in vulns:
            section += (
                f"\n{'=' * 50}\n"
                f"  {vuln.get('cve_id', 'N/A')} [{vuln.get('severity', 'N/A')}]\n"
                f"  CVSS: {vuln.get('cvss_v3_score', 'N/A')} | "
                f"Criticality: {vuln.get('criticality_score', 0)}/100\n"
                f"  {vuln.get('description', 'No description')[:150]}\n"
            )

            section += self._build_exploits_section(vuln.get("exploits", []))
            section += self._build_references_section(vuln.get("references", []))
            section += self._build_sandbox_section(vuln.get("sandbox_runs", []))

        return section

    def _build_recommendations_section(
        self, recs: List[Dict[str, Any]], stats: Dict[str, Any]
    ) -> str:
        """build security recommendations section string"""
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


def save_report_json(
    data: Dict[str, Any], filepath: str = "report_data.json"
) -> None:
    """save report data to JSON file"""
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    print(f"Report saved to {filepath}")


def load_report_json(
    filepath: str = "report_data.json"
) -> Optional[Dict[str, Any]]:
    """load report data from JSON file"""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return None


def fetch_all_vulnerabilities(db) -> List[Dict[str, Any]]:
    """fetch all vulnerabilities with full details"""
    all_vulns = []
    offset = 0
    chunk = 50
    while True:
        batch = db.search(limit=chunk, offset=offset)
        if not batch:
            break
        for vuln in batch:
            full = db.get_vulnerability_with_details(vuln["cve_id"])
            if full:
                all_vulns.append(full)
        if len(batch) < chunk:
            break
        offset += chunk
    return all_vulns


def build_kev_data(db) -> List[Dict[str, Any]]:
    """build KEV data list from DB"""
    kev_list = db.get_cisa_kev_list(limit=100)
    kev_data = []
    for vuln in kev_list:
        kev_data.append({
            "cve_id": vuln.get("cve_id"),
            "description": vuln.get("description", "")[:100],
            "cvss_v3_score": vuln.get("cvss_v3_score"),
            "severity": vuln.get("severity"),
            "criticality_score": vuln.get("criticality_score"),
        })
    return kev_data


def build_sandbox_runs(db) -> List[Dict[str, Any]]:
    """build sandbox runs list from DB"""
    runs = []
    critical_vulns = db.get_critical(limit=5)
    for idx, vuln in enumerate(critical_vulns, 1):
        cve_id = vuln.get("cve_id")
        sandbox_runs = db.get_sandbox_runs(cve_id)
        for run in sandbox_runs:
            runs.append({
                "id": idx,
                "status": (
                    "SUCCESS" if run.get("execution_success") else "MAYBE"
                ),
                "description": f"PoC test for {cve_id}",
                "stdout": run.get("stdout", "")[:500],
                "stderr": run.get("stderr", "")[:500],
            })
    return runs


def build_security_recommendations(db) -> List[Dict[str, Any]]:
    """build security recommendations list from DB"""
    return db.get_security_recommendations(limit=200)


def get_kernel_info() -> Dict[str, str]:
    """get kernel info from LocalRecon"""
    try:
        lr = LocalRecon()
        kernel = lr.get_kernel_version_simple()
        build_date = lr.get_kernel_build_date(kernel)
        system = lr.environment_info.get("system", "Linux")

        # retry get version FIXME 
        latest = "Unknown"
        try:
            import httpx
            major = kernel.split('.')[0] if kernel else '6'
            resp = httpx.get(
                f"https://cdn.kernel.org/pub/linux/kernel/v{major}.x/"
            )
            if resp.status_code == 200:
                import re
                versions = re.findall(
                    r'change-log-(\d+\.\d+\.\d+)', resp.text, re.IGNORECASE
                )
                if versions:
                    latest = max(versions)
        except Exception:
            pass

        p_build = None
        if build_date:
            p_build = datetime.fromtimestamp(
                build_date, tz=timezone.utc
            ).strftime('%Y-%m-%d %H:%M:%S')

        return {
            "kernel_version": kernel,
            "distribution": system,
            "latest_version": latest,
            "build_date": p_build
        }
    except Exception:
        return {
            "kernel_version": "Unknown",
            "distribution": "Unknown",
            "latest_version": "Unknown",
            "build_date": None
        }


def sort_vulnerabilities(vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """sort vulns: with sandbox runs first 
    (by year desc, crit desc), then without (by year desc, crit desc)"""
    with_runs = []
    without_runs = []

    for v in vulns:
        if v.get('sandbox_runs') and len(v['sandbox_runs']) > 0:
            with_runs.append(v)
        else:
            without_runs.append(v)

    def sort_key(v):
        # Extract YYYY cve
        cve_id = v.get('cve_id', '')
        year = 0
        if cve_id.startswith('CVE-'):
            try:
                year = int(cve_id.split('-')[1])
            except (ValueError, IndexError):
                year = 0
        crit = v.get('criticality_score', 0) or 0
        # Sort: -year (desc), -crit (desc)
        return (-year, -crit)

    with_runs_sorted = sorted(with_runs, key=sort_key)
    without_runs_sorted = sorted(without_runs, key=sort_key)

    return with_runs_sorted + without_runs_sorted


def build_report_data(db=None) -> Dict[str, Any]:
    """build report data structure from DB"""
    if db is None:
        db = get_db("orm")

    kernel_info = get_kernel_info()
    vulns = fetch_all_vulnerabilities(db)
    sorted_vulns = sort_vulnerabilities(vulns)

    return {
        "started": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z"),
        "completed": datetime.now(timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S %Z"
        ),
        "kernel_version": kernel_info["kernel_version"],
        "distribution": kernel_info["distribution"],
        "latest_version": kernel_info["latest_version"],
        "kev_data": build_kev_data(db),
        "runs": build_sandbox_runs(db),
        "statistics": db.get_statistics(),
        "vulnerabilities": sorted_vulns,
        "security_recommendations": build_security_recommendations(db),
    }


def main(
    verbose: bool = False,
    save_json: bool = False,
    filepath: str = "report_data.json"
):
    """main entry point for report generation"""
    db = get_db("orm")

    try:
        data = build_report_data(db)

        if STREAMLIT_AVAILABLE:
            if save_json:
                save_report_json(data, filepath)
            StreamlitReportRenderer(data).render()
        else:
            CLIReportRenderer(data, verbose=verbose).render()
            save_report_json(data, filepath)

    finally:
        db.close()


def main_cli():
    """CLI argument parsing for report"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate Kernel Vulnerability Report"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--save", "-s", action="store_true",
        help="Save report to JSON file"
    )
    parser.add_argument(
        "--output", "-o", type=str, default="report_data.json",
        help="Output JSON file path (default: report_data.json)"
    )
    parser.add_argument(
        "--load", "-l", type=str, default=None,
        help="Load and display existing report from JSON file"
    )

    args = parser.parse_args()

    if args.load:
        data = load_report_json(args.load)
        if data is None:
            print(f"Error: Could not load report from {args.load}")
            sys.exit(1)
        if STREAMLIT_AVAILABLE:
            StreamlitReportRenderer(data).render()
        else:
            CLIReportRenderer(data, verbose=args.verbose).render()
    else:
        main(
            verbose=args.verbose,
            save_json=args.save,
            filepath=args.output
        )


if __name__ == "__main__":
    if STREAMLIT_AVAILABLE and len(sys.argv) == 1:
        main()
    else:
        main_cli()
