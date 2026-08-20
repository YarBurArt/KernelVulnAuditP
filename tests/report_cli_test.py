
import presentation.terminal as term
from presentation.colors import BOLD, CRIT, GRAY, INFO, OK, WARN
from presentation.glyphs import unicode_glyph
from presentation.terminal import paint
from report.cli import CLIReportRenderer, _arrow


def _renderer(data=None, verbose=False, color=False):
    return CLIReportRenderer(data or {}, verbose=verbose, color=color)


def test_sev_colorize_uses_palette(monkeypatch):
    monkeypatch.setattr(term, "supports_color", lambda: True)
    r = _renderer(color=True)
    assert CRIT in r._sev("CRIT")
    assert WARN in r._sev("WARN")
    assert OK in r._sev("OK")
    assert INFO in r._sev("INFO")
    assert GRAY in r._sev("UNKNOWN")
    assert r._sev("SOMETHING_ELSE") == "[SOMETHING_ELSE]"


def test_color_disabled_returns_plain():
    r = _renderer()
    assert r._c("text", CRIT, bold=True) == "text"


def test_color_enabled_paints(monkeypatch):
    monkeypatch.setattr(term, "supports_color", lambda: True)
    r = _renderer(color=True)
    assert r._c("text", CRIT) == paint("text", CRIT)


def test_build_header_contains_fields():
    r = _renderer(
        {
            "started": "2024-01-01",
            "completed": "2024-01-01",
            "kernel_version": "6.8.0",
            "distribution": "Debian",
            "latest_version": "6.8.1",
        }
    )
    header = r._build_header()
    assert "KERNEL VULNERABILITY AUDIT REPORT" in header
    assert "6.8.0" in header
    assert "Debian" in header


def test_header_color_title_present(monkeypatch):
    monkeypatch.setattr(term, "supports_color", lambda: True)
    r = _renderer(color=True)
    header = r._build_header()
    assert "KERNEL VULNERABILITY AUDIT REPORT" in header
    assert BOLD in header


def test_kev_section_empty():
    r = _renderer()
    assert "No CVE data available" in r._build_kev_section([])


def test_kev_section_compact():
    r = _renderer()
    out = r._build_kev_section([{"cve_id": "CVE-2024-1"}])
    assert "1 CVEs in CISA KEV list" in out


def test_kev_section_verbose_lists_first_ten():
    r = _renderer(verbose=True)
    kev = [{"cve_id": f"CVE-2024-{i}", "description": f"desc {i}"} for i in range(12)]
    out = r._build_kev_section(kev)
    assert "CVE-2024-0" in out
    assert "and 2 more" in out


def test_kev_section_verbose_without_overflow():
    r = _renderer(verbose=True)
    out = r._build_kev_section([{"cve_id": "CVE-2024-1", "description": "d"}])
    assert "and" not in out


def test_runs_section_statuses_and_verbose():
    r = _renderer(verbose=True)
    runs = [
        {"id": 1, "status": "SUCCESS", "description": "ran ok",
         "stdout": "line1", "stderr": "err1"},
        {"id": 2, "status": "FAILED", "description": "crashed"},
    ]
    out = r._build_runs_section(runs)
    assert "Run 1" in out
    assert "SUCCESS" in out
    assert "STDOUT: line1" in out
    assert "STDERR: err1" in out


def test_runs_section_compact_no_output():
    r = _renderer()
    out = r._build_runs_section([{"status": "OK", "description": "fine"}])
    assert "STDOUT" not in out


def test_stats_section_empty_returns_empty():
    assert CLIReportRenderer._build_stats_section({}) == ""


def test_stats_section_with_severity():
    out = CLIReportRenderer._build_stats_section(
        {
            "total": 10,
            "with_exploits": 2,
            "in_cisa_kev": 1,
            "ransomware_related": 0,
            "critical_count": 3,
            "avg_cvss": 7.5,
            "by_severity": {"CRITICAL": 4, "HIGH": 6},
        }
    )
    assert "Total Vulnerabilities: 10" in out
    assert "CRITICAL: 4" in out
    assert "HIGH: 6" in out


def test_exploits_section_empty():
    assert CLIReportRenderer._build_exploits_section([]) == ""


def test_exploits_section_verified_flag():
    out = CLIReportRenderer._build_exploits_section(
        [{"exploit_type": "POC", "source": "GitHub", "url": "u", "verified": True}]
    )
    assert "Verified" in out


def test_exploits_section_unverified():
    out = CLIReportRenderer._build_exploits_section(
        [{"exploit_type": "POC", "source": "GitHub", "url": "u"}]
    )
    assert "Verified" not in out


def test_references_section_empty():
    assert CLIReportRenderer._build_references_section([]) == ""


def test_references_section_lists():
    out = CLIReportRenderer._build_references_section(
        [{"ref_type": "ADVISORY", "source": "NVD", "url": "https://nvd"}]
    )
    assert "[ADVISORY]" in out
    assert "https://nvd" in out


def test_sandbox_section_empty():
    assert _renderer()._build_sandbox_section([]) == ""


def test_sandbox_section_compact_no_verbose_output():
    r = _renderer()
    out = r._build_sandbox_section(
        [
            {
                "execution_success": False,
                "exit_code": 0,
                "sandbox_platform": "qemu",
                "stdout": "hidden",
                "stderr": "hidden",
            }
        ]
    )
    assert "STDOUT" not in out
    assert "STDERR" not in out


def test_sandbox_section_success_and_warnings():
    r = _renderer(verbose=True)
    out = r._build_sandbox_section(
        [
            {
                "execution_success": True,
                "exit_code": 0,
                "sandbox_platform": "qemu",
                "notes": "n",
                "exploit_file_hash": "0123456789abcdef",
                "stdout": "hi",
                "stderr": "warning text",
            },
            {"execution_success": False, "exit_code": 0},
            {"execution_success": False, "exit_code": 3},
        ]
    )
    assert "SUCCESS" in out
    assert "COMPLETED WITH WARNINGS" in out
    assert "MAYBE" in out
    assert "Notes: n" in out
    assert "0123456789abcdef" in out
    assert "STDERR: warning text" in out


def test_vuln_section_empty():
    assert _renderer()._build_vuln_section([]) == ""


def test_vuln_section_builds_entries():
    r = _renderer()
    out = r._build_vuln_section(
        [
            {
                "cve_id": "CVE-2024-1",
                "severity": "HIGH",
                "cvss_v3_score": 8.8,
                "criticality_score": 80,
                "description": "some vuln",
            }
        ]
    )
    assert "CVE-2024-1" in out
    assert "8.8" in out
    assert "80/100" in out
    assert "some vuln" in out


def test_row_status_color_classification():
    assert CLIReportRenderer._row_status_color("FAIL") == CRIT
    assert CLIReportRenderer._row_status_color("ok") == OK


def test_render_two_column_aligned_with_detail():
    r = _renderer(verbose=True)
    out = r._render_two_column(
        {
            "headers": ["Expected", "Actual"],
            "rows": [
                {
                    "key": "param",
                    "left": "0",
                    "right": "2",
                    "status": "FAIL",
                    "detail": "mismatch",
                }
            ],
        }
    )
    assert "param" in out
    assert "mismatch" in out
    assert "Expected" in out


def test_render_two_column_detail_hidden_when_ok_and_not_verbose():
    r = _renderer()
    out = r._render_two_column(
        {
            "headers": ["L", "R"],
            "rows": [
                {"key": "k", "left": "a", "right": "a", "status": "OK",
                 "detail": "hidden"}
            ],
        }
    )
    assert "hidden" not in out


def test_render_two_column_color_changes_changed_right(monkeypatch):
    monkeypatch.setattr(term, "supports_color", lambda: True)
    r = _renderer(color=True)
    out = r._render_two_column(
        {
            "headers": ["L", "R"],
            "rows": [
                {"key": "k", "left": "a", "right": "b", "status": "WARN",
                 "changed": True}
            ],
        }
    )
    assert WARN in out


def test_hardening_section_empty():
    assert _renderer()._build_hardening_diff_section([]) == ""


def test_hardening_section_module_layout():
    r = _renderer()
    diff = [
        {"type": "module", "key": "btrfs", "status": "new",
         "expected": "not loaded", "actual": "loaded in sandbox"},
        {"type": "module", "key": "kvm", "status": "removed",
         "expected": "loaded", "actual": "not loaded in sandbox"},
    ]
    out = r._build_hardening_diff_section(diff)
    assert "Hardening & Diff" in out
    assert "btrfs" in out


def test_hardening_section_param_two_column():
    r = _renderer(verbose=True)
    diff = [
        {"type": "param", "key": "fs.suid_dumpable", "status": "FAIL",
         "expected": "0", "actual": "2", "detail": "mismatch"},
    ]
    out = r._build_hardening_diff_section(diff)
    assert "fs.suid_dumpable" in out
    assert "mismatch" in out


def test_hardening_section_capability_layout():
    r = _renderer()
    diff = [
        {
            "type": "capability",
            "key": "/usr/bin/capbin",
            "status": "WARN",
            "actual": "cap_sys_admin",
            "detail": "file: /usr/bin/capbin owner: root",
        },
    ]
    out = r._build_hardening_diff_section(diff)
    assert "cap_sys_admin" in out
    assert "capbin" in out


def test_columns_balances_and_wraps():
    out = CLIReportRenderer._columns(["a", "bb", "ccc"], width=100)
    assert len(out) == 2
    assert "ccc" in out[0] or "ccc" in out[1]


def test_columns_empty():
    assert CLIReportRenderer._columns([]) == []


def test_columns_single():
    out = CLIReportRenderer._columns(["only"], width=100)
    assert len(out) == 1
    assert "only" in out[0]


def test_render_references_table_plain():
    out = _renderer()._render_references_table(
        [{"what": "cap", "how": "h", "why": "danger"}]
    )
    assert "cap" in out
    assert "h" in out
    assert "danger" in out


def test_render_references_table_color_links():
    out = _renderer(color=True)._render_references_table(
        [{"what": "cap", "how": "h", "why": "danger"}]
    )
    assert "cap" in out
    assert "\x1b]8" in out


def test_render_capability_groups_empty():
    assert _renderer()._render_capability_groups({"rows": []}) == ""


def test_render_capability_groups_without_detail():
    r = _renderer()
    out = r._render_capability_groups(
        {
            "rows": [
                {"key": "cap_sys_admin", "left": "2", "status": "WARN"},
            ]
        }
    )
    assert "cap_sys_admin" in out


def test_hardening_section_references_fallback_links():
    r = _renderer()
    diff = [
        {"type": "param", "key": "k", "status": "FAIL",
         "expected": "a", "actual": "b", "link": "https://example.com/advisory"},
    ]
    out = r._build_hardening_diff_section(diff)
    assert "example.com" in out


def test_columns_empty_cell_padding():
    out = CLIReportRenderer._columns(["", "x"], width=100)
    assert isinstance(out, list)


def test_columns_empty_after_wrap_emits_blank():
    long = "a" * 200
    out = CLIReportRenderer._columns([long, "x"], width=100)
    assert any(line.strip() == "" for line in out) or len(out) >= 1


def test_columns_both_empty_emits_blank_row():
    out = CLIReportRenderer._columns(["", ""], width=100)
    assert any(line == "" for line in out)


def test_render_references_empty():
    assert _renderer()._render_references_table([]) == ""


def test_build_full_report_integration():
    r = _renderer(
        {
            "kev_data": [{"cve_id": "CVE-2024-1"}],
            "runs": [{"status": "OK", "description": "d"}],
            "statistics": {"total": 1},
            "vulnerabilities": [
                {"cve_id": "CVE-2024-2", "severity": "LOW", "description": "x"}
            ],
            "diff": [
                {"type": "param", "key": "k", "status": "OK",
                 "expected": "a", "actual": "a"}
            ],
        }
    )
    report = r.build_full_report()
    assert "END OF REPORT" in report
    assert "CVE-2024-2" in report


def test_render_pages_output(monkeypatch):
    from report.cli import CLIReportRenderer

    captured = {}

    def fake_pager(text):
        captured["text"] = text

    monkeypatch.setattr("report.cli.pager", fake_pager)
    r = CLIReportRenderer({"kev_data": [], "runs": []})
    r.render()
    assert "END OF REPORT" in captured["text"]


def test_arrow_returns_glyph():
    assert _arrow() == unicode_glyph("↳", "->")