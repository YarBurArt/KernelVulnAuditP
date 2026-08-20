"""Unit tests for the main CLI argument parsing and report-producing flows."""

import io
from pathlib import Path
from unittest import mock

import pytest

import presentation.terminal as term
from cli_app import CLIApp, build_parser, main_cli
from core.entities import CveExecution, ExecutionReport, PocExecution


def _sample_data() -> dict:
    return {
        "started": "2026-01-01 00:00:00 UTC",
        "completed": "2026-01-01 00:01:00 UTC",
        "kernel_version": "6.8.0",
        "distribution": "Ubuntu 24.04",
        "latest_version": "6.9.0",
        "kev_data": [],
        "runs": [],
        "statistics": {"total": 0},
        "vulnerabilities": [],
        "security_recommendations": [],
        "host_info": None,
        "diff": [],
    }


def test_parse_full_poc_tests_flags():
    args = build_parser().parse_args(
        ["--full-poc-tests", "-o", "audit.yaml", "--format", "yaml", "-q"]
    )
    assert args.full_poc_tests is True
    assert args.output == "audit.yaml"
    assert args.format == "yaml"
    assert args.quiet is True


def test_parse_report_defaults():
    args = build_parser().parse_args(["--report"])
    assert args.report is True
    assert args.output is None
    assert args.format is None
    assert args.quiet is False


def test_parse_invalid_format_exits():
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(["--report", "--format", "html"])
    assert exc.value.code == 2


def test_parse_quiet_short_flag():
    args = build_parser().parse_args(["-r", "-q"])
    assert args.report is True
    assert args.quiet is True


@mock.patch("cli_app.AppServices")
def test_quiet_disables_progress_bar(MockServices):
    CLIApp(db=mock.Mock(), quiet=True)
    assert MockServices.call_args.kwargs["progress"] is None


@mock.patch("cli_app.AppServices")
def test_non_quiet_uses_progress_bar(MockServices):
    CLIApp(db=mock.Mock(), quiet=False)
    assert MockServices.call_args.kwargs["progress"] is term.ProgressBar


def test_progress_bar_step_accepts_note_kwarg():
    """AppServices calls bar.step(label=..., note=...); the CLI bar must
    accept it (the old signature raised TypeError, which aborted the async
    flow and left asyncio.to_thread coroutines never awaited)."""
    with mock.patch.object(term, "stream_tty", return_value=True):
        bar = term.ProgressBar(total=5, label="Local recon", stream=io.StringIO())
        bar.step(label="lynis", note="147 checks")
        bar.step(label="linpeas", note="3 CVEs")
        bar.finish(note="complete")
    drawn = bar._stream.getvalue()
    assert "lynis" in drawn
    assert "147 checks" in drawn
    assert "100% 5/5" in drawn


@mock.patch("cli_app.AppServices")
@mock.patch("report.build_report_data")
@mock.patch("report.emit_report")
def test_run_full_poc_tests_flow(mock_emit, mock_build, MockServices):
    mock_build.return_value = _sample_data()
    mock_emit.return_value = Path("report_data.txt")

    services = MockServices.return_value
    recon_result = mock.Mock()
    recon_result.local.security_recommendations = []
    services.run_full_recon.return_value = recon_result
    services.store_security_recommendations.return_value = 0
    services.run_execution_tests.return_value = ExecutionReport(
        cves_processed=1,
        entries=[
            CveExecution(
                pocs=[PocExecution(url="https://example.invalid/x")]
            )
        ],
    )

    app = CLIApp(db=mock.Mock())
    app.run_full_poc_tests(output="audit", fmt="json")

    services.run_full_recon.assert_called_once_with()
    services.store_security_recommendations.assert_called_once_with([])
    services.run_execution_tests.assert_called_once_with()
    mock_build.assert_called_once_with(app.db)
    _, kwargs = mock_emit.call_args
    assert kwargs["fmt"] == "json"
    assert kwargs["output"] == "audit"
    assert kwargs["quiet"] is False


@mock.patch("cli_app.AppServices")
@mock.patch("report.build_report_data")
@mock.patch("report.emit_report")
def test_run_report_quiet(mock_emit, mock_build, MockServices):
    mock_build.return_value = _sample_data()
    mock_emit.return_value = Path("report_data.yaml")

    app = CLIApp(db=mock.Mock(), quiet=True)
    app.run_report(output="audit", fmt="yaml")

    mock_build.assert_called_once()
    _, kwargs = mock_emit.call_args
    assert kwargs["fmt"] == "yaml"
    assert kwargs["quiet"] is True


@mock.patch("cli_app.CLIApp")
@mock.patch("sys.argv", ["main.py", "--full-poc-tests", "-o", "x.txt", "-q"])
def test_main_cli_dispatch_full_poc(MockCLIApp):
    app = MockCLIApp.return_value
    main_cli(db=mock.Mock())
    MockCLIApp.assert_called_once()
    assert MockCLIApp.call_args.kwargs["quiet"] is True
    app.run_full_poc_tests.assert_called_once_with(output="x.txt", fmt="txt")


@mock.patch("cli_app.CLIApp")
@mock.patch("sys.argv", ["main.py", "--exec-tests", "--format", "json", "-o", "x.json"])
def test_main_cli_exec_tests_emits_report(MockCLIApp):
    app = MockCLIApp.return_value
    main_cli(db=mock.Mock())
    app.run_execution_tests.assert_called_once()
    app.run_report.assert_called_once_with(output="x.json", fmt="json")


@mock.patch("cli_app.CLIApp")
@mock.patch("sys.argv", ["main.py", "--scan"])
def test_main_cli_scan_no_report_without_output(MockCLIApp):
    app = MockCLIApp.return_value
    main_cli(db=mock.Mock())
    app.run_scan.assert_called_once_with(save=False)
    app.run_report.assert_not_called()


@mock.patch("cli_app.CLIApp")
@mock.patch("sys.argv", ["main.py", "--report"])
def test_main_cli_error_exits_nonzero(MockCLIApp):
    app = MockCLIApp.return_value
    app.run_report.side_effect = OSError("disk full")
    with pytest.raises(SystemExit) as exc:
        main_cli(db=mock.Mock())
    assert exc.value.code == 1


def _param_diff() -> list:
    from report import build_diff

    return build_diff(
        sandbox_modules=set(),
        host_modules=set(),
        kernel_recs=[
            {
                "field_name": "fs.suid_dumpable",
                "expected_value": "0",
                "actual_value": "2",
                "description": "restrict core dumps",
            }
        ],
        host_info=None,
    )


def test_report_diff_arrow_ascii_on_pure_tty(monkeypatch):
    """On a pure TTY the tree connector must degrade to ASCII, never '?'."""
    from report.cli import CLIReportRenderer

    monkeypatch.setattr("presentation.glyphs._unicode_supported", False)
    renderer = CLIReportRenderer({}, verbose=False, color=False)
    section = renderer._build_hardening_diff_section(_param_diff())
    assert "-> " in section
    assert "↳" not in section
    assert all(c.isascii() for c in section)


def test_report_diff_arrow_keeps_unicode(monkeypatch):
    from report.cli import CLIReportRenderer

    monkeypatch.setattr("presentation.glyphs._unicode_supported", True)
    renderer = CLIReportRenderer({}, verbose=False, color=False)
    section = renderer._build_hardening_diff_section(_param_diff())
    assert "↳" in section
