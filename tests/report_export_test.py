"""Unit tests for the report export helpers (txt/json/yaml rendering + saving)."""

import json
from pathlib import Path

import pytest
import yaml

from report.export import (
    default_report_path,
    emit_report,
    render_report,
    resolve_report_path,
    save_report,
)


def _sample_data() -> dict:
    return {
        "started": "2026-01-01 00:00:00 UTC",
        "completed": "2026-01-01 00:01:00 UTC",
        "kernel_version": "6.8.0",
        "distribution": "Ubuntu 24.04",
        "latest_version": "6.9.0",
        "kev_data": [{"cve_id": "CVE-2024-1086", "severity": "HIGH"}],
        "runs": [],
        "statistics": {"total": 3, "with_exploits": 1, "in_cisa_kev": 2},
        "vulnerabilities": [
            {
                "cve_id": "CVE-2024-1086",
                "severity": "HIGH",
                "cvss_v3_score": 7.8,
                "references": [],
                "exploits": [],
                "sandbox_runs": [],
            }
        ],
        "security_recommendations": [],
        "host_info": None,
        "diff": [],
    }


def test_default_report_paths():
    assert default_report_path("txt") == "report_data.txt"
    assert default_report_path("json") == "report_data.json"
    assert default_report_path("yaml") == "report_data.yaml"


def test_resolve_report_path_default():
    assert resolve_report_path(None, "json") == Path("report_data.json")


def test_resolve_report_path_appends_extension():
    assert resolve_report_path("out/audit", "yaml") == Path("out/audit.yaml")


def test_resolve_report_path_keeps_extension():
    assert resolve_report_path("audit.json", "json") == Path("audit.json")


def test_resolve_report_path_invalid_format():
    with pytest.raises(ValueError):
        resolve_report_path(None, "html")


def test_render_txt():
    text = render_report(_sample_data(), "txt")
    assert "KERNEL VULNERABILITY AUDIT REPORT" in text
    assert "CVE-2024-1086" in text


def test_render_txt_no_ansi():
    text = render_report(_sample_data(), "txt", color=True)
    assert "\x1b[" not in text


def test_render_json_roundtrip():
    text = render_report(_sample_data(), "json")
    data = json.loads(text)
    assert data["kernel_version"] == "6.8.0"
    assert data["vulnerabilities"][0]["cve_id"] == "CVE-2024-1086"


def test_render_yaml_roundtrip():
    text = render_report(_sample_data(), "yaml")
    data = yaml.safe_load(text)
    assert data["distribution"] == "Ubuntu 24.04"
    assert data["statistics"]["in_cisa_kev"] == 2


def test_render_invalid_format():
    with pytest.raises(ValueError):
        render_report({}, "html")


def test_save_report_creates_parent_dirs(tmp_path):
    path = save_report(_sample_data(), tmp_path / "nested" / "audit", "json")
    assert path == tmp_path / "nested" / "audit.json"
    assert path.exists()
    assert json.loads(path.read_text())["distribution"] == "Ubuntu 24.04"


def test_save_report_txt_no_ansi(tmp_path):
    path = save_report(_sample_data(), tmp_path / "audit", "txt")
    assert "KERNEL VULNERABILITY AUDIT REPORT" in path.read_text()
    assert "\x1b[" not in path.read_text()


def test_emit_report_quiet_prints_nothing(tmp_path, capsys):
    path = emit_report(_sample_data(), tmp_path / "audit", "yaml", quiet=True)
    assert path.exists()
    assert capsys.readouterr().out == ""


def test_emit_report_prints_when_not_quiet(tmp_path, capsys):
    emit_report(_sample_data(), tmp_path / "audit", "txt", quiet=False)
    assert "KERNEL VULNERABILITY AUDIT REPORT" in capsys.readouterr().out
