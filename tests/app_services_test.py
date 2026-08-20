from datetime import UTC, datetime
from types import SimpleNamespace
from unittest import mock

from sqlalchemy.exc import IntegrityError

from app_services import AppServices, _NoopProgress
from application.dto import LesCVEItem
from core.entities import (
    CisaKevEntry,
    CveExecution,
    ExecutionReport,
    PocExecution,
    RecommendationStats,
    RunLogs,
    SandboxRunResult,
    SecurityRecommendationType,
    Statistics,
    Vulnerability,
)
from isolate.poc_runner import PocRunOutcome
from sqxpl import GitHubExploitSearcher


def _bare_services(**overrides):
    services = object.__new__(AppServices)
    services.db = mock.MagicMock()
    services.lr = mock.MagicMock()
    services.rf = mock.AsyncMock()
    services.poc_searcher = mock.MagicMock()
    services.isolate = mock.MagicMock()
    services.poc_runner = mock.MagicMock()
    services.progress = None
    for key, value in overrides.items():
        setattr(services, key, value)
    return services


def _rec(test_id="KRNL-1000", **kw):
    return SecurityRecommendationType(
        test_id=test_id,
        category=kw.get("category", "kernel"),
        severity=kw.get("severity", "HIGH"),
        status=kw.get("status", "open"),
    )


def test_noop_progress_any_attribute():
    bar = _NoopProgress()
    assert bar.step(label="x", note="y") is None
    assert bar.finish(note="z") is None
    assert bar.detail(label="x") is None


def test_make_bar_returns_noop_when_no_progress():
    s = _bare_services()
    assert isinstance(s._make_bar(5, "label"), _NoopProgress)


def test_make_bar_uses_progress_callable():
    factory = mock.MagicMock()
    s = _bare_services(progress=factory)
    s._make_bar(5, "label")
    factory.assert_called_once_with(total=5, label="label")


def test_store_security_recommendations():
    s = _bare_services()
    s.db.bulk_insert_recommendations.return_value = 2

    result = s.store_security_recommendations([_rec(), _rec("KRNL-2000")])

    assert result == 2
    s.db.bulk_insert_recommendations.assert_called_once()


def test_parse_kev_date_valid():
    parsed = AppServices._parse_kev_date("2024-01-15")
    assert parsed == datetime(2024, 1, 15, tzinfo=UTC)


def test_parse_kev_date_none_and_invalid():
    assert AppServices._parse_kev_date(None) is None
    assert AppServices._parse_kev_date("not-a-date") is None


def test_build_kev_records():
    s = _bare_services()
    cve_id, kev_data, vuln_data = s._build_kev_records(
        {
            "cveID": "CVE-2024-1",
            "dateAdded": "2024-01-15",
            "dueDate": "2024-02-15",
            "requiredAction": "Patch",
            "knownRansomwareCampaignUse": "Known",
            "vendorProject": "Linux",
            "product": "kernel",
            "notes": "note",
            "shortDescription": "desc",
        }
    )
    assert cve_id == "CVE-2024-1"
    assert kev_data.known_ransomware is True
    assert kev_data.date_added == datetime(2024, 1, 15, tzinfo=UTC)
    assert vuln_data.in_cisa_kev is True


def test_build_kev_records_not_known_ransomware():
    s = _bare_services()
    _, kev_data, _ = s._build_kev_records(
        {"cveID": "CVE-2024-1", "knownRansomwareCampaignUse": "Unknown"}
    )
    assert kev_data.known_ransomware is False


def test_save_kev_entry_success():
    s = _bare_services()
    assert (
        s._save_kev_entry(
            "CVE-2024-1", CisaKevEntry(), Vulnerability(cve_id="CVE-2024-1")
        )
        is True
    )
    s.db.upsert_vulnerability.assert_called_once()
    s.db.add_cisa_kev.assert_called_once()


def test_save_kev_entry_integrity_error_returns_false():
    s = _bare_services()
    s.db.add_cisa_kev.side_effect = IntegrityError("stmt", {}, Exception())
    assert (
        s._save_kev_entry(
            "CVE-2024-1", CisaKevEntry(), Vulnerability(cve_id="CVE-2024-1")
        )
        is False
    )


def test_save_kev_entry_other_error_returns_false():
    s = _bare_services()
    s.db.upsert_vulnerability.side_effect = ValueError("bad")
    assert (
        s._save_kev_entry(
            "CVE-2024-1", CisaKevEntry(), Vulnerability(cve_id="CVE-2024-1")
        )
        is False
    )


def test_normalize_source():
    assert AppServices._normalize_source("les") == "LES"
    assert AppServices._normalize_source("linpeas") == "LINPEAS"


def test_build_vulnerability_with_context():
    s = _bare_services()
    vuln = s._build_vulnerability(
        "CVE-2024-1",
        {"details": "detail", "severity": "HIGH", "source": "les"},
        {"description": "meta", "cvss_v3_score": 7.5, "raw": {"x": 1}},
        {"kernel_version": "6.8.0"},
    )
    assert vuln.cve_id == "CVE-2024-1"
    assert vuln.severity == "HIGH"
    assert vuln.sources == ["LES"]
    assert vuln.raw_data["context"]["kernel_version"] == "6.8.0"


def test_build_vulnerability_falls_back_to_metadata():
    s = _bare_services()
    vuln = s._build_vulnerability(
        "CVE-2024-1", {"source": "linpeas"}, {"description": "m"}, None
    )
    assert vuln.description == "m"
    assert "context" not in vuln.raw_data


def _execution(cve_id="CVE-1", pocs=None):
    return CveExecution(cve_id=cve_id, pocs=pocs or [])


def _poc(sandbox=None, error=None):
    return PocExecution(sandbox=sandbox, sandbox_error=error)


def test_cve_outcome_note_variants():
    assert AppServices._cve_outcome_note(None) == "no data"
    assert AppServices._cve_outcome_note(_execution()) == "no PoCs"


def test_cve_outcome_note_full_stats():
    note = AppServices._cve_outcome_note(
        _execution(
            pocs=[
                _poc(SandboxRunResult(
                    returncode=1, execution_mode="qemu", crashed=True,
                    stdout="", stderr="", duration_ms=0.0,
                )),
                _poc(SandboxRunResult(
                    returncode=0, execution_mode="qemu", crashed=False,
                    stdout="", stderr="", duration_ms=0.0,
                )),
                _poc(error="boom"),
            ]
        )
    )
    assert "3 PoCs" in note
    assert "ok" in note
    assert "crashed" in note
    assert "errors" in note


def test_cve_outcome_note_no_ok_no_crash():
    note = AppServices._cve_outcome_note(
        _execution(
            pocs=[
                _poc(SandboxRunResult(
                    returncode=1, execution_mode="qemu", crashed=False,
                    stdout="", stderr="", duration_ms=0.0,
                ))
            ]
        )
    )
    assert "1 PoCs" in note
    assert "ok" not in note
    assert "crashed" not in note


def test_cve_outcome_note_crash_only():
    note = AppServices._cve_outcome_note(
        _execution(
            pocs=[
                _poc(SandboxRunResult(
                    returncode=1, execution_mode="qemu", crashed=True,
                    stdout="", stderr="", duration_ms=0.0,
                ))
            ]
        )
    )
    assert "crashed" in note


def test_cve_outcome_note_multiple_modes_no_mode():
    note = AppServices._cve_outcome_note(
        _execution(
            pocs=[
                _poc(SandboxRunResult(
                    returncode=0, execution_mode="qemu", crashed=False,
                    stdout="", stderr="", duration_ms=0.0,
                )),
                _poc(SandboxRunResult(
                    returncode=0, execution_mode="host", crashed=False,
                    stdout="", stderr="", duration_ms=0.0,
                )),
            ]
        )
    )
    assert "qemu" not in note


def test_build_execution_report():
    s = _bare_services()
    s.db.get_statistics.return_value = Statistics(total=1)
    report = s._build_execution_report(
        {"kernel_version": "6.8.0", "build_date": None}, []
    )
    assert report.kernel == "6.8.0"
    assert report.build_date is None
    assert report.stats.total == 1


def test_register_poc():
    s = _bare_services()
    s._register_poc("CVE-2024-1", {"url": "https://github.com/x"})
    s.db.add_exploit.assert_called_once()
    s.db.add_reference.assert_called_once()


def test_register_poc_without_url():
    s = _bare_services()
    s._register_poc("CVE-2024-1", {})
    s.db.add_exploit.assert_called_once()
    s.db.add_reference.assert_not_called()


def test_build_poc_summary():
    summary = AppServices._build_poc_summary(
        {"url": "u", "language": "C", "stars": 5, "compile_cmd": "gcc", "test_cmd": "./x"}
    )
    assert summary.url == "u"
    assert summary.language == "C"
    assert summary.stars == 5


def test_execute_poc_no_repo_returns_empty():
    s = _bare_services()
    result = s._execute_poc("CVE-2024-1", {})
    assert result.sandbox is None and result.sandbox_error is None
    s.poc_runner.run.assert_not_called()


def test_execute_poc_delegates_skipped_outcome(tmp_path):
    s = _bare_services()
    s.poc_runner.run.return_value = PocRunOutcome()
    result = s._execute_poc("CVE-2024-1", {"local_path": str(tmp_path)})
    assert result.sandbox is None and result.sandbox_error is None
    s.poc_runner.run.assert_called_once()


def test_execute_poc_error_outcome(tmp_path):
    s = _bare_services()
    s.poc_runner.run.return_value = PocRunOutcome(error="compile failed: cc fail")
    result = s._execute_poc(
        "CVE-2024-1",
        {"local_path": str(tmp_path), "compile_cmd": "gcc x.c"},
    )
    assert result.sandbox_error == "compile failed: cc fail"


def test_execute_poc_sandbox_success(tmp_path):
    s = _bare_services()
    run = SandboxRunResult(
        returncode=0,
        execution_mode="qemu",
        crashed=False,
        stdout="out",
        stderr="err",
        duration_ms=100.0,
    )
    s.poc_runner.run.return_value = PocRunOutcome(sandbox=run, command="./x")
    with mock.patch.object(s, "_store_sandbox_run") as store:
        result = s._execute_poc(
            "CVE-2024-1",
            {"local_path": str(tmp_path), "test_cmd": "./x"},
        )
    assert result.sandbox is run
    assert result.sandbox_error is None
    store.assert_called_once_with("CVE-2024-1", run, "./x")


def test_generate_report():
    s = _bare_services()
    import app_services
    from application.dto import ReconResult

    with mock.patch.object(
        s, "run_full_recon", return_value=ReconResult(local=None, feeds=None)
    ), mock.patch.object(
        app_services, "format_report", return_value="<report>"
    ) as fmt_mock:
        assert s.generate_report() == "<report>"
    fmt_mock.assert_called_once()


def test_run_feeds_recon_async_with_kev_store():
    s = _bare_services()
    s.lr.get_kernel_version_simple.return_value = "6.8.0"
    s.lr.get_kernel_build_date.return_value = 1234
    s.rf.kev_kern_vuln = []
    s.rf.nist_search.return_value = []
    s.rf.osv_search.return_value = []
    s.rf.github_search.return_value = []

    import asyncio

    result = asyncio.run(s._run_feeds_recon_async(store_kev=True))
    assert result.findings == []


def test_process_single_cve_hint_not_saved():
    s = _bare_services()
    with mock.patch.object(
        s, "_persist_cve_hint", new=mock.AsyncMock(return_value=None)
    ):
        import asyncio

        entry = asyncio.run(
            s._process_single_cve("CVE-1", {"source": "les"}, {})
        )
    assert entry is None


def test_process_single_cve_gathers_pocs():
    s = _bare_services()
    s.poc_searcher.search_repositories.return_value = [{"url": "u"}]

    def fake_load(repos):
        return [{"url": "u", "repo": "r"}]

    with (
        mock.patch.object(
            s,
            "_persist_cve_hint",
            new=mock.AsyncMock(
                return_value={
                    "cve_id": "CVE-1",
                    "description": "d",
                    "cvss_v3_score": 9.8,
                    "severity": "CRITICAL",
                    "sources": ["LES"],
                }
            ),
        ),
        mock.patch.object(
            s,
            "_record_poc_for_cve",
            return_value=PocExecution(sandbox=SandboxRunResult(
                returncode=0, execution_mode="qemu", crashed=False,
                stdout="", stderr="", duration_ms=0.0,
            )),
        ),
        mock.patch.object(GitHubExploitSearcher, "load_xpls", side_effect=fake_load),
    ):
        import asyncio

        entry = asyncio.run(
            s._process_single_cve("CVE-1", {"source": "les"}, {})
        )
    assert entry.cve_id == "CVE-1"
    assert len(entry.pocs) == 1 and entry.pocs[0].sandbox is not None


def test_init_builds_dependencies():
    import app_services

    with (
        mock.patch.object(app_services, "LocalRecon"),
        mock.patch.object(app_services, "ReconFeeds"),
        mock.patch.object(app_services, "GitHubExploitSearcher"),
        mock.patch.object(app_services, "Isolate"),
    ):
        services = AppServices(db=mock.MagicMock())
        assert services.lr is app_services.LocalRecon.return_value
        assert services.rf is app_services.ReconFeeds.return_value
        app_services.Isolate.assert_called_once()
    assert services.db is not None


def test_run_execution_tests_skips_none_entry():
    s = _bare_services()
    with (
        mock.patch.object(
            s, "_build_execution_context", new=mock.AsyncMock(return_value={})
        ),
        mock.patch.object(
            s, "_collect_kernel_cves", return_value={"CVE-1": {"source": "les"}}
        ),
        mock.patch.object(
            s, "_process_single_cve", new=mock.AsyncMock(return_value=None)
        ),
        mock.patch.object(s, "_build_execution_report", return_value={}),
    ):
        result = s.run_execution_tests()
    assert result == {}


def test_store_sandbox_run():
    s = _bare_services()
    result = SandboxRunResult(
        returncode=0,
        execution_mode="qemu",
        stdout="out",
        stderr="err",
        duration_ms=1.0,
        crashed=False,
        logs=RunLogs(binary="aabbcc", command="cmd"),
    )
    s._store_sandbox_run("CVE-2024-1", result, "./x")
    s.db.add_sandbox_run.assert_called_once()
    sandbox_data = s.db.add_sandbox_run.call_args[0][1]
    assert sandbox_data.execution_success is True
    assert sandbox_data.exploit_file_hash == "aabbcc"


def test_save_recon_results():
    from core.entities import CveExecution, ExecutionReport

    s = _bare_services()
    saved = s.save_recon_results(
        ExecutionReport(
            kernel="6.8.0",
            build_date="2024",
            entries=[
                CveExecution(cve_id="CVE-2024-1", description="d"),
                CveExecution(description="no cve id"),
            ],
        )
    )
    assert saved == 1
    s.db.upsert_vulnerability.assert_called_once()


def test_get_cached_recon_returns_matching():
    s = _bare_services()
    s.db.search.side_effect = [
        [
            Vulnerability(
                cve_id="CVE-1",
                raw_data={"context": {"kernel_version": "6.8.0"}},
            )
        ],
        [],
    ]
    results = s.get_cached_recon("6.8.0")
    assert len(results) == 1


def test_get_cached_recon_stops_at_small_batch():
    s = _bare_services()
    s.db.search.return_value = [Vulnerability(cve_id="CVE-1")]
    results = s.get_cached_recon("6.8.0")
    assert results == []


def test_get_cached_recon_empty_batch():
    s = _bare_services()
    s.db.search.return_value = []
    assert s.get_cached_recon("6.8.0") == []


def test_get_cached_recon_pages_through_chunks():
    s = _bare_services()
    full_page = [
        Vulnerability(
            cve_id=f"CVE-{i}",
            raw_data={"context": {"kernel_version": "6.8.0"}},
        )
        for i in range(100)
    ]
    empty = [
        Vulnerability(
            cve_id="CVE-x",
            raw_data={"context": {"kernel_version": "other"}},
        )
    ]
    s.db.search.side_effect = [full_page, empty]
    results = s.get_cached_recon("6.8.0")
    assert len(results) == 100


def test_get_statistics_merges_recommendations():
    s = _bare_services()
    s.db.get_statistics.return_value = Statistics(total=1)
    s.db.get_recommendations_stats.return_value = RecommendationStats(total=2)
    stats = s.get_statistics()
    assert stats["total"] == 1
    assert stats["security_recommendations"]["total"] == 2


def test_get_security_recommendations_passthrough():
    s = _bare_services()
    s.get_security_recommendations(category="kernel", status="open", limit=10)
    s.db.get_security_recommendations.assert_called_once_with(
        category="kernel", status="open", limit=10
    )


def test_get_cisa_kev_entries_passthrough():
    s = _bare_services()
    s.get_cisa_kev_entries(limit=5)
    s.db.get_cisa_kev_list.assert_called_once_with(limit=5)


def test_collect_kernel_cves_from_linpeas_and_les():
    s = _bare_services()
    s.lr.get_linpeas_scan_details.return_value = SimpleNamespace(
        cves=["CVE-2024-1", ""]
    )
    s.lr.get_les_scan_details.return_value = [
        LesCVEItem(cve_id="CVE-2024-2", title="t")
    ]
    cves = s._collect_kernel_cves()
    assert set(cves) == {"CVE-2024-1", "CVE-2024-2"}
    assert cves["CVE-2024-1"]["source"] == "linpeas"
    assert cves["CVE-2024-2"]["source"] == "les"


def test_collect_kernel_cves_no_linpeas():
    s = _bare_services()
    s.lr.get_linpeas_scan_details.return_value = None
    assert s._collect_kernel_cves() == {}


def test_collect_kernel_cves_skips_empty_les_cve_id():
    s = _bare_services()
    s.lr.get_linpeas_scan_details.return_value = SimpleNamespace(cves=[])
    s.lr.get_les_scan_details.return_value = [LesCVEItem(cve_id="")]
    assert s._collect_kernel_cves() == {}


def test_save_host_recon(tmp_path):
    s = _bare_services()
    s.lr.environment_info = {
        "architecture": ("x86_64",),
        "node": "host1",
        "platform": "linux",
        "distribution": "Debian",
        "current_directory": str(tmp_path),
        "username": "user",
        "home_dir": "/home/user",
        "system": "Linux",
    }
    s.lr.get_kernel_version_simple.return_value = "6.8.0"
    s.lr.kernel_version = {"kernel_release": "r", "kernel_name": "n",
                           "machine": "m", "platform_release": "p",
                           "platform_system": "ps", "platform_version": "pv",
                           "proc_version": "pr"}
    s.lr.get_loaded_kernel_modules.return_value = ["ext4", "", "kvm"]
    s.db.add_host_info.return_value = 7

    hid = s.save_host_recon(
        selinux_booleans=[], process_capabilities=[], file_capabilities=[],
        kernel_modules=["ext4", "", "kvm"],
    )

    assert hid == 7
    host = s.db.add_host_info.call_args[0][0]
    assert host.architecture == "x86_64"
    assert [m.module_name for m in host.kernel_modules] == ["ext4", "kvm"]


def test_run_local_recon_async():
    s = _bare_services()
    s.lr.get_kernel_version_simple.return_value = "6.8.0"
    s.lr.get_kernel_build_date.return_value = 1234
    s.lr.get_lynis_kernel_hardening_details.return_value = [{"test_id": "x"}]
    s.lr.get_linpeas_scan_details.return_value = SimpleNamespace(cves=[])
    s.lr.get_les_scan_details.return_value = []
    s.lr.get_host_selinux_bools.return_value = []
    s.lr.get_pids_caps.return_value = []
    s.lr.get_bpath_caps.return_value = []
    s.lr.get_selinux_hardening.return_value = []
    s.lr.get_capability_recommendations.return_value = []
    s.lr.environment_info = {"system": "Linux"}
    s.lr.get_loaded_kernel_modules.return_value = []
    s.db.add_host_info.return_value = 1

    import asyncio

    result = asyncio.run(s._run_local_recon_async())
    assert result.kernel == "6.8.0"
    assert result.system == "Linux"


def test_run_local_recon_wrapper():
    s = _bare_services()
    with mock.patch.object(s, "_run_local_recon_async", new=mock.AsyncMock()):
        result = s.run_local_recon()
    assert result is not None


def test_run_feeds_recon_async_no_store():
    s = _bare_services()
    s.lr.get_kernel_version_simple.return_value = "6.8.0"
    s.lr.get_kernel_build_date.return_value = 1234

    async def nist(kernel, build_date):
        return [{"cve_id": "CVE-1"}]

    async def osv(kernel):
        return [{"cve_id": "CVE-2"}]

    async def gh(kernel):
        return [{"url": "u"}]

    s.rf.nist_search.side_effect = nist
    s.rf.osv_search.side_effect = osv
    s.rf.github_search.side_effect = gh

    import asyncio

    result = asyncio.run(s._run_feeds_recon_async(store_kev=False))
    assert len(result.findings) == 2
    assert len(result.pocs) == 1
    s.rf.close.assert_awaited()


def test_run_full_recon_async():
    s = _bare_services()
    import asyncio

    with (
        mock.patch.object(s, "_run_local_recon_async", new=mock.AsyncMock()),
        mock.patch.object(s, "_run_feeds_recon_async", new=mock.AsyncMock()),
    ):
        result = asyncio.run(s._run_full_recon_async())
    assert result.local is not None
    assert result.feeds is not None


def test_run_feeds_recon_wrapper():
    s = _bare_services()
    with mock.patch.object(s, "_run_feeds_recon_async", new=mock.AsyncMock()):
        result = s.run_feeds_recon(store_kev=False)
    assert result is not None


def test_run_full_recon_wrapper():
    s = _bare_services()
    with mock.patch.object(s, "_run_full_recon_async", new=mock.AsyncMock()):
        result = s.run_full_recon()
    assert result is not None


def test_run_execution_tests():
    from core.entities import CveExecution

    s = _bare_services()
    with (
        mock.patch.object(
            s, "_build_execution_context", new=mock.AsyncMock(return_value={})
        ),
        mock.patch.object(
            s, "_collect_kernel_cves", return_value={"CVE-1": {"source": "les"}}
        ),
        mock.patch.object(
            s,
            "_process_single_cve",
            new=mock.AsyncMock(return_value=CveExecution(cve_id="CVE-1")),
        ),
        mock.patch.object(
            s, "_build_execution_report", return_value=ExecutionReport(entries=1)
        ),
    ):
        result = s.run_execution_tests()
    assert result.entries == 1


def test_load_and_store_kev_success():
    s = _bare_services()

    s.rf.kev_kern_vuln = [
        {"cveID": "CVE-2024-1", "knownRansomwareCampaignUse": "Known"}
    ]
    s.rf.get_cve_details_many.return_value = {
        "CVE-2024-1": {"cvss_v3_score": 9.8, "severity": "CRITICAL"}
    }
    s.db.upsert_vulnerability.return_value = mock.MagicMock()

    import asyncio

    stored = asyncio.run(s._load_and_store_kev(build_date=1234))

    assert stored == 1
    s.db.upsert_vulnerability.assert_called()
    s.db.add_cisa_kev.assert_called_once()


def test_load_and_store_kev_feed_error():
    s = _bare_services()

    async def get_kev():
        raise ValueError("feed down")

    s.rf.get_kev.side_effect = get_kev

    import asyncio

    stored = asyncio.run(s._load_and_store_kev())
    assert stored == 0


def test_load_and_store_kev_skips_missing_cve_and_skipped():
    s = _bare_services()
    s.rf.kev_kern_vuln = [
        {"knownRansomwareCampaignUse": "Unknown"},  # no cveID -> skip
        {"cveID": "CVE-2024-1", "knownRansomwareCampaignUse": "Unknown"},
    ]
    s.rf.get_cve_details_many.return_value = {}
    s.db.upsert_vulnerability.return_value = mock.MagicMock()
    s.db.add_cisa_kev.side_effect = ValueError("dup")

    import asyncio

    stored = asyncio.run(s._load_and_store_kev())

    assert stored == 0


def test_persist_cve_hint():
    s = _bare_services()
    s.rf.get_cve_details.return_value = {
        "description": "d",
        "cvss_v3_score": 9.8,
        "nist_url": "https://nvd",
        "severity": "CRITICAL",
    }

    import asyncio

    entry = asyncio.run(
        s._persist_cve_hint("CVE-2024-1", {"details": "hint", "source": "les"})
    )
    assert entry["cve_id"] == "CVE-2024-1"
    s.db.add_reference.assert_called_once()


def test_persist_cve_hint_no_metadata():
    s = _bare_services()
    s.rf.get_cve_details.return_value = {}

    import asyncio

    entry = asyncio.run(
        s._persist_cve_hint("CVE-2024-1", {"source": "linpeas"})
    )
    assert entry is not None
    s.db.add_reference.assert_not_called()


def test_build_execution_context():
    s = _bare_services()
    s.lr.get_kernel_version_simple.return_value = "6.8.0"
    s.lr.get_kernel_build_date.return_value = 99

    import asyncio

    ctx = asyncio.run(s._build_execution_context())
    assert ctx == {"kernel_version": "6.8.0", "build_date": 99}


def test_process_single_cve():
    s = _bare_services()
    s.rf.get_cve_details.return_value = {}
    s.poc_searcher.search_repositories.return_value = [{"url": "u"}]
    with mock.patch.object(GitHubExploitSearcher, "load_xpls", return_value=[]):
        import asyncio

        entry = asyncio.run(
            s._process_single_cve(
                "CVE-2024-1", {"source": "les"}, {"kernel_version": "6.8.0"}
            )
        )
    assert entry is not None
    assert entry.pocs == []


def test_record_poc_for_cve():
    s = _bare_services()
    with (
        mock.patch.object(s, "_register_poc"),
        mock.patch.object(
            s,
            "_execute_poc",
            return_value=PocExecution(sandbox=SandboxRunResult(
                returncode=0, execution_mode="qemu", crashed=False,
                stdout="", stderr="", duration_ms=0.0,
            )),
        ),
    ):
        summary = s._record_poc_for_cve("CVE-2024-1", {"url": "u"})
    assert summary.url == "u"
    assert summary.sandbox is not None