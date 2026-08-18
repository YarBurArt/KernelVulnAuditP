from datetime import UTC, datetime

import term
from report import (
    build_caps_diff,
    build_diff,
    build_diff_columns,
    build_hardening_diff,
    build_module_diff,
    build_param_diff,
    build_selinux_diff,
    build_two_column,
    collect_sandbox_modules,
    count_findings,
    host_module_names,
    host_module_set,
    host_param_map,
    host_selinux_map,
    load_selinux_params,
)
from schemas import HostInfoData, HostKernelModule, HostKernelParameter


def _proc_modules_line(name: str) -> str:
    return f"{name} 4096 0 - Live 0xffffffffc047c000"


def test_collect_sandbox_modules_parses_lines_and_dedupes():
    data = {
        "runs": [
            {"modules": [_proc_modules_line("ext4"), "  ", "", None, 5]},
            {"modules": [_proc_modules_line("ext4"), _proc_modules_line("kvm")]},
        ],
        "vulnerabilities": [
            {"sandbox_runs": [{"modules": [_proc_modules_line("nft_chain_nat")]}]}
        ],
    }
    modules = collect_sandbox_modules(data)
    assert modules == {"ext4", "kvm", "nft_chain_nat"}


def test_collect_sandbox_modules_tolerates_missing_keys():
    assert collect_sandbox_modules({}) == set()
    assert collect_sandbox_modules({"runs": [{}], "vulnerabilities": [{}]}) == set()


def test_host_module_map_from_dict_and_dataclass():
    host_dict = {
        "kernel_modules": [{"module_name": "ext4"}, {"module_name": "kvm"}]
    }
    host_data = HostInfoData(
        kernel_modules=[HostKernelModule(module_name="ext4")]
    )
    assert host_module_set(host_dict) == {"ext4", "kvm"}
    assert host_module_set(host_data) == {"ext4"}
    assert host_module_set(None) == set()


def test_build_module_diff_both_directions_sorted():
    sandbox = {"ext4", "btrfs"}
    host = {"ext4", "kvm"}
    rows = build_module_diff(sandbox, host)

    by_key = {row["key"]: row for row in rows}
    assert set(by_key) == {"btrfs", "kvm"}

    assert by_key["btrfs"]["status"] == "new"
    assert by_key["btrfs"]["expected"] == "not loaded"
    assert by_key["btrfs"]["actual"] == "loaded in sandbox"

    assert by_key["kvm"]["status"] == "removed"
    assert by_key["kvm"]["expected"] == "loaded"
    assert by_key["kvm"]["actual"] == "not loaded in sandbox"

    # sorted alphabetically
    assert [row["key"] for row in rows] == ["btrfs", "kvm"]
    # modules come first in the aggregate
    assert all(row["type"] == "module" for row in rows)


def test_build_param_diff_computes_status_from_values():
    recs = [
        {
            "field_name": "fs.suid_dumpable",
            "expected_value": "0",
            "actual_value": "2",
            "description": "suid_dumpable should be 0",
        },
        {
            "field_name": "kernel.unprivileged_bpf_disabled",
            "expected_value": "1",
            "actual_value": "",
            "description": "param not set",
        },
        {
            "field_name": "fs.protected_hardlinks",
            "expected_value": "1",
            "actual_value": "1",
        },
        {
            "field_name": "kernel.perf_event_paranoid",
            "expected_value": "2|3|4",
            "actual_value": "3",
        },
    ]
    rows = {row["key"]: row for row in build_param_diff(recs)}
    assert set(rows) >= {
        "fs.suid_dumpable",
        "kernel.unprivileged_bpf_disabled",
        "fs.protected_hardlinks",
        "kernel.perf_event_paranoid",
    }
    assert rows["fs.suid_dumpable"]["status"] == "mismatch"
    assert rows["kernel.unprivileged_bpf_disabled"]["status"] == "missing"
    assert rows["fs.protected_hardlinks"]["status"] == "ok"
    # pipe-delimited recommended is an "allowed set": 3 matches
    assert rows["kernel.perf_event_paranoid"]["status"] == "ok"


def test_build_param_diff_marks_absent_actual():
    rows = build_param_diff(
        [{"field_name": "kernel.yama", "expected_value": "1", "actual_value": ""}]
    )
    assert rows[0]["actual"] == "(not present)"
    assert rows[0]["status"] == "missing"

_HOST_WITH_CAPS = {
    "file_capabilities": [
        {
            "path": "/usr/bin/ping",
            "owner_name": "root",
            "cap_effective": "cap_net_raw",
            "cap_permitted": "cap_net_raw",
        },
        {
            "path": "/usr/bin/thing",
            "owner_name": "root",
            "cap_effective": "cap_sys_admin",
            "cap_permitted": "cap_sys_admin",
        },
        {
            "path": "/usr/bin/plain",
            "owner_name": "root",
            "cap_effective": None,
            "cap_permitted": None,
        },
    ],
    "process_capabilities": [
        {
            "pid": 1,
            "process_name": "systemd",
            "username": "root",
            "cap_effective": "0x00000000",
        },
        {
            "pid": 42,
            "process_name": "agent",
            "username": "bob",
            # bit 21 = cap_sys_admin
            "cap_effective": "0x00200000",
        },
    ],
}


def test_build_caps_diff_from_host_snapshot():
    rows = {row["key"]: row for row in build_caps_diff(_HOST_WITH_CAPS)}
    assert set(rows) == {"/usr/bin/ping", "/usr/bin/thing", "agent/42"}
    assert "/usr/bin/plain" not in rows
    assert rows["/usr/bin/ping"]["expected"] == "none"
    assert rows["/usr/bin/ping"]["actual"] == "cap_net_raw"
    assert rows["/usr/bin/ping"]["status"] == "WARNING"
    assert rows["/usr/bin/thing"]["status"] == "FAIL"
    assert rows["agent/42"]["status"] == "FAIL"
    assert all(r["type"] == "capability" for r in rows.values())


def test_build_selinux_diff_from_host_snapshot():
    host_info = {
        "selinux_booleans": [
            {"boolean_name": "httpd_can_network_connect", "value": False},
            {"boolean_name": "deny_execmem", "value": True},
            {"boolean_name": "httpd_execmem", "value": True},
        ]
    }
    params = {
        "cant_connect": {
            "booleans": [
                {"name": "httpd_can_network_connect", "state": "off"},
                {"name": "zzz_ignored", "state": "off"},
            ]
        },
        "deny_execmem": {
            "booleans": [
                {"name": "deny_execmem", "state": "on"},
                {"name": "httpd_execmem", "state": "off"},
                {"name": "selinuxuser_execheap", "state": "off"},
            ]
        },
    }
    rows = {row["key"]: row for row in build_selinux_diff(host_info, params)}
    assert set(rows) == {
        "httpd_can_network_connect",
        "zzz_ignored",
        "deny_execmem",
        "httpd_execmem",
        "selinuxuser_execheap",
    }
    assert rows["httpd_can_network_connect"]["status"] == "ok"
    assert rows["zzz_ignored"]["status"] == "ok"
    assert rows["deny_execmem"]["status"] == "ok"
    assert rows["httpd_execmem"]["status"] == "WARNING"
    assert rows["selinuxuser_execheap"]["status"] == "ok"


def test_build_diff_sorts_by_section_then_severity_then_key():
    rows = build_diff(
        sandbox_modules={"aaa_extra"},
        host_modules=set(),
        kernel_recs=[{"field_name": "fs.suid_dumpable", "expected_value": "0",
                      "actual_value": "2"}],
        host_info={
            "file_capabilities": [
                {"path": "capbin", "cap_effective": "cap_sys_admin",
                 "cap_permitted": "cap_sys_admin"}
            ],
            "process_capabilities": [],
            "selinux_booleans": [
                {"boolean_name": "zsel", "value": True}
            ],
        },
        selinux_params={
            "s": {"booleans": [{"name": "zsel", "state": "off"}]},
        },
    )
    types = [row["type"] for row in rows]
    # modules first, then params, capabilities, selinux
    assert types == ["module", "param", "capability", "selinux"]


def test_build_diff_tolerates_none():
    rows = build_diff(None, None, [])
    assert rows == []


def _sample_diff_rows():
    return build_diff(
        sandbox_modules={"btrfs", "ext4"},
        host_modules={"ext4", "kvm"},
        kernel_recs=[
            {
                "field_name": "fs.suid_dumpable",
                "expected_value": "0",
                "actual_value": "2",
            }
        ],
        host_info={
            "file_capabilities": [
                {"path": "capbin", "cap_effective": "cap_sys_admin",
                 "cap_permitted": "cap_sys_admin"}
            ],
            "process_capabilities": [],
            "selinux_booleans": [
                {"boolean_name": "bool1", "value": True}
            ],
        },
        selinux_params={
            "s": {"booleans": [{"name": "bool1", "state": "off"}]},
        },
    )


def test_build_diff_columns_groups_into_sections():
    sections = build_diff_columns(_sample_diff_rows())
    assert set(sections) == {"module", "param", "capability", "selinux"}
    assert sections["param"]["layout"] == "two"


def test_build_diff_columns_module_added_removed():
    module = build_diff_columns(_sample_diff_rows())["module"]
    assert module["layout"] == "module"
    groups = {g["title"]: set(g["items"]) for g in module["groups"]}
    assert groups["module loaded by the sandbox run but missing on the host"] == {
        "btrfs"
    }
    assert groups[
        "module present on the host but not loaded in the sandbox"
    ] == {"kvm"}
    assert {r["status"] for r in module["rows"]} == {"new"}


def test_build_diff_columns_param_two_columns():
    param = build_diff_columns(_sample_diff_rows())["param"]
    row = param["rows"][0]
    assert row["key"] == "fs.suid_dumpable"
    assert row["left"] == "0"
    assert row["right"] == "2"
    assert row["changed"] is True


def test_build_diff_columns_hunk_consistent_sort():
    param = build_diff_columns(_sample_diff_rows())["param"]
    assert [r["key"] for r in param["rows"]] == ["fs.suid_dumpable"]


def test_build_diff_columns_module_uses_group_layout():
    section = build_diff_columns(_sample_diff_rows())["module"]
    assert section["layout"] == "module"
    assert "headers" not in section


def test_build_two_column_marks_difference_and_keeps_status():
    items = [
        {
            "key": "KRNL-6000",
            "expected": "0",
            "actual": "2",
            "status": "mismatch",
        },
        {
            "key": "KRNL-6001",
            "expected": "1",
            "actual": "1",
            "status": "ok",
        },
    ]
    table = build_two_column(items, ("Recommended", "Current"))
    assert table["headers"] == ("Recommended", "Current")
    assert table["rows"][0]["changed"] is True
    assert table["rows"][1]["changed"] is False
    assert table["rows"][0]["status"] == "mismatch"


def test_build_two_column_defaults_key_and_empty_actual():
    table = build_two_column(
        [{"expected": "1", "actual": ""}], ("Recommended", "Current")
    )
    row = table["rows"][0]
    assert row["key"] == "?"
    assert row["left"] == "1"
    assert row["right"] == ""
    assert row["changed"] is True


def test_host_info_data_to_dict_serializes_children_and_dates():
    now = datetime.now(UTC)
    host = HostInfoData(
        captured_at=now,
        kernel_modules=[HostKernelModule(module_name="ext4", size=4096)],
        kernel_parameters=[
            HostKernelParameter(parameter_name="fs.suid_dumpable", parameter_value="0")
        ],
    )
    as_dict = host.to_dict()
    assert as_dict["captured_at"] == now.isoformat()
    assert as_dict["kernel_modules"] == [
        {"module_name": "ext4", "size": 4096, "refcount": None,
         "used_by": None, "state": None, "address": None}
    ]
    assert as_dict["kernel_parameters"][0]["parameter_name"] == "fs.suid_dumpable"


def test_count_findings_ignores_ok_rows():
    rows = [
        {"status": "mismatch"},
        {"status": "WARNING"},
        {"status": "ok"},
        {"status": "FAIL"},
        {"status": ""},
    ]
    assert count_findings(rows) == 3


def test_param_diff_carries_deduplicable_link():
    recs = [
        {
            "field_name": "fs.suid_dumpable",
            "expected_value": "0",
            "actual_value": "2",
            "description": "restrict core dumps",
            "raw_data": {"solution": "https://kernel.org/doc/fs.txt"},
        },
        {
            "field_name": "kernel.dmesg_restrict",
            "expected_value": "1",
            "actual_value": "1",
            "raw_data": {"details": "https://kernel.org/doc/kernel.txt"},
        },
        {
            "field_name": "no.link",
            "expected_value": "1",
            "actual_value": "0",
            "raw_data": {"solution": "text:see docs"},
        },
    ]
    rows = {row["key"]: row for row in build_param_diff(recs)}
    assert rows["fs.suid_dumpable"]["link"] == "https://kernel.org/doc/fs.txt"
    assert rows["kernel.dmesg_restrict"]["link"] == "https://kernel.org/doc/kernel.txt"
    assert rows["no.link"]["link"] == ""


def test_diff_columns_capability_table_and_references():
    sections = build_diff_columns(_sample_diff_rows())
    cap = sections["capability"]
    assert cap["layout"] == "capability"
    row = cap["rows"][0]
    assert row["key"].startswith("cap_sys_admin")
    assert row["status"] == "fail"
    assert row["left"] == "1"
    refs = cap["references"]
    assert any(r["what"] == "CAP_SYS_ADMIN" for r in refs)
    assert all("man.archlinux" in r["how"] for r in refs)
    assert all("hacktricks" in r["why"] for r in refs)


def test_cap_references_only_link_hacktricks_for_escalating_caps():
    from report.diff import _cap_reference_rows

    rows = _cap_reference_rows(
        ["cap_net_raw", "cap_sys_admin", "cap_setuid", "cap_checkpoint_restore"]
    )
    by_what = {r["what"]: r for r in rows}
    doc = by_what["CAP_SYS_ADMIN"]
    assert doc["escalates"] is True
    assert "hacktricks" in doc["why"]
    assert by_what["CAP_SETUID"]["escalates"] is True
    net = by_what["CAP_NET_RAW"]
    # documented on the page + has a why link, but cannot escalate directly
    assert net["escalates"] is False
    assert "hacktricks" in net["why"]
    # genuinely undocumented on the page -> no why link
    assert by_what["CAP_CHECKPOINT_RESTORE"]["why"] == ""
    assert by_what["CAP_CHECKPOINT_RESTORE"]["escalates"] is False
    # escalating capabilities sort first (a contiguous block, before the rest)
    esculating = [r for r in rows if r["escalates"]]
    others = [r for r in rows if not r["escalates"]]
    assert rows == esculating + others
    assert rows[0]["escalates"] is True


def test_capability_rows_omit_plus_more_truncation():
    from report.diff import _build_capability_section

    many = ",".join(f"cap_c{i}" for i in range(50))
    section = _build_capability_section(
        [{"actual": many, "status": "warning", "key": "x", "detail": ""}]
    )
    row = section["rows"][0]
    assert "+50 more" not in row["key"]
    assert "…" not in row["key"]
    assert len(row["key"].split(",")) == 50
    assert row["escalates"] is False


def test_build_capability_section_collapses_same_process_different_pids():
    from report.diff import _build_capability_section

    rows = [
        {
            "actual": "cap_net_raw",
            "status": "warning",
            "key": "foo/1024",
            "detail": "process capabilities (owner: bob)",
        },
        {
            "actual": "cap_net_raw",
            "status": "warning",
            "key": "foo/2048",
            "detail": "process capabilities (owner: bob)",
        },
        {
            "actual": "cap_net_raw,cap_chown",
            "status": "fail",
            "key": "/usr/bin/ping",
            "detail": "file capabilities (owner: root)",
        },
    ]
    section = _build_capability_section(rows)
    assert len(section["rows"]) == 2
    by_key = {g["key"]: g for g in section["rows"]}
    net_raw = by_key["cap_net_raw"]
    assert net_raw["left"] == "1"
    assert "foo (pids: 1024, 2048)" in net_raw["detail"]
    assert net_raw["status"] == "warning"
    mixed = by_key["cap_net_raw, cap_chown"]
    assert mixed["status"] == "fail"
    assert "/usr/bin/ping (owner: root)" in mixed["detail"]
    whats = {r["what"] for r in section["references"]}
    assert whats == {"CAP_NET_RAW", "CAP_CHOWN"}


def test_base_proc_name_strips_numeric_thread_suffix():
    from report.diff import _base_proc_name

    assert _base_proc_name("cpuhp/0") == "cpuhp"
    assert _base_proc_name("cpuhp/11") == "cpuhp"
    assert _base_proc_name("idle_inject/3") == "idle_inject"
    assert _base_proc_name("card1-crtc3") == "card1-crtc"


def test_holder_lines_collapse_threads_by_base_name(monkeypatch):
    from report.diff import _holder_lines_from_procs

    monkeypatch.setattr(term, "_unicode_supported", True)
    lines = _holder_lines_from_procs(
        {
            "cpuhp/0": ["22"],
            "cpuhp/1": ["23"],
            "cpuhp/10": ["77"],
            "sshd": ["1697"],
        }
    )
    assert "cpuhp/… (pids: 22, 23, 77)" in lines
    assert "sshd (pid: 1697)" in lines


def test_holder_lines_ascii_fallback_on_pure_tty(monkeypatch):
    from report.diff import _holder_lines_from_procs

    monkeypatch.setattr(term, "_unicode_supported", False)
    lines = _holder_lines_from_procs(
        {
            "cpuhp/0": ["22"],
            "cpuhp/1": ["23"],
            "cpuhp/10": ["77"],
            "sshd": ["1697"],
        }
    )
    assert "cpuhp/... (pids: 22, 23, 77)" in lines
    assert all(c.isascii() for c in "".join(lines))


def test_diff_columns_param_preserves_link_and_detail():
    diff = build_diff(
        sandbox_modules=set(),
        host_modules=set(),
        kernel_recs=[
            {
                "field_name": "fs.suid_dumpable",
                "expected_value": "0",
                "actual_value": "2",
                "description": "restrict core dumps",
                "raw_data": {"solution": "https://kernel.org/doc/fs.txt"},
            }
        ],
        host_info=None,
    )
    param = build_diff_columns(diff)["param"]
    row = param["rows"][0]
    assert row["link"] == "https://kernel.org/doc/fs.txt"
    assert row["detail"] == "restrict core dumps"


def test_host_module_names_sorted_dedup():
    host = {"kernel_modules": [{"module_name": "btrfs"}, {"module_name": "ext4"}]}
    assert host_module_names(host) == ["btrfs", "ext4"]
    assert host_module_names(None) == []


def test_host_module_names_skips_empty_and_non_str():
    host = {"kernel_modules": [{"module_name": ""}, {"module_name": "x"}, None]}
    assert host_module_names(host) == ["x"]


def test_host_param_map_from_dict_and_dataclass():
    from schemas import HostInfoData, HostKernelParameter

    host_dict = {
        "kernel_parameters": [
            {"parameter_name": "fs.suid_dumpable", "parameter_value": "0"},
            {"parameter_name": "kernel.yama", "parameter_value": ""},
        ]
    }
    host_data = HostInfoData(
        kernel_parameters=[
            HostKernelParameter(parameter_name="fs.suid_dumpable", parameter_value="0")
        ]
    )
    assert host_param_map(host_dict) == {
        "fs.suid_dumpable": "0",
        "kernel.yama": "",
    }
    assert host_param_map(host_data) == {"fs.suid_dumpable": "0"}
    assert host_param_map(None) == {}


def test_host_param_map_skips_unnamed_params():
    host = {
        "kernel_parameters": [
            {"parameter_name": "", "parameter_value": "0"},
            {"parameter_value": "x"},
        ]
    }
    assert host_param_map(host) == {}


def test_host_selinux_map_from_dict_and_dataclass():
    from schemas import HostInfoData, HostSELinuxBoolean

    host_dict = {"selinux_booleans": [{"boolean_name": "a", "value": True}]}
    host_data = HostInfoData(
        selinux_booleans=[HostSELinuxBoolean(boolean_name="b", value=False)]
    )
    assert host_selinux_map(host_dict) == {"a": True}
    assert host_selinux_map(host_data) == {"b": False}
    assert host_selinux_map(None) == {}


def test_host_selinux_map_skips_unnamed_booleans():
    host = {"selinux_booleans": [{"boolean_name": ""}, {"value": True}]}
    assert host_selinux_map(host) == {}


def test_load_selinux_params_missing_file_returns_empty(tmp_path):
    assert load_selinux_params(str(tmp_path / "missing.json")) == {}


def test_load_selinux_params_invalid_json_returns_empty(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("not json")
    assert load_selinux_params(str(path)) == {}


def test_load_selinux_params_non_dict_json_returns_empty(tmp_path):
    path = tmp_path / "list.json"
    path.write_text("[1, 2, 3]")
    assert load_selinux_params(str(path)) == {}


def test_build_selinux_diff_skips_non_dict_sections():
    rows = build_selinux_diff(None, {"s1": "not-a-dict", "s2": {"booleans": []}})
    assert rows == []


def test_build_selinux_diff_skips_missing_names():
    params = {"s1": {"booleans": [{"state": "on"}, {"name": "", "state": "off"}]}}
    rows = build_selinux_diff({}, params)
    assert rows == []


def test_build_selinux_diff_fail_when_expected_on_but_off():
    params = {"s1": {"booleans": [{"name": "bool_x", "state": "on"}]}}
    rows = {r["key"]: r for r in build_selinux_diff({}, params)}
    assert rows["bool_x"]["status"] == "FAIL"
    assert rows["bool_x"]["expected"] == "on"
    assert rows["bool_x"]["actual"] == "off"


def test_build_caps_diff_without_host_uses_records():
    recs = [
        {
            "field_name": "KRNL-6000",
            "expected_value": "0",
            "actual_value": "2",
            "status": "FAIL",
            "description": "file caps",
        },
        {
            "field_name": "KRNL-6001",
            "expected_value": "0",
            "actual_value": "1",
            "status": "ok",
            "description": "satisfied",
        },
    ]
    rows = build_caps_diff(None, cap_recs=recs)
    assert len(rows) == 1
    assert rows[0]["key"] == "KRNL-6000"
    assert rows[0]["status"] == "FAIL"


def test_build_hardening_diff_filters_non_findings():
    recs = [
        {"status": "FAIL", "field_name": "a"},
        {"status": "warning", "field_name": "b"},
        {"status": "ok", "field_name": "c"},
        {"status": "", "field_name": "d"},
        {"status": "FAIL"},  # no key -> "?"
    ]
    rows = {r["key"]: r for r in build_hardening_diff(recs, "selinux")}
    assert set(rows) == {"a", "b", "?"}
    assert all(r["type"] == "selinux" for r in rows.values())
    assert rows["?"]["expected"] == ""
    assert rows["a"]["status"] == "FAIL"


def test_build_capability_section_wrapper():
    from report.diff import build_capability_section

    rows = [{"actual": "cap_net_raw", "status": "warning", "key": "x", "detail": ""}]
    section = build_capability_section(rows)
    assert section["rows"][0]["key"] == "cap_net_raw"


def test_build_capability_section_proc_without_name_key_skipped():
    from report.diff import _build_capability_section

    rows = [
        {
            "actual": "cap_net_raw",
            "status": "warning",
            "key": "/",  # rpartition produces empty name
            "detail": "process capabilities (owner: root)",
        }
    ]
    section = _build_capability_section(rows)
    # the "/" key has an empty name -> holder dropped but group still present
    assert len(section["rows"]) == 1
    assert section["rows"][0]["count"] == 0


def test_capability_group_fail_keeps_fail_when_mixed_statuses():
    from report.diff import _build_capability_section

    rows = [
        {
            "actual": "cap_sys_admin",
            "status": "fail",
            "key": "/usr/bin/thing",
            "detail": "file capabilities (owner: root)",
        },
        {
            "actual": "cap_sys_admin",
            "status": "warning",
            "key": "agent/42",
            "detail": "process capabilities (owner: bob)",
        },
    ]
    section = _build_capability_section(rows)
    assert len(section["rows"]) == 1
    assert section["rows"][0]["status"] == "fail"
    assert section["rows"][0]["key"] == "cap_sys_admin"
    assert "agent" in section["rows"][0]["detail"]
    assert "/usr/bin/thing" in section["rows"][0]["detail"]


def test_diff_columns_module_sandbox_only_group():
    rows = build_module_diff({"btrfs"}, set())
    sections = build_diff_columns(rows)
    module = sections["module"]
    assert len(module["groups"]) == 1
    assert module["groups"][0]["title"].startswith("module loaded")
    assert module["groups"][0]["items"] == ["btrfs"]


def test_diff_columns_module_host_only_group():
    rows = build_module_diff(set(), {"kvm"})
    sections = build_diff_columns(rows)
    module = sections["module"]
    assert len(module["groups"]) == 1
    assert module["groups"][0]["title"].startswith("module present")
    assert module["groups"][0]["items"] == ["kvm"]


def test_collect_sandbox_modules_from_vulnerability_runs():
    data = {
        "vulnerabilities": [
            {"sandbox_runs": [{"modules": ["  "]}], "sandbox_runs2": []},
            {"sandbox_runs": [{"modules": ["nft_chain_nat"]}]},
        ]
    }
    assert collect_sandbox_modules(data) == {"nft_chain_nat"}
