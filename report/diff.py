"""Diff builder for kernel vulnerability reports.

Produce a unified, sorted list of divergences between the host and hardening checks (kernel params,
capabilities and SELinux) as recommended-vs-current rows.
"""

import json
from pathlib import Path
from typing import Any

from core import is_finding, norm_sysctl_value, proc_module_name, safe_get_attr
from recon.parse_recon_reports import HIGH_RISK_CAPS, ParseReports

#: diff section type -> human-readable label (shared by the renderers)
DIFF_SECTIONS: dict[str, str] = {
    "module": "Kernel Modules",
    "param": "Kernel Parameters",
    "capability": "Capabilities",
    "selinux": "SELinux Hardening",
}

#: diff section ordering (module -> param -> capability -> selinux)
_SECTION_ORDER = {
    "module": 0,
    "param": 1,
    "capability": 2,
    "selinux": 3,
}

#: per-status sort weight (lower = more severe, shown first)
_STATUS_RANK = {
    "FAIL": 0,
    "new": 0,
    "mismatch": 1,
    "WARNING": 2,
    "missing": 3,
    "removed": 4,
    "ok": 5,
}

def _comparison_status(expected: str, actual: str) -> str:
    """Return ok/mismatch/missing for a recommended-vs-current comparison.
    pipe-delimited recommended value (e.g. 2|3|4) is treated as an allowed
    set matching any one of the alternatives is ok.
    """
    exp = str(expected or "").strip()
    act = str(actual or "").strip()
    if act in ("", "(not present)", "none", "unknown"):
        return "missing" if exp else "ok"
    actual_norm = norm_sysctl_value(act)
    if "|" in exp:
        allowed = [norm_sysctl_value(p) for p in exp.split("|") if p.strip()]
        return "ok" if actual_norm in allowed else "mismatch"
    return "ok" if norm_sysctl_value(exp) == actual_norm else "mismatch"


def collect_sandbox_modules(data: dict[str, Any]) -> set[str]:
    """Union of every kernel module name observed inside sandbox runs."""
    modules: set[str] = set()
    for run in data.get("runs", []) or []:
        for entry in run.get("modules", []) or []:
            name = proc_module_name(entry)
            if name:
                modules.add(name)
    for vuln in data.get("vulnerabilities", []) or []:
        for run in vuln.get("sandbox_runs", []) or []:
            for entry in run.get("modules", []) or []:
                name = proc_module_name(entry)
                if name:
                    modules.add(name)
    return modules


def host_module_set(host_info: Any) -> set[str]:
    """Set of module names from a host info snapshot"""
    modules = host_info.get("kernel_modules", []) if isinstance(host_info, dict) else (
        getattr(host_info, "kernel_modules", []) or []
    )
    result: set[str] = set()
    for mod in modules or []:
        name = safe_get_attr(mod, "module_name")
        if name:
            result.add(str(name))
    return result


def host_module_names(host_info: Any) -> list[str]:
    return sorted(host_module_set(host_info))


def host_param_map(host_info: Any) -> dict[str, str]:
    """Map kernel parameter name -> value from a host info snapshot."""
    params = host_info.get("kernel_parameters", []) if isinstance(
        host_info, dict
    ) else (getattr(host_info, "kernel_parameters", []) or [])
    result: dict[str, str] = {}
    for param in params or []:
        name = safe_get_attr(param, "parameter_name")
        if name:
            result[str(name)] = str(safe_get_attr(param, "parameter_value", "") or "")
    return result


def build_module_diff(
    sandbox_modules: set[str] | list[str] | None,
    host_modules: set[str] | list[str] | None,
) -> list[dict[str, Any]]:
    """Both-direction kernel module divergence."""
    sandbox = {str(m) for m in (sandbox_modules or set()) if str(m).strip()}
    host = {str(m) for m in (host_modules or set()) if str(m).strip()}

    rows: list[dict[str, Any]] = []
    for name in sorted(sandbox - host):
        rows.append(
            {
                "type": "module",
                "key": name,
                "expected": "not loaded",
                "actual": "loaded in sandbox",
                "status": "new",
                "detail": "module loaded by the sandbox run but missing on the host",
            }
        )
    for name in sorted(host - sandbox):
        rows.append(
            {
                "type": "module",
                "key": name,
                "expected": "loaded",
                "actual": "not loaded in sandbox",
                "status": "removed",
                "detail": "module present on the host but not loaded in the sandbox",
            }
        )
    return rows


def _rec_raw(rec: Any) -> dict[str, Any]:
    raw = safe_get_attr(rec, "raw_data", {}) or {}
    return raw if isinstance(raw, dict) else {}


def _extract_link(rec: Any) -> str:
    raw = _rec_raw(rec)
    for key in ("solution", "details"):
        value = str(raw.get(key, "") or "").strip()
        if value.startswith(("http://", "https://")):
            return value
    return ""


def build_param_diff(
    kernel_recs: list[Any],
    host_info: Any = None,
) -> list[dict[str, Any]]:
    """Kernel parameter recommended-vs-current rows.

    kernel_recs are the stored security recommendations (category kernel)
    from the scan snapshot; each carries expected_value from recon
    and actual_value. Each row carries details and a link when known.
    """
    rows: list[dict[str, Any]] = []
    for rec in kernel_recs or []:
        key = safe_get_attr(rec, "field_name") or safe_get_attr(rec, "test_id") or "?"
        expected = str(safe_get_attr(rec, "expected_value", "") or "")
        actual = str(safe_get_attr(rec, "actual_value", "") or "")
        rows.append(
            {
                "type": "param",
                "key": str(key),
                "expected": expected,
                "actual": actual or "(not present)",
                "status": _comparison_status(expected, actual),
                "detail": str(safe_get_attr(rec, "description", "") or ""),
                "link": _extract_link(rec),
            }
        )
    return rows


def host_selinux_map(host_info: Any) -> dict[str, bool]:
    """Map SELinux boolean name -> current value from a host snapshot."""
    bools = host_info.get("selinux_booleans", []) if isinstance(
        host_info, dict
    ) else (getattr(host_info, "selinux_booleans", []) or [])
    result: dict[str, bool] = {}
    for b in bools or []:
        name = safe_get_attr(b, "boolean_name")
        if name:
            result[str(name)] = bool(safe_get_attr(b, "value", False))
    return result


def _load_json_cfg(path: str | Path) -> dict[str, Any]:
    try:
        with Path(path).open("r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except FileNotFoundError, OSError, ValueError:
        return {}


def load_selinux_params(path: str | Path = "recon/selinux_params.json") -> dict[str, Any]:
    return _load_json_cfg(path) # config taken from RedHat hardening playbooks


def build_selinux_diff(
    host_info: Any = None,
    selinux_params: dict[str, Any] | None = None,
    params_path: str | Path = "recon/selinux_params.json",
) -> list[dict[str, Any]]:
    """SELinux boolean hardening: recommended (selinux_params.json) vs current"""
    current = host_selinux_map(host_info)
    params = selinux_params if selinux_params is not None else _load_json_cfg(
        params_path
    )
    rows: list[dict[str, Any]] = []
    for section in (params or {}).values():
        if not isinstance(section, dict):
            continue
        for item in section.get("booleans", []) or []:
            name = item.get("name")
            if not name:
                continue
            expected_on = item.get("state", "off") == "on"
            expected = "on" if expected_on else "off"
            actual_on = bool(current.get(str(name), False))
            actual = "on" if actual_on else "off"
            if actual_on == expected_on:
                status = "ok"
            elif expected_on and not actual_on:
                status = "FAIL"
            else:
                status = "WARNING"
            rows.append(
                {
                    "type": "selinux",
                    "key": str(name),
                    "expected": expected,
                    "actual": actual,
                    "status": status,
                    "detail": str(item.get("comment", "") or ""),
                }
            )
    return rows


def _host_file_caps(host_info: Any) -> list[dict[str, Any]]:
    entry = host_info.get("file_capabilities", []) if isinstance(
        host_info, dict
    ) else (getattr(host_info, "file_capabilities", []) or [])
    return list(entry or [])


def _host_proc_caps(host_info: Any) -> list[dict[str, Any]]:
    entry = host_info.get("process_capabilities", []) if isinstance(
        host_info, dict
    ) else (getattr(host_info, "process_capabilities", []) or [])
    return list(entry or [])


def _cap_status(names: list[str]) -> str:
    """Any capability is a hardening finding; high-risk caps escalate to FAIL."""
    if any(cap in HIGH_RISK_CAPS for cap in names):
        return "FAIL"
    return "WARNING" if names else "ok"


def build_caps_diff(
    host_info: Any = None,
    cap_recs: list[Any] | None = None,
) -> list[dict[str, Any]]:
    """Capability findings derived from the stored host snapshot.

    Recommended is always "none"; the current value lists every capability a
    file-backed executable or a process holds. Files decode comma-joined cap
    names, processes decode the effective cap mask. High-risk caps (see
    HIGH_RISK_CAPS) are FAILs, the rest are WARNINGs, only for report.
    """
    if host_info is not None:
        rows: list[dict[str, Any]] = []
        for fc in _host_file_caps(host_info):
            names = sorted(
                {c for c in (safe_get_attr(fc, "cap_effective") or "").split(",") if c}
                | {c for c in (safe_get_attr(fc, "cap_permitted") or "").split(",") if c}
            )
            if not names:
                continue
            rows.append(
                {
                    "type": "capability",
                    "key": str(safe_get_attr(fc, "path") or "?"),
                    "expected": "none",
                    "actual": ",".join(names),
                    "status": _cap_status(names),
                    "detail": f"file capabilities (owner: {safe_get_attr(fc, 'owner_name') or '?'})",
                }
            )
        for pc in _host_proc_caps(host_info):
            names = ParseReports.cap_names_from_mask(
                str(safe_get_attr(pc, "cap_effective") or "")
            )
            if not names:
                continue
            label = f"{safe_get_attr(pc, 'process_name') or '?'}/{safe_get_attr(pc, 'pid') or '?'}"
            rows.append(
                {
                    "type": "capability",
                    "key": str(label),
                    "expected": "none",
                    "actual": ",".join(names),
                    "status": _cap_status(names),
                    "detail": f"process capabilities (owner: {safe_get_attr(pc, 'username') or '?'})",
                }
            )
        return rows
    return build_hardening_diff(cap_recs or [], "capability")


def build_hardening_diff(recs: list[Any], diff_type: str) -> list[dict[str, Any]]:
    """FAIL/WARNING hardening divergences (capabilities / SELinux)."""
    rows: list[dict[str, Any]] = []
    for rec in recs or []:
        status = str(safe_get_attr(rec, "status", "")).upper()
        if status not in ("FAIL", "WARNING"):
            continue
        key = safe_get_attr(rec, "field_name") or safe_get_attr(rec, "test_id") or "?"
        rows.append(
            {
                "type": diff_type,
                "key": str(key),
                "expected": str(safe_get_attr(rec, "expected_value", "") or ""),
                "actual": str(safe_get_attr(rec, "actual_value", "") or ""),
                "status": status,
                "detail": str(safe_get_attr(rec, "description", "") or ""),
            }
        )
    return rows


def _sort_key(row: dict[str, Any]) -> tuple[int, int, str]:
    return (
        _SECTION_ORDER.get(row.get("type", ""), 9),
        _STATUS_RANK.get(str(row.get("status", "")), 9),
        str(row.get("key", "")).lower(),
    )


def build_diff(
    sandbox_modules: set[str] | list[str] | None,
    host_modules: set[str] | list[str] | None,
    kernel_recs: list[Any],
    host_info: Any = None,
    selinux_params: dict[str, Any] | None = None,
    selinux_recs: list[Any] | None = None,
) -> list[dict[str, Any]]:
    """Aggregate all diff rows, sorted by (section, severity, key)."""
    # if host_info is given, capabilities come from it
    cap_rows = build_caps_diff(host_info) if host_info is not None else []
    selinux_rows = build_selinux_diff(
        host_info=host_info,
        selinux_params=selinux_params,
    ) if host_info is not None else []

    rows = build_module_diff(sandbox_modules, host_modules)
    rows += build_param_diff(kernel_recs)
    rows += cap_rows
    rows += selinux_rows
    return sorted(rows, key=_sort_key)


def build_two_column(
    items: list[dict[str, Any]],
    headers: tuple[str, str],
) -> dict[str, Any]:
    """Build a two-column comparison table model.

    items is a list of dicts each carrying key (or test_id),
    expected and actual. Returns {"headers", "rows"} where every
    row is {"key", "left", "right", "changed", "status"} and changed
    is True when the two values differ renderers highlight those rows.
    """
    rows = []
    for item in items:
        left = str(item.get("expected") or "")
        right = str(item.get("actual") or "")
        rows.append(
            {
                "key": str(item.get("key") or item.get("test_id") or "?"),
                "left": left,
                "right": right,
                "changed": left != right,
                "status": str(item.get("status", "")).lower(),
            }
        )
    return {"headers": headers, "rows": rows}


_CAP_MAN_URL = "https://man.archlinux.org/man/capabilities.7#{cap}"
_CAP_HACKTRICKS_URL = (
    "https://angelica.gitbook.io/hacktricks/linux-hardening/"
    "privilege-escalation/linux-capabilities#{cap}"
)


# Capabilities that have their own dedicated section on the HackTricks mirror
# linux-capabilities page. Every one of these gets a "why it is dangerous"
HACKTRICKS_DOCUMENTED_CAPS: frozenset[str] = frozenset(
    {
        "cap_chown",
        "cap_dac_override",
        "cap_dac_read_search",
        "cap_fowner",
        "cap_kill",
        "cap_linux_immutable",
        "cap_mknod",
        "cap_net_admin",
        "cap_net_bind_service",
        "cap_net_raw",
        "cap_setfcap",
        "cap_setgid",
        "cap_setuid",
        "cap_setpcap",
        "cap_sys_admin",
        "cap_sys_boot",
        "cap_sys_chroot",
        "cap_sys_module",
        "cap_sys_ptrace",
        "cap_sys_rawio",
        "cap_syslog",
    }
)

# Capabilities for which the HackTricks page documents a concrete, reusable
# privilege-escalation / container-escape technique (an actual exploitation
# path) to sort the most dangerous findings first.
HACKTRACKS_LPE_CAPS: frozenset[str] = frozenset(
    {
        "cap_chown",
        "cap_dac_override",
        "cap_dac_read_search",
        "cap_fowner",
        "cap_kill",
        "cap_mknod",
        "cap_setfcap",
        "cap_setgid",
        "cap_setuid",
        "cap_sys_admin",
        "cap_sys_chroot",
        "cap_sys_module",
        "cap_sys_ptrace",
        "cap_sys_rawio",
    }
)


def _cap_escalates(cap: str) -> bool:
    """Whether HackTricks documents a direct LPE technique for cap."""
    return str(cap or "").strip().lower() in HACKTRACKS_LPE_CAPS


def _cap_documented(cap: str) -> bool:
    """Whether the HackTricks page has a dedicated section for cap."""
    return str(cap or "").strip().lower() in HACKTRICKS_DOCUMENTED_CAPS


def _cap_reference_rows(names: list[str]) -> list[dict[str, dict]]:
    """Per-capability reference rows {"what", "how", "why", "escalates"}"""
    rows = []
    for name in sorted({str(n).lower() for n in names or []}, reverse=True):
        escalates = _cap_escalates(name)
        rows.append(
            {
                "what": name.upper(),
                "how": _CAP_MAN_URL.format(cap=name.upper()),
                "why": (
                    _CAP_HACKTRICKS_URL.format(cap=name.lower())
                    if _cap_documented(name)
                    else ""
                ),
                "escalates": escalates,
            }
        )
    rows.sort(key=lambda r: (not r["escalates"], r["what"]))
    return rows


_CAP_REF_LABELS = {"how": "MAN / capabilities.7", "why": "Hacktricks"}


def _cap_display(caps: list[str]) -> str:
    """Full capability list a security report must show all of it."""
    return ", ".join(str(c) for c in caps)


def _cap_holder_label(path: str, owner: str) -> str:
    return f"{path} (owner: {owner})" if owner else str(path)


def _sort_pids(pids: list[str]) -> list[str]:
    """Numeric sort of pid strings."""
    return sorted(set(pids), key=lambda p: (len(p), p))


def _process_label(name: str, pids: list[str]) -> str:
    if len(pids) == 1:
        return f"{name} (pid: {pids[0]})"
    joined = ", ".join(pids)
    return f"{name} (pids: {joined})"


def _base_proc_name(name: str) -> str:
    """Strip a trailing numeric thread/index suffix for grouping"""
    stripped = name.rstrip("0123456789/")
    return stripped if stripped else name


def _holder_lines_from_procs(procs: dict[str, list[str]]) -> list[str]:
    """Collapse process holders into lines, merging same-base names.

    Threads like cpuhp/0 ... cpuhp/11 that differ only by a numeric
    index are reported once as cpuhp/… with all their pids together.
    """
    lines: list[str] = []
    base_groups: dict[str, list[str]] = {}
    for name in sorted(procs):
        base_groups.setdefault(_base_proc_name(name), []).append(name)
    for base, names in sorted(base_groups.items()):
        pids: list[str] = []
        for n in sorted(names):
            pids += procs[n]
        label = f"{base}/…" if len(names) > 1 else names[0]
        lines.append(_process_label(label, _sort_pids(pids)))
    return lines


def _build_capability_section(
    capability_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    """Collapse capability findings into a readable table model.
    Findings are grouped by their capability set; within each group holders are
    deduplicated by process name (pids merged).
    """
    groups: dict[tuple[str, ...], dict[str, Any]] = {}
    for row in capability_rows:
        caps = tuple(name for name in str(row.get("actual") or "").split(",") if name)
        status = str(row.get("status") or "").lower()
        group = groups.setdefault(
            caps,
            {
                "caps": list(caps),
                "status": "ok",
                "files": [],
                "procs": {},
                "count": 0,
            },
        )
        if status == "fail":
            group["status"] = "fail"
        elif group["status"] != "fail":
            group["status"] = "warning"
        group["count"] += 1

        detail = str(row.get("detail") or "")
        if "process capabilities" in detail:
            name, _, pid = str(row.get("key") or "").rpartition("/")
            if not name:
                continue
            group["procs"].setdefault(name, []).append(pid)
        else:
            owner = ""
            if "owner:" in detail:
                owner = detail.split("owner:", 1)[1].strip().rstrip(")")
            group["files"].append(_cap_holder_label(str(row.get("key") or "?"), owner))

    rows: list[dict[str, Any]] = []
    for caps, group in groups.items():
        seen_files: set[str] = set()
        unique_files = [f for f in group["files"] if not (f in seen_files or seen_files.add(f))]
        holder_lines: list[str] = list(unique_files)
        holder_lines += _holder_lines_from_procs(group["procs"])
        holder_count = len(unique_files) + len(
            {_base_proc_name(name) for name in group["procs"]}
        )
        escalates = any(_cap_escalates(cap) for cap in caps)
        rows.append(
            {
                "key": _cap_display(list(caps)),
                "left": str(holder_count),
                "right": ",".join(caps),
                "changed": True,
                "status": group["status"],
                "count": holder_count,
                "escalates": escalates,
                "detail": "\n".join(holder_lines) if holder_lines else "",
            }
        )
    rows.sort(
        key=lambda r: (
            not r["escalates"],
            _STATUS_RANK.get(str(r["status"]).upper(), 9),
            -r["count"],
            str(r["key"]).lower(),
        )
    )
    references: list[dict[str, dict]] = []
    seen_what: set[str] = set()
    for caps in groups:
        for ref in _cap_reference_rows(list(caps)):
            current: str = ref["what"]
            if current not in seen_what:
                seen_what.add(current)
                references.append(ref)
    references.sort(key=lambda r: (not r["escalates"], r["what"]))
    return {"rows": rows, "references": references}


def build_capability_section(
    capability_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    return _build_capability_section(capability_rows)


def count_findings(rows: list[dict[str, Any]]) -> int:
    """Count only non-ok rows (findings), never correctly satisfied checks."""
    return sum(1 for r in rows or [] if is_finding(r.get("status")))


def build_diff_columns(
    diff: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Group diff rows into renderable sections.

    Each section yields {"label", "layout", "rows"}. Layouts:
      * "module"      - two grouped module lists (sandbox-only / host-only)
      * "capability"  - collapsed cap-set groups with holders + doc links
      * "two"         - a Recommended vs Current two-column table

    rows always carries every finding row so count_findings and the
    renderers can treat all sections uniformly. Pure python, no ANSI.
    """
    sections: dict[str, dict[str, Any]] = {}
    for kind, label in DIFF_SECTIONS.items():
        rows = [r for r in diff if r.get("type") == kind]
        if not rows:
            continue

        if kind == "module":
            sandbox_only = [
                str(r["key"]) for r in rows if str(r.get("status", "")).lower() == "new"
            ]
            host_only = sorted(
                {str(r["key"]) for r in rows if str(r.get("status", "")).lower() != "new"}
            )
            groups = []
            if sandbox_only:
                groups.append(
                    {
                        "title": "module loaded by the sandbox run but missing on the host",
                        "items": sorted(sandbox_only),
                    }
                )
            if host_only:
                groups.append(
                    {
                        "title": "module present on the host but not loaded in the sandbox",
                        "items": host_only,
                    }
                )
            sections[kind] = {
                "label": label,
                "layout": "module",
                "rows": [r for r in rows if str(r.get("status", "")).lower() == "new"],
                "groups": groups,
            }
        elif kind == "capability":
            built = _build_capability_section(rows)
            sections[kind] = {
                "label": label,
                "layout": "capability",
                "rows": built["rows"],
                "references": built["references"],
            }
        else:
            two_col = build_two_column(rows, ("Recommended", "Current"))
            body = []
            for row, item in zip(rows, two_col["rows"]):
                body.append(
                    {
                        **item,
                        "detail": str(row.get("detail", "") or ""),
                        "link": str(row.get("link", "") or ""),
                    }
                )
            sections[kind] = {
                "label": label,
                "layout": "two",
                "headers": two_col["headers"],
                "rows": body,
            }
    return sections
