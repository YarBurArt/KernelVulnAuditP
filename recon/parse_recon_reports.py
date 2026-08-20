import json
import logging
import os
import pwd
import re
import shutil
import subprocess
from functools import lru_cache
from pathlib import Path
from typing import Any

from application.dto import KernelLPE, LesCVEItem
from config import RECON_TOOL_TIMEOUT_SEC
from core.entities import CVEFinding, GitHubPoC
from core.parsing import (
    CVE_RE,
    extract_cve_ids,
    extract_cvss,
    extract_english_description,
    filter_items_by_date,
)
from lib_tools.peas2json import parse_peass

logger = logging.getLogger(f"kernel_audit.{__name__}")

#: process capability bits (lower 41) → canonical cap_* names
CAPABILITY_NAMES: dict[int, str] = {
    0: "cap_chown",
    1: "cap_dac_override",
    2: "cap_dac_read_search",
    3: "cap_fowner",
    4: "cap_fsetid",
    5: "cap_kill",
    6: "cap_setgid",
    7: "cap_setuid",
    8: "cap_setpcap",
    9: "cap_linux_immutable",
    10: "cap_net_bind_service",
    11: "cap_net_broadcast",
    12: "cap_net_admin",
    13: "cap_net_raw",
    14: "cap_ipc_lock",
    15: "cap_ipc_owner",
    16: "cap_sys_module",
    17: "cap_sys_rawio",
    18: "cap_sys_chroot",
    19: "cap_sys_ptrace",
    20: "cap_sys_pacct",
    21: "cap_sys_admin",
    22: "cap_sys_boot",
    23: "cap_sys_nice",
    24: "cap_sys_resource",
    25: "cap_sys_time",
    26: "cap_sys_tty_config",
    27: "cap_mknod",
    28: "cap_lease",
    29: "cap_audit_write",
    30: "cap_audit_control",
    31: "cap_setfcap",
    32: "cap_mac_override",
    33: "cap_mac_admin",
    34: "cap_syslog",
    35: "cap_wake_alarm",
    36: "cap_block_suspend",
    37: "cap_audit_read",
    38: "cap_perfmon",
    39: "cap_bpf",
    40: "cap_checkpoint_restore",
}

#: capabilities that escalate to root / break domain isolation when effective
HIGH_RISK_CAPS: frozenset[str] = frozenset(
    {
        "cap_sys_admin",
        "cap_sys_module",
        "cap_sys_rawio",
        "cap_sys_ptrace",
        "cap_dac_override",
        "cap_dac_read_search",
        "cap_mac_admin",
        "cap_syslog",
        "cap_perfmon",
        "cap_bpf",
        "cap_sys_boot",
        "cap_ipc_owner",
    }
)


def strip_ansi_sequences(text: str) -> str:
    ansi_pattern = re.compile(r"\x1b\[[0-9;]*m")
    return ansi_pattern.sub("", text)


def parse_key_with_brackets(raw_key: str) -> tuple:
    match = re.fullmatch(r"([^\[]+)(?:\[(.*?)])?", raw_key)
    if not match:
        return raw_key, None
    return match.group(1), match.group(2)


def ensure_list_in_dict(container: dict[str, Any], key: str, value: Any) -> None:
    if key not in container:
        container[key] = [value]
    else:
        if not isinstance(container[key], list):
            container[key] = [container[key]]
        container[key].append(value)


def assign_value_by_key_type(
    results: dict[str, Any], base: str, inner: str | None, value: str
) -> None:
    if inner is None:  # key=value
        if base in results:
            ensure_list_in_dict(results, base, value)
        else:
            results[base] = value
    elif inner == "":  # key[]=value
        ensure_list_in_dict(results, base, value)
    else:  # key[name]=value
        if base not in results:
            results[base] = {}
        if not isinstance(results[base], dict):
            raise ValueError(f"Key '{base}' used as both scalar/list and dict")
        results[base][inner] = value


def parse_key_value_pairs(
    blob: str, separator: str = ";", kv_delim: str = ":"
) -> dict[str, str]:
    result = {}
    for pair in blob.split(separator):
        if kv_delim in pair:
            key, value = pair.split(kv_delim, 1)
            result[key.strip()] = value.strip()
    return result


class ParseReports:
    """
    Normalize audit-tool output (linpeas JSON, LES text, getsebool, getcap,
    /proc) into the typed entities the service layer consumes.
    """

    @staticmethod
    def convert_linpeas_to_dict(output_path: str, json_path: str = "") -> dict:
        res: dict | None = parse_peass(output_path, json_path)
        if res is None:
            logger.debug("lynis report not found or not parsed at %s", output_path)
            raise ValueError("Could not parse PEAS output")
        return res

    @staticmethod
    def _extract_basic_info_peas(data: dict) -> dict:
        info = {}
        for line in data.get("Basic information", {}).get("lines", []):
            text = line.get("clean_text", "").strip()
            colors = line.get("colors", {})
            if text.startswith("OS:"):
                info["os"] = text.replace("OS:", "").strip()
            elif text.startswith("User & Groups:"):
                info["user_groups"] = text.replace("User & Groups:", "").strip()
            elif text.startswith("Hostname:"):
                info["hostname"] = text.replace("Hostname:", "").strip()
            elif any(c in colors for c in ("RED", "REDYELLOW")):
                info.setdefault("findings", []).append(text)
        return info

    @staticmethod
    def _extract_cves_from_peas(sys_info: dict) -> dict:
        cves_list = []
        ker = sys_info.get("sections", {}).get("Kernel Exploit Registry", {})
        matched = ker.get("sections", {}).get("Matched CVEs", {})
        for line in matched.get("lines", []):
            text = line.get("clean_text", "")
            match = CVE_RE.search(text)
            if match:
                cves_list.append(match.group(1))
        return {"cves": cves_list} if cves_list else {}

    @staticmethod
    def _extract_kernel_modules_peas(sys_info: dict) -> dict:
        mods_info = {}
        kmi = sys_info.get("sections", {}).get("Kernel Modules Information", {})
        for mod_name, mod_data in kmi.get("sections", {}).items():
            for line in mod_data.get("lines", []):
                text = line.get("clean_text", "")
                colors = line.get("colors", {})
                if text and any(c in colors for c in ("RED", "REDYELLOW")):
                    mods_info[mod_name] = text
        return {"kernel_modules": mods_info} if mods_info else {}

    def extract_useful_info_peas(self, data: dict) -> KernelLPE:
        useful = {}
        useful.update(self._extract_basic_info_peas(data))
        sys_info = data.get("System Information", {})
        if sys_info:
            useful.update(self._extract_cves_from_peas(sys_info))
            useful.update(self._extract_kernel_modules_peas(sys_info))
        return KernelLPE(
            os=useful.get("os", {}),
            user_groups=useful.get("user_groups", {}),
            hostname=useful.get("hostname", {}),
            cves=useful.get("cves", {}),
        )

    def parse_les_report(self, report: str | None = None) -> list[LesCVEItem]:
        """Parse LES plain-text output into a list of findings"""
        assert report is not None  # DEBUG
        path = Path(report)
        if not path.exists():
            logger.info("LES report not found: %s", report)
            return []

        text = path.read_text(encoding="utf-8", errors="ignore")
        results: list[LesCVEItem] = []
        current: LesCVEItem | None = None
        current_id = None
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            key, value = self._les_parse_line(line)
            logger.debug("les report key %s : %s", key, repr(value))
            if key == "header":
                if current_id and current:
                    results.append(current)
                current_id = value["id"]
                current = LesCVEItem(cve_id=value["cve_id"], title=value["title"])
                continue

            if current_id is None or key is None:
                continue
            if current:
                self._les_assign_value(current, key, value)
        if current_id and current:
            results.append(current)

        logger.debug("LES report parsed")
        return results

    @staticmethod
    def _les_strip_ansi(text: str) -> str:
        return strip_ansi_sequences(text)

    def _les_parse_line(self, line_c):
        """identify line type and return (key, value)"""
        line = self._les_strip_ansi(line_c)

        # New LES format:
        # [+] [CVE-2025-32463] sudo-chwoot
        match = re.match(
            r"^\[\+]\s*\[(CVE-\d{4}-\d+)]\s*(.+)$", line, flags=re.IGNORECASE
        )
        if match:
            return "header", {
                "id": match.group(1).upper(),
                "cve_id": match.group(1).upper(),
                "title": match.group(2).strip(),
            }

        if ":" not in line:
            return None, None

        key, value = line.split(":", 1)
        return key.strip().lower(), value.strip()

    @staticmethod
    def _les_assign_value(current: LesCVEItem, base, value):
        if base == "details":
            current.details = value
        elif base == "exposure":
            current.exposure = value
        elif base == "tags":
            current.tags = [t.strip() for t in value.split(",") if t.strip()]
        elif base in ("download url", "ext-url"):
            current.download_urls.append(value)
        elif base == "comments":
            current.comments = value

    @staticmethod
    def _parse_lynis_sysctl_line(
        line: str, line_no: int
    ) -> tuple[str, dict[str, str]] | None:
        """parse config-data=sysctl... line"""
        payload = line.removeprefix("config-data=")
        parts = [part.strip() for part in payload.split(";")]

        if len(parts) < 6:
            logger.debug("skip malformed params.prf line %d: %s", line_no, line)
            return None

        if parts[0].lower() != "sysctl":
            return None

        setting = parts[1]

        solution = parts[6] if len(parts) > 6 else ""
        details = ""
        if solution.startswith("url:"):
            details = solution[4:]
        elif solution.startswith("text:"):
            details = solution[5:]
        elif solution not in ("-", ""):
            logger.debug(
                "skip non-solution field %s in params.prf line %d", solution, line_no
            )
        else:
            details = ""

        return setting, {
            "test_id": "KRNL-6000",
            "category": "Kernel",
            "field_name": setting,
            "expected_value": parts[2],
            "description": parts[4] if len(parts) > 4 else "",
            "related": parts[5] if len(parts) > 5 else "",
            "solution": details,
            "details": details,
            "raw": line,
        }

    def load_lynis_params_prf(
        self,
        params_path: str | Path = "params.prf",
    ) -> dict[str, list[dict[str, str]]]:
        """
        parse Lynis profile-like params.prf and collect sysctl recommendations
        from format like:
        config-data=sysctl;setting;expected;points;description;related;solution;...
        """
        path = Path(params_path)
        if not path.is_file():
            raise FileNotFoundError(f"Lynis params.prf not found: {path}")

        result: dict[str, list[dict[str, str]]] = {}
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as f:
                for line_no, raw_line in enumerate(f, start=1):
                    line = raw_line.strip()
                    if (
                        not line
                        or line.startswith("#")
                        or not line.startswith("config-data=")
                    ):
                        continue

                    parsed = self._parse_lynis_sysctl_line(line, line_no)
                    if parsed is None:
                        continue

                    setting, item = parsed
                    result.setdefault(setting, []).append(item)

            logger.debug(
                "loaded %d sysctl recommendations",
                sum(len(items) for items in result.values()),
            )
            return result
        except FileNotFoundError:
            raise
        except PermissionError as e:
            logger.warning("permission denied reading params.prf: %s", e)
        except OSError as e:
            logger.warning("os error reading params.prf: %s", e)
        return {}


    @staticmethod
    @lru_cache
    def load_selinux_params(
        params_path: str | Path = "recon/selinux_params.json",
    ) -> dict[str, Any]:
        """load combined SELinux boolean definitions (recon/selinux_params.json)"""
        try:
            with Path(params_path).open("r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError as e:
            logger.warning("selinux_params.json not found: %s", e)
            return {}
        except (OSError, ValueError) as e:
            logger.warning("load selinux params error: %s", e)
            return {}

    @staticmethod
    def getsebool_values() -> dict[str, bool]:
        """parse current SELinux boolean values from getsebool -a"""
        values: dict[str, bool] = {}
        getsebool = shutil.which("getsebool")
        if getsebool is None:
            logger.warning("getsebool not found, SELinux booleans check skipped")
            return values
        try:
            proc = subprocess.run(
                [getsebool, "-a"],
                check=True,
                text=True,
                capture_output=True,
                timeout=RECON_TOOL_TIMEOUT_SEC,
            )
        except subprocess.CalledProcessError as e:
            logger.warning("getsebool -a failed: %s", e)
            return values
        except subprocess.TimeoutExpired:
            logger.warning(
                "getsebool -a timed out after %ds, SELinux booleans skipped",
                RECON_TOOL_TIMEOUT_SEC,
            )
            return values
        except OSError as e:
            logger.warning("getsebool -a os error: %s", e)
            return values

        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line or "-->" not in line:
                continue
            name, _, raw = line.partition("-->")
            name = name.strip()
            state = raw.strip().lower()
            if name and state in ("on", "off", "1", "0"):
                values[name] = state in ("on", "1")
        return values

    @staticmethod
    def parse_proc_status(status_text: str) -> dict[str, str]:
        """parse /proc/<pid>/status 'Key: Value' lines into a dict"""
        fields: dict[str, str] = {}
        for line in status_text.splitlines():
            key, sep, value = line.partition(":")
            if not sep:
                continue
            fields[key.strip()] = value.strip()
        return fields

    @staticmethod
    def decode_cap_mask(mask: str | None) -> int:
        """convert a hex capability mask string to an int (0 on error)"""
        if not mask:
            return 0
        try:
            return int(mask, 16)
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def cap_names_from_mask(mask_hex: str | None) -> list[str]:
        """expand a hex capability mask string to a list of cap_* names"""
        value = ParseReports.decode_cap_mask(mask_hex)
        return [CAPABILITY_NAMES[i] for i in range(41) if value & (1 << i)]

    @staticmethod
    def username_for_uid(uid: int | None) -> str | None:
        """resolve a numeric uid to a username (falls back to the number)"""
        if uid is None:
            return None
        try:
            return pwd.getpwuid(uid).pw_name
        except (KeyError, OverflowError):
            return str(uid)

    @staticmethod
    def path_dirs() -> list[Path]:
        """list existing directories from $PATH"""
        dirs: list[Path] = []
        for raw in os.environ.get("PATH", "").split(os.pathsep):
            if not raw:
                continue
            path = Path(raw)
            if path.is_dir():
                dirs.append(path)
        return dirs

    @staticmethod
    def getcap_binaries(binaries: list[str]) -> list[tuple[str, str]]:
        """run getcap on the given files, return (path, caps-string) pairs"""
        getcap = shutil.which("getcap")
        if getcap is None:
            logger.warning("getcap not found, file caps check skipped")
            return []
        if not binaries:
            return []

        # chunk to stay well under ARG_MAX for very large $PATH dirs
        chunk_size = 100
        caps: list[tuple[str, str]] = []
        for start in range(0, len(binaries), chunk_size):
            chunk = binaries[start : start + chunk_size]
            try:
                proc = subprocess.run(
                    [getcap] + chunk,
                    check=True,
                    text=True,
                    capture_output=True,
                    timeout=RECON_TOOL_TIMEOUT_SEC,
                )
            except subprocess.CalledProcessError as e:
                logger.warning("getcap failed: %s", e)
                continue
            except subprocess.TimeoutExpired:
                logger.warning(
                    "getcap timed out after %ds on a %d-file chunk, skipped",
                    RECON_TOOL_TIMEOUT_SEC,
                    len(chunk),
                )
                continue
            except OSError as e:
                logger.warning("getcap os error: %s", e)
                continue

            for line in proc.stdout.splitlines():
                if not line.strip():
                    continue
                if "-->" in line:
                    cap_path, _, raw = line.partition("-->")
                    caps.append((cap_path.strip(), raw.strip()))
                else:
                    cap_path, _, raw = line.partition(" ")
                    raw = raw.strip()
                    if raw and "-->" not in raw:
                        caps.append((cap_path.strip(), raw))
        return caps

    @staticmethod
    def split_capabilities(raw: str) -> dict[str, list[str]]:
        """split a getcap caps-string (e.g. 'cap_net_raw=ep') into sets by flag"""
        sets: dict[str, list[str]] = {"e": [], "p": [], "i": [], "a": []}
        if not isinstance(raw, str):
            return sets
        for part in raw.replace(" ", "").split(","):
            if not part:
                continue
            name, sep, flags = part.partition("=")
            if not sep and "+" in part:
                name, _, flags = part.partition("+")
            if not flags:
                continue
            for flag in flags:
                if flag in sets:
                    sets[flag].append(name)
        return sets

    @staticmethod
    def reformat_cve_details(data_raw: dict) -> dict:
        """reformat NIST CVE 2.0 payload into the CVE JSON 5.x record shape"""
        vulns = data_raw.get("vulnerabilities", [])
        if not vulns:
            return {}
        nist_cve = vulns[0].get("cve", {})
        if not nist_cve:
            return {}

        descriptions = nist_cve.get("descriptions", [])
        published = nist_cve.get("published", "")
        modified = nist_cve.get("lastModified", "")
        source_id = nist_cve.get("sourceIdentifier", "")

        metrics = []
        nist_metrics = nist_cve.get("metrics", {})
        for nk, mk in (
            ("cvssMetricV40", "cvssV4_0"),
            ("cvssMetricV31", "cvssV3_1"),
            ("cvssMetricV30", "cvssV3_0"),
            ("cvssMetricV2", "cvssV2_0"),
        ):
            for m in nist_metrics.get(nk, []):
                metrics.append({mk: m.get("cvssData", {})})

        problem_types = []
        for w in nist_cve.get("weaknesses", []):
            for desc in w.get("description", []):
                cv = desc.get("value", "")
                problem_types.append(
                    {
                        "descriptions": [
                            {
                                "lang": desc.get("lang", "en"),
                                "description": cv,
                                "cweId": cv if cv.startswith("CWE-") else "",
                                "type": "CWE",
                            }
                        ]
                    }
                )

        references = []
        for r in nist_cve.get("references", []):
            ref = {"url": r.get("url", "")}
            src = r.get("source")
            if src:
                ref["tags"] = [src]
            references.append(ref)

        affected = []
        for a in nist_cve.get("affected", []):
            item = {
                "vendor": a.get("vendor", ""),
                "product": a.get("product", ""),
                "versions": a.get("versions", []),
            }
            if a.get("modules"):
                item["modules"] = a["modules"]
            affected.append(item)

        return {
            "dataType": "CVE_RECORD",
            "dataVersion": "5.2",
            "cveMetadata": {
                "cveId": nist_cve.get("id", ""),
                "assignerOrgId": source_id,
                "state": nist_cve.get("vulnStatus", "PUBLISHED"),
                "datePublished": published,
                "dateUpdated": modified,
            },
            "containers": {
                "cna": {
                    "providerMetadata": {
                        "orgId": source_id,
                        "dateUpdated": modified,
                    },
                    "descriptions": descriptions,
                    "metrics": metrics,
                    "problemTypes": problem_types,
                    "references": references,
                    "affected": affected,
                }
            },
        }

    @staticmethod
    def parse_nist_findings(data: dict, min_ts: int | None = None) -> list[CVEFinding]:
        """parse NIST CVE 2.0 search payload into CVEFinding list, date-filtered"""
        raw = filter_items_by_date(
            (data or {}).get("vulnerabilities", []),
            date_field="published",
            min_timestamp=min_ts,
        )

        findings: list[CVEFinding] = []
        for item in raw:
            cve = item.get("cve", {})
            cve_id = cve.get("id") or item.get("cveId")
            if not cve_id:
                continue

            description = extract_english_description(cve.get("descriptions", []))
            cvss, severity, _ = extract_cvss(cve.get("metrics", {}))
            references = [
                ref.get("url", "")
                for ref in cve.get("references", []) or []
                if ref.get("url")
            ]
            cwes = [
                desc.get("value", "")
                for weak in cve.get("weaknesses", []) or []
                for desc in weak.get("description", []) or []
                if desc.get("value", "").startswith("CWE-")
            ]

            findings.append(
                CVEFinding(
                    cve_id=str(cve_id),
                    description=description,
                    severity=severity or "",
                    cvss_score=cvss,
                    source="NIST",
                    references=references,
                    raw_data={
                        "source": "NIST",
                        "published": cve.get("published", ""),
                        "cwe": cwes,
                        "references": references,
                    },
                )
            )
        return findings

    @staticmethod
    def parse_github_pocs(data: dict) -> list[GitHubPoC]:
        """parse GitHub repo search payload into GitHubPoC list"""
        results: list[GitHubPoC] = []
        seen: set[str] = set()

        for repo in (data or {}).get("items", []):
            text = " ".join(
                [
                    repo.get("name", "") or "",
                    repo.get("full_name", "") or "",
                    repo.get("description", "") or "",
                ]
            )
            matches = extract_cve_ids(text)
            if not matches:
                continue

            cve_id = matches[0].upper()
            key = f"{cve_id}:{repo.get('full_name', '')}"
            if key in seen:
                continue
            seen.add(key)

            results.append(
                GitHubPoC(
                    cve_id=cve_id,
                    repo_name=repo.get("full_name", ""),
                    repo_url=repo.get("html_url", ""),
                    description=repo.get("description", "") or "",
                    stars=repo.get("stargazers_count", 0),
                    language=repo.get("language") or "",
                )
            )
        return results

    @staticmethod
    def osv_cve_ids(vuln: dict) -> list[str]:
        """resolve one OSV record to concrete CVE ids (aliases-aware)."""
        candidates: list[str] = [vuln.get("id", "")]
        candidates.extend(vuln.get("aliases", []) or [])
        cve_ids = [
            str(c).upper() for c in candidates if str(c).upper().startswith("CVE-")
        ]
        if not cve_ids and vuln.get("id"):
            cve_ids.append(str(vuln["id"]))
        return list(dict.fromkeys(cve_ids))

    @staticmethod
    def build_osv_finding(cve_id: str, vuln: dict) -> CVEFinding:
        """build a base OSV finding; CVSS/severity enrichment happens later"""
        db_specific = vuln.get("database_specific") or {}
        references = [
            str(ref.get("url", ""))
            for ref in vuln.get("references", []) or []
            if ref.get("url")
        ]
        return CVEFinding(
            cve_id=cve_id,
            description=vuln.get("summary", "") or "",
            severity=str(db_specific.get("severity") or ""),
            cvss_score=None,
            source="OSV",
            references=references,
            raw_data={
                "source": "OSV",
                "summary": vuln.get("summary", "") or "",
                "published": vuln.get("published", "") or "",
                "related": list(vuln.get("related", []) or [])[:5],
                "references": references,
            },
        )

    @staticmethod
    def extract_cve_details(data: dict, nist_url: str) -> dict:
        """extract {description, cvss, severity, raw} from a cve.org/NIST record"""
        containers = data.get("containers", {}) or {}
        cna = containers.get("cna", {}) or {}
        # cve.org / reformatted NIST use containers.cna, raw NIST 2.0 uses cve
        cve_obj = data.get("cve", {}) or cna

        description = extract_english_description(cve_obj.get("descriptions", []))
        cvss_score, cvss_severity, cvss_vector = extract_cvss(cve_obj.get("metrics"))

        return {
            "description": description,
            "cvss_v3_score": cvss_score,
            "cvss_v3_vector": cvss_vector,
            "severity": cvss_severity,
            "raw": data,
            "nist_url": nist_url,
        }
