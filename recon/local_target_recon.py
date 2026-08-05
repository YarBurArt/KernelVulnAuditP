import os
import platform
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx

from config import (
    CH_API_URL,
    LES_PATH,
    LES_REPORT_PATH,
    LINPEAS_OUT_JSON,
    LYNIS_BINARY,
    LYNIS_LOG_FILE,
    LYNIS_REPORT_FILE,
    PATH_LINPEAS,
)
from core import norm_sysctl_value
from recon.parse_recon_reports import HIGH_RISK_CAPS, ParseReports
from recon.remote_feeds_recon import logger
from schemas import (
    HostFileCapabilities,
    HostProcessCapabilities,
    HostSELinuxBoolean,
    KernelAuditItem,
    KernelLPE,
    LesCVEItem,
    SecurityRecommendationType,
)


class LocalRecon:
    """
    get kernel version from different sources
    get information about its environment
    get & filter information by audit tools
    """

    def __init__(self):
        # self.kernel_version['kernel_release'] is n.n.n
        self.kernel_version = self.get_kernel_version()
        self.environment_info = self.get_environment_info()
        self.parser = ParseReports()

    @staticmethod
    def get_kernel_version() -> dict[str, Any]:
        """get kernel version from various sources"""
        # using platform module
        kernel_info: dict[str, Any] = {
            "platform_release": platform.release(),
            "platform_system": platform.system(),
            "platform_version": platform.version(),
        }

        # using os.uname()
        if hasattr(os, "uname"):
            uname_info = os.uname()
            kernel_info["kernel_name"] = uname_info.sysname
            kernel_info["kernel_release"] = uname_info.release
            kernel_info["kernel_version"] = uname_info.version
            kernel_info["machine"] = uname_info.machine

        # from /proc/version file if available
        if os.path.exists("/proc/version"):
            try:
                with open("/proc/version", "r") as f:
                    kernel_info["proc_version"] = f.read().strip()
            except Exception as e:
                logger.debug("kernel /proc/version error: %s", e)

        logger.info("collected kernel version: %s", kernel_info["kernel_version"])
        logger.debug("kernel info: %s", kernel_info)
        return kernel_info

    @staticmethod
    def get_environment_info():
        """get information about the environment"""
        # base system information
        os_rel_info = platform.freedesktop_os_release()
        distro_name = os_rel_info.get("PRETTY_NAME") or os_rel_info.get("NAME", "")
        env_info = {
            "platform": platform.platform(),
            "system": platform.system(),
            "node": platform.node(),
            "processor": platform.processor(),
            "architecture": platform.architecture(),
            "os_environ": dict(os.environ),
            "current_directory": os.getcwd(),
            "distribution": distro_name,
        }
        # TODO: check privileges via user IDs, capabilities,
        # ns, supplementary groups, and SELinux context
        username_default = os.environ.get("USERNAME", "user")
        username = os.environ.get("USER", username_default)
        env_info["username"] = username

        profile_default = os.environ.get("USERPROFILE", "/home")
        home_dir = os.environ.get("HOME", profile_default)
        env_info["home_dir"] = home_dir

        logger.info("collected current environment info")
        logger.debug("env info: %s", env_info)
        return env_info

    @staticmethod
    def get_kernel_version_simple():
        """kernel version string"""
        return ".".join(re.split(r"[+-]", platform.release())[0].split(".")[:3])

    @staticmethod
    def get_kernel_build_date(version) -> int:
        """get build date by changelog, returns None on error"""
        try:
            major = version.split(".")[0]
            response = httpx.get(
                CH_API_URL.format(major=major, version=version), timeout=10.0
            )
            response.raise_for_status()

            for line in response.text.split("\n")[:10]:
                if line.startswith("Date:"):
                    date_str = line.replace("Date:", "").strip()
                    try:
                        return int(
                            datetime.strptime(date_str, "%a, %d %b %Y").timestamp()
                        )
                    except Exception as e:
                        logger.debug("kernel format build date error 1st: %s", e)
                        try:
                            return int(
                                datetime.strptime(
                                    date_str, "%a %b %d %H:%M:%S %Y %z"
                                ).timestamp()
                            )
                        except Exception as e:
                            logger.debug("kernel format build date error 2nd: %s", e)
                            return 0
            logger.warning("get kernel build date error")
            return 0
        except Exception as e:
            logger.warning("get_kernel_build_date error: %s", e)
            return 0

    @staticmethod
    def run_lynis_audit() -> bool:
        """much more detailed scan"""
        cmd = [
            LYNIS_BINARY,
            "audit",
            "system",
            "-Q",
            "-q",
            "--no-colors",  # minimal scan
            "--report-file",
            LYNIS_REPORT_FILE,
            "--log-file",
            LYNIS_LOG_FILE,
        ]

        try:
            subprocess.run(
                cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            return True
        except Exception as e:
            logger.warning("lynis_audit error: %s", e)
            return False

    @staticmethod
    def _find_linpeas() -> str | None:
        """Find linpeas.sh custom script"""
        if (path := PATH_LINPEAS) and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
        # try common locations
        for loc in [
            "/opt/linpeas/linpeas.sh",
            "./linpeas.sh",
            "linpeas.sh",
            "/tmp/linpeas.sh",
        ]:
            if os.path.isfile(loc) and os.access(loc, os.X_OK):
                return loc
        path_2stg: str | None = shutil.which("linpeas.sh")
        if path_2stg is not None:
            return path_2stg
        return None

    def run_linpeas(self, output_path: str = LINPEAS_OUT_JSON) -> Path | None:
        """Run linpeas and save output to specified path"""
        linpeas = self._find_linpeas()
        if not linpeas:
            return None
        cmd = [linpeas, "-q", "-N"]  # FIXME: -N

        try:
            with open(output_path, "w", encoding="utf-8") as f:
                subprocess.run(cmd, stdout=f, stderr=subprocess.DEVNULL, check=True)
        except subprocess.CalledProcessError as e:
            logger.warning("linpeas execution failed: %s", e)
            return None

        return Path(output_path)

    def get_lynis_scan_details(
        self, report_path: str = LYNIS_REPORT_FILE
    ) -> list[KernelAuditItem]:
        """lynis facade and filter"""
        try:
            self.run_lynis_audit()
            parsed: dict = self.parser.parse_lynis_dat_report(report_path)
            return self.parser.extract_lynis_kernel_details(parsed)
        except Exception as e:
            logger.warning("get_lynis_scan_details error: %s", e)
            return []

    def get_linpeas_scan_details(
        self,
        output_path: str = "/tmp/linpeas_report.txt",
    ) -> KernelLPE | None:
        """linpeas facade"""
        try:
            linpeas = self._find_linpeas()
            if not linpeas:
                logger.exception("No linpeas found")
                return None

            Path(output_path).unlink(missing_ok=True)
            self.run_linpeas(output_path)
            data: dict = self.parser.convert_linpeas_to_dict(output_path=output_path)
            return self.parser.extract_useful_info_peas(data)
        except Exception as e:
            logger.warning("get_linpeas_scan_details error: %s", e)
            return None

    def get_les_scan_details(
        self, report_path: str = LES_REPORT_PATH
    ) -> list[LesCVEItem]:
        try:
            self.run_les(report_path)
            parsed: list[LesCVEItem] = self.parser.parse_les_report(report_path)
            return parsed
        except Exception as e:
            logger.warning("get_les_scan_details parse error: %s", e)
            return []

    @staticmethod
    def run_les(report_path: str | None = None) -> bool:
        """run Linux Exploit Suggester"""
        cmd = [str(LES_PATH)]  # no additional flags
        if report_path:
            dest = Path(report_path)
        else:
            logger.info("LES report not found: %s", report_path)
            return False
        try:
            proc = subprocess.run(cmd, check=True, text=True, capture_output=True)
            dest.write_text(proc.stdout, encoding="utf-8")
            logger.info("LES scan completed and saved to: %s", dest)
            return True
        except Exception as e:
            logger.warning("something wrong with LES: %s", e)
            return False

    @staticmethod
    def get_loaded_kernel_modules() -> list[str]:
        """basically just cat /proc/modules, for later cmp inside VM"""
        modules: list[str] = []
        try:
            with Path("/proc/modules").open(
                "r", encoding="utf-8", errors="ignore"
            ) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        modules.append(line.split(None, 1)[0])
            logger.debug("loaded %d kernel modules", len(modules))
            return modules
        except FileNotFoundError as e:
            logger.warning("/proc/modules not found: %s", e)
            return []
        except PermissionError as e:
            logger.warning("permission denied reading /proc/modules: %s", e)
            return []
        except OSError as e:
            logger.warning("os error reading /proc/modules: %s", e)
            return []
        except Exception as e:
            logger.exception("unexpected error reading kernel modules: %s", e)
            return []

    @staticmethod
    def _load_sysctl_values() -> dict[str, str]:
        values: dict[str, str] = {}
        root = Path("/proc/sys")
        try:
            if not root.exists():
                logger.warning("/proc/sys not found")
                return values

            for path in root.rglob("*"):
                try:
                    if not path.is_file():
                        continue
                    key = ".".join(path.relative_to(root).parts)
                    if not key:
                        continue
                    try:
                        value = path.read_text(
                            encoding="utf-8", errors="ignore"
                        ).strip()
                    except PermissionError:
                        continue
                    except OSError as e:
                        logger.debug("skip sysctl key %s: %s", key, e)
                        continue
                    if value:
                        values[key] = value
                except Exception as e:
                    logger.debug("skip sysctl entry %s: %s", path, e)
                    continue

            logger.debug("loaded %d sysctl values", len(values))
            return values
        except Exception as e:
            logger.exception("unexpected error loading sysctl values: %s", e)
            return {}

    def get_lynis_kernel_hardening_details(
        self,
        params_path: str | Path = "recon/params.prf",
    ) -> list[SecurityRecommendationType]:
        """cmp current sysctl values with kernel recommendations from lynis"""
        try:
            prf = self.parser.load_lynis_params_prf(params_path)
            current = self._load_sysctl_values()
            results: list[SecurityRecommendationType] = []

            for field_name, entries in prf.items():
                actual_raw = current.get(field_name, "")
                actual_norm = norm_sysctl_value(actual_raw)

                for entry in entries:
                    expected_raw = entry.get("expected_value", "")
                    expected_norm = norm_sysctl_value(expected_raw)
                    ok_s = actual_raw != "" and expected_norm == actual_norm

                    results.append(
                        SecurityRecommendationType(
                            test_id=entry.get("test_id", "KRNL-6000"),
                            category=entry.get("category", "Kernel"),
                            description=entry.get("description", ""),
                            field_name=field_name,
                            expected_value=expected_raw,
                            actual_value=actual_raw,
                            status=(
                                "ok"
                                if ok_s
                                else ("missing" if actual_raw == "" else "mismatch")
                            ),
                            severity="medium",
                            source="lynis",
                            raw_data={
                                "related": entry.get("related", ""),
                                "solution": entry.get("solution", ""),
                                "details": entry.get("details", ""),
                                "raw": entry.get("raw", ""),
                                "expected_normalized": expected_norm,
                                "actual_normalized": actual_norm,
                            },
                        )
                    )

            logger.debug(
                "prepared %d lynis kernel hardening recommendations", len(results)
            )
            return results

        except FileNotFoundError as e:
            logger.warning("params.prf not found: %s", e)
            return []
        except Exception as e:
            logger.exception("get_lynis_kernel_hardening_details failed: %s", e)
            return []

    def get_host_selinux_bools(
        self,
        params_path: str | Path = "recon/selinux_params.json",
    ) -> list[HostSELinuxBoolean]:
        """check hardened SELinux booleans (selinux_params.json) against the
        current system values from `getsebool -a`"""
        params = self.parser.load_selinux_params(params_path)
        current = self.parser.getsebool_values()

        names: list[str] = []
        for section in params.values():
            for item in section.get("booleans", []):
                name = item.get("name")
                if name and name not in names:
                    names.append(name)

        booleans = [
            HostSELinuxBoolean(
                boolean_name=name,
                value=current.get(name, False),
            )
            for name in names
        ]
        logger.info("collected %d SELinux booleans", len(booleans))
        return booleans

    def get_selinux_hardening(
        self,
        params_path: str | Path = "recon/selinux_params.json",
    ) -> list[SecurityRecommendationType]:
        """build per-boolean hardening recommendations by comparing the
        hardened state from selinux_params.json with the live getsebool value,
        based on https://access.redhat.com/articles/7047896
        and https://github.com/fedora-selinux/selinux-playbooks """
        params = self.parser.load_selinux_params(params_path)
        current = self.parser.getsebool_values()

        results: list[SecurityRecommendationType] = []
        idx = 0
        for section_name, section in params.items():
            for item in section.get("booleans", []):
                name = item.get("name")
                if not name:
                    continue
                idx += 1
                expected_on = item.get("state", "off") == "on"
                actual = current.get(name, False)
                expected_str = "on" if expected_on else "off"
                actual_str = "on" if actual else "off"

                if actual == expected_on:
                    status, severity = "ok", "info"
                elif expected_on and not actual:
                    status, severity = "FAIL", "critical"
                else:
                    status, severity = "WARNING", "warning"

                results.append(
                    SecurityRecommendationType(
                        test_id=f"SELNX-{idx:04d}",
                        category="SELinux",
                        description=item.get(
                            "comment", section.get("description", "")
                        ),
                        field_name=name,
                        expected_value=expected_str,
                        actual_value=actual_str,
                        status=status,
                        severity=severity,
                        source="selinux",
                        raw_data={
                            "section": section_name,
                            "persistent": item.get("persistent", ""),
                            "expected_normalized": expected_on,
                            "actual_normalized": actual,
                        },
                    )
                )

        logger.info("prepared %d SELinux hardening recommendations", len(results))
        return results

    def get_pids_caps(self) -> list[HostProcessCapabilities]:
        """inspect capability masks of every process (/proc/<pid>/status),
        returning only processes that actually hold capabilities"""
        result: list[HostProcessCapabilities] = []
        proc_root = Path("/proc")
        if not proc_root.exists():
            logger.warning("/proc not found, process caps check skipped")
            return result

        try:
            pids = [
                int(entry.name)
                for entry in proc_root.iterdir()
                if entry.name.isdigit()
            ]
        except OSError as e:
            logger.warning("list /proc error: %s", e)
            return result

        for pid in pids:
            try:
                status_file = proc_root / str(pid) / "status"
                if not status_file.is_file():
                    continue
                status_text = status_file.read_text(
                    encoding="utf-8", errors="ignore"
                )
            except (PermissionError, OSError) as e:
                logger.debug("skip pid %s status: %s", pid, e)
                continue

            fields = self.parser.parse_proc_status(status_text)
            cap_eff = self.parser.decode_cap_mask(fields.get("CapEff"))
            cap_prm = self.parser.decode_cap_mask(fields.get("CapPrm"))
            cap_amb = self.parser.decode_cap_mask(fields.get("CapAmb"))

            # keep only processes that actually hold (dangerous) capabilities
            if not (cap_eff or cap_prm or cap_amb):
                continue

            uid_fields = fields.get("Uid", "").split()
            uid = int(uid_fields[1]) if len(uid_fields) > 1 else None

            secbits = fields.get("Secbits")
            no_new_privs_raw = fields.get("NoNewPrivs")
            result.append(
                HostProcessCapabilities(
                    pid=pid,
                    process_name=fields.get("Name", ""),
                    username=self.parser.username_for_uid(uid),
                    cap_effective=fields.get("CapEff"),
                    cap_permitted=fields.get("CapPrm"),
                    cap_inheritable=fields.get("CapInh"),
                    cap_bounding=fields.get("CapBnd"),
                    cap_ambient=fields.get("CapAmb"),
                    secbits=secbits,
                    no_new_privs=(
                        no_new_privs_raw == "1" if no_new_privs_raw else None
                    ),
                )
            )

        result.sort(key=lambda c: c.pid)
        logger.info("collected capability masks for %d processes", len(result))
        return result

    def get_bpath_caps(self) -> list[HostFileCapabilities]:
        """getcap every executable file found in $PATH"""
        binaries: list[str] = []
        for directory in self.parser.path_dirs():
            try:
                for entry in directory.iterdir():
                    if entry.is_file() and os.access(entry, os.X_OK):
                        binaries.append(str(entry))
            except OSError as e:
                logger.debug("skip PATH dir %s: %s", directory, e)
                continue

        found = self.parser.getcap_binaries(binaries)
        result: list[HostFileCapabilities] = []
        for path, raw in found:
            sets = self.parser.split_capabilities(raw)
            owner_name = None
            try:
                uid = os.stat(path).st_uid
                owner_name = self.parser.username_for_uid(uid)
            except OSError as e:
                logger.debug("stat %s error: %s", path, e)
            result.append(
                HostFileCapabilities(
                    path=path,
                    owner_name=owner_name,
                    cap_effective=",".join(sets["e"]) or None,
                    cap_permitted=",".join(sets["p"]) or None,
                    cap_inheritable=",".join(sets["i"]) or None,
                    cap_ambient=",".join(sets["a"]) or None,
                )
            )

        result.sort(key=lambda c: c.path)
        logger.info("found %d PATH files with capabilities", len(result))
        return result

    @staticmethod
    def _proc_cap_severity(
        cap_names: list[str], username: str | None
    ) -> tuple[str, str]:
        """(severity, status) for a process capability set.

        Warning by default (most processes legitimately hold some caps);
        critical only when a non-root process carries high-risk caps,
        which is a genuine privilege-escalation signal.
        """
        has_high = any(cap in HIGH_RISK_CAPS for cap in cap_names)
        if has_high and username != "root":
            return "critical", "FAIL"
        if cap_names:
            return "warning", "WARNING"
        return "info", "ok"

    @staticmethod
    def _file_cap_severity(cap_names: list[str]) -> tuple[str, str]:
        """(severity, status) for a PATH file's effective capability set.

        Files with high-risk caps are persistent attack surface, so those
        are critical; the common low-risk ones (cap_net_raw etc.) warn.
        """
        if any(cap in HIGH_RISK_CAPS for cap in cap_names):
            return "critical", "FAIL"
        if cap_names:
            return "warning", "WARNING"
        return "info", "ok"

    def get_capability_recommendations(self) -> list[SecurityRecommendationType]:
        """summarise process + PATH-file capabilities as hardening findings"""
        results: list[SecurityRecommendationType] = []
        idx = 0

        for pc in self.get_pids_caps():
            idx += 1
            eff_names = self.parser.cap_names_from_mask(pc.cap_effective)
            severity, status = self._proc_cap_severity(eff_names, pc.username)
            proc_label = f"{pc.process_name or '?'}/{pc.pid}"
            results.append(
                SecurityRecommendationType(
                    test_id=f"PCAP-{idx:04d}",
                    category="ProcessCapabilities",
                    description=(
                        f"Process '{proc_label}' holds capabilities "
                        f"(effective: {', '.join(eff_names) or 'unknown'})"
                    ),
                    field_name=proc_label,
                    expected_value="none",
                    actual_value=",".join(eff_names) or (pc.cap_effective or ""),
                    status=status,
                    severity=severity,
                    source="proc",
                    raw_data={
                        "pid": pc.pid,
                        "username": pc.username,
                        "no_new_privs": pc.no_new_privs,
                        "cap_effective": pc.cap_effective,
                        "cap_permitted": pc.cap_permitted,
                    },
                )
            )

        for fc in self.get_bpath_caps():
            idx += 1
            eff_names = [c for c in (fc.cap_effective or "").split(",") if c]
            prm_names = [c for c in (fc.cap_permitted or "").split(",") if c]
            severity, status = self._file_cap_severity(
                sorted(set(eff_names) | set(prm_names))
            )
            results.append(
                SecurityRecommendationType(
                    test_id=f"FCAP-{idx:04d}",
                    category="FileCapabilities",
                    description=(
                        f"PATH executable has capabilities "
                        f"(owner: {fc.owner_name or '?'})"
                    ),
                    field_name=fc.path,
                    expected_value="none",
                    actual_value=",".join(
                        sorted(set(eff_names) | set(prm_names))
                    )
                    or (fc.cap_effective or fc.cap_permitted or ""),
                    status=status,
                    severity=severity,
                    source="getcap",
                    raw_data={
                        "cap_effective": fc.cap_effective,
                        "cap_permitted": fc.cap_permitted,
                        "cap_inheritable": fc.cap_inheritable,
                    },
                )
            )

        logger.info(
            "prepared %d capability hardening recommendations", len(results)
        )
        return results
