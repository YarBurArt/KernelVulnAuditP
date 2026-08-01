import os
import platform
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, List

import httpx

from config import (
    CH_API_URL,
    LYNIS_BINARY,
    LYNIS_REPORT_FILE,
    LYNIS_LOG_FILE,
    PATH_LINPEAS,
    LINPEAS_OUT_JSON,
    LES_REPORT_PATH,
    LES_PATH,
)
from core import norm_sysctl_value
from recon.parse_recon_reports import ParseReports
from recon.remote_feeds_recon import logger
from schemas import KernelAuditItem, KernelLPE, LesCVEItem, SecurityRecommendation


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
        if path := PATH_LINPEAS:
            if os.path.isfile(path) and os.access(path, os.X_OK):
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
    ) -> List[KernelAuditItem]:
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
        params_path: str | Path = "params.prf",
    ) -> list[SecurityRecommendation]:
        """cmp current sysctl values with kernel recommendations from lynis"""
        try:
            prf = self.parser.load_lynis_params_prf(params_path)
            current = self._load_sysctl_values()
            results: list[SecurityRecommendation] = []

            for field_name, entries in prf.items():
                actual_raw = current.get(field_name, "")
                actual_norm = norm_sysctl_value(actual_raw)

                for entry in entries:
                    expected_raw = entry.get("expected_value", "")
                    expected_norm = norm_sysctl_value(expected_raw)
                    ok_s = actual_raw != "" and expected_norm == actual_norm

                    results.append(
                        SecurityRecommendation(
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
