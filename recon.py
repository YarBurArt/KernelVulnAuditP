import shutil
from pathlib import Path
import subprocess
import os
import re
import json
import logging
import platform
from datetime import datetime
from typing import List, Dict

import httpx
from config import (
    CISA_KEV_PATH, CISA_KEV_URL, CH_API_URL,
    CVEORG_BASE_URL, GITHUB_API_URL, NIST_API_URL,
    OSV_API_URL, LYNIS_REPORT_FILE, LYNIS_BINARY,
    LYNIS_LOG_FILE, LINPEAS_OUT_JSON, PATH_LINPEAS,
    LES_PATH, LES_REPORT_PATH
)
from core import (
    filter_items_by_date, strip_ansi_sequences,
    parse_key_with_brackets, ensure_list_in_dict, assign_value_by_key_type,
    parse_key_value_pairs
)

from lib_tools.peas2json import parse_peass
from schemas import KernelAuditItem, KernelLPE, LesCVEItem

logger = logging.getLogger(__name__)


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

    @staticmethod
    def get_kernel_version():
        """get kernel version from various sources"""
        kernel_info = {}

        # using platform module
        kernel_info['platform_release'] = platform.release()
        kernel_info['platform_system'] = platform.system()
        kernel_info['platform_version'] = platform.version()

        # using os.uname()
        if hasattr(os, 'uname'):
            uname_info = os.uname()
            kernel_info['kernel_name'] = uname_info.sysname
            kernel_info['kernel_release'] = uname_info.release
            kernel_info['kernel_version'] = uname_info.version
            kernel_info['machine'] = uname_info.machine

        # from /proc/version file if available
        if os.path.exists('/proc/version'):
            try:
                with open('/proc/version', 'r') as f:
                    kernel_info['proc_version'] = f.read().strip()
            except Exception as e:
                logger.debug(f"kernel /proc/version error: {e}")

        logger.info(f"collected kernel version: {kernel_info['kernel_version']}")
        logger.debug(f"kernel info: {kernel_info}")
        return kernel_info

    @staticmethod
    def get_environment_info():
        """get information about the environment"""
        env_info = {}

        # base system information
        env_info['platform'] = platform.platform()
        env_info['system'] = platform.system()
        env_info['node'] = platform.node()
        env_info['processor'] = platform.processor()
        env_info['architecture'] = platform.architecture()
        env_info['os_environ'] = dict(os.environ)

        env_info['current_directory'] = os.getcwd()
        # TODO: check privileges via user IDs, capabilities,
        # ns, supplementary groups, and SELinux context
        username_default = os.environ.get('USERNAME', 'user')
        username = os.environ.get('USER', username_default)
        env_info['username'] = username

        profile_default = os.environ.get(
            'USERPROFILE', '/home')
        home_dir = os.environ.get('HOME', profile_default)
        env_info['home_dir'] = home_dir

        logger.info("collected current environment info")
        logger.debug(f"env info: {env_info}")
        return env_info

    @staticmethod
    def get_kernel_version_simple():
        """kernel version string"""
        return ".".join(re.split(r"[+-]",
                        platform.release())[0].split(".")[:3])

    @staticmethod
    def get_kernel_build_date(version) -> int:
        """get build date by changelog, returns None on error"""
        try:
            major = version.split('.')[0]
            response = httpx.get(
                CH_API_URL.format(major=major, version=version),
                timeout=10.0
            )
            response.raise_for_status()

            for line in response.text.split('\n')[:10]:
                if line.startswith('Date:'):
                    date_str = line.replace('Date:', '').strip()
                    try:
                        return int(datetime.strptime(
                            date_str, '%a, %d %b %Y').timestamp())
                    except Exception as e:
                        logger.debug(f"kernel format build date error 1st: {e}")
                        try:
                            return int(datetime.strptime(
                                date_str, '%a %b %d %H:%M:%S %Y %z'
                            ).timestamp())
                        except Exception as e:
                            logger.debug(f"kernel format build date error 2nd: {e}")
                            return 0
            logger.warning("get kernel build date error")
            return 0
        except Exception as e:
            logger.warning(f"get_kernel_build_date error: {e}")
            return 0

    @staticmethod
    def run_lynis_audit() -> bool:
        cmd = [
            LYNIS_BINARY, "audit", "system",
            "-Q", "-q", "--no-colors",  # minimal scan
            "--report-file", LYNIS_REPORT_FILE,
            "--log-file", LYNIS_LOG_FILE,
        ]

        try:
            subprocess.run(cmd, check=True)
            return True
        except Exception as e:
            logger.warning(f"lynis_audit error: {e}")
            return False

    @staticmethod
    def _dat_parse_key(raw_key: str):
        return parse_key_with_brackets(raw_key)

    @staticmethod
    def _dat_ensure_list(container, key, value):
        ensure_list_in_dict(container, key, value)

    @staticmethod
    def _dat_assign_value(
            results: dict, base: str,
        inner: str | None, value: str
    ) -> None:
        assign_value_by_key_type(results, base, inner, value)

    def parse_lynis_dat_report(self, report_path) -> Dict:
        """
        Parse Lynis .dat file (key=value per line or key[]=v1|v2)
        Returns nested dict structure.
        """
        results = {}
        path = Path(report_path)

        if not path.exists():
            raise FileNotFoundError(
                f"Lynis report not found at {report_path}")

        with path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                raw_key, value = line.split("=", 1)
                raw_key = raw_key.strip()
                value = value.strip()
                base, inner = self._dat_parse_key(raw_key)

                self._dat_assign_value(results, base, inner, value)

        return results

    @staticmethod
    def _parse_lynis_datl_entry(
            entry: str, category_prefix: str
    ) -> dict | None:
        parts = entry.split("|")
        if len(parts) < 3:
            return None

        test_id, category, kv_blob = parts[0], parts[1], parts[2]
        if not test_id.startswith(category_prefix + "-"):
            return None

        item = {"test_id": test_id, "category": category}
        for key, value in parse_key_value_pairs(kv_blob).items():
            item[key] = value

        return item

    def extract_lynis_kernel_details(
        self, parsed_data: dict, category_prefix: str = "KRNL",
        type_ent: str = "details"
    ) -> List[KernelAuditItem]:
        """
        Parse dat entries by category and filters it
        """
        results = []
        entries = parsed_data.get(type_ent, [])
        if not isinstance(entries, list):
            entries = [entries]

        for entry in entries:
            item = self._parse_lynis_datl_entry(entry, category_prefix)
            if item:
                results.append(item)

        logger.debug(f"extracted {len(results)} lynis entries: {results}")
        return results

    @staticmethod
    def _find_linpeas() -> str | None:
        """Find linpeas.sh custom script"""
        if path := PATH_LINPEAS:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return path
        # try common locations
        for loc in [
            "/opt/linpeas/linpeas.sh", "./linpeas.sh",
            "linpeas.sh", "/tmp/linpeas.sh"
        ]:
            if os.path.isfile(loc) and os.access(loc, os.X_OK):
                return loc
        if path := shutil.which("linpeas.sh"):
            return path
        return None

    def run_linpeas(
        self, output_path: str = LINPEAS_OUT_JSON
    ) -> Path:
        """Run linpeas and save output to specified path"""
        linpeas = self._find_linpeas()
        if not linpeas:
            return None
        cmd = [linpeas, "-q", "-N"]  # FIXME: -N

        with open(output_path, "w", encoding="utf-8") as f:
            subprocess.run(
                cmd, stdout=f, stderr=subprocess.DEVNULL, check=True
            )

        return Path(output_path)

    @staticmethod
    def convert_linpeas_to_dict(
            output_path: Path, json_path: Path
    ) -> dict:
        return parse_peass(str(output_path), None)

    @staticmethod
    def _extract_basic_info_peas(data: dict) -> dict:
        info = {}
        for line in data.get("Basic information", {}).get("lines", []):
            text = line.get("clean_text", "").strip()
            colors = line.get("colors", {})
            if text.startswith("OS:"):
                info["os"] = text.replace("OS:", "").strip()
            elif text.startswith("User & Groups:"):
                info["user_groups"] = text.replace(
                    "User & Groups:", "").strip()
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
            if text.startswith("CVE-"):
                cves_list.append(text)
        return {"cves": cves_list} if cves_list else {}

    @staticmethod
    def _extract_kernel_modules_peas(sys_info: dict) -> dict:
        mods_info = {}
        kmi = sys_info.get("sections", {}).get(
            "Kernel Modules Information", {})
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

    def get_lynis_scan_details(
        self, report_path: str = LYNIS_REPORT_FILE
    ) -> List[KernelAuditItem]:
        """lynis facade and filter"""
        try:
            self.run_lynis_audit()
            parsed: dict = self.parse_lynis_dat_report(report_path)
            return self.extract_lynis_kernel_details(parsed)
        except Exception as e:
            logger.warning(f"get_lynis_scan_details error: {e}")
            return []

    def get_linpeas_scan_details(
        self,  output_path: str = "/tmp/linpeas_report.txt",
    ) -> KernelLPE | None:
        """linpeas facade"""
        try:
            linpeas = self._find_linpeas()
            if not linpeas:
                logger.exception(f"No linpeas found")
                return None

            Path(output_path).unlink(missing_ok=True)
            self.run_linpeas(output_path)
            data: dict = self.convert_linpeas_to_dict(Path(output_path), None)
            return self.extract_useful_info_peas(data)
        except Exception as e:
            logger.warning(f"get_linpeas_scan_details error: {e}")

    def get_les_scan_details(
        self, report_path: str = LES_REPORT_PATH
    ) -> list[LesCVEItem]:
        try:
            self.run_les(report_path)
            parsed: list[LesCVEItem] = self.parse_les_report(report_path)
            return parsed
        except Exception as e:
            logger.warning(f"get_les_scan_details parse error: {e}")
            return []

    @staticmethod
    def run_les(report_path: str | None = None) -> bool:
        """ run Linux Exploit Suggester"""
        cmd = [str(LES_PATH)]  # no additional flags
        if report_path:
            dest = Path(report_path)
        else:
            logger.info(f"LES report not found: {report_path}")
            return False
        try:
            proc = subprocess.run(
                cmd, check=True, text=True, capture_output=True)
            dest.write_text(proc.stdout, encoding="utf-8")
            logger.info(f"LES scan completed and saved to: {dest}")
            return True
        except Exception as e:
            logger.warning(f"something wrong with LES: {e}")
            return False

    def parse_les_report(self, report=None) -> list[LesCVEItem]:
        """Parse LES plain-text output into a list of findings"""
        path = Path(report)
        if not path.exists():
            logger.info(f"LES report not found: {report}")
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
            if key == "header":
                if current_id:
                    results.append(current)
                current_id = value["id"]
                current = LesCVEItem(
                    cve_id=value["cve_id"], title=value["title"]
                )
                continue

            if current_id is None or key is None:
                continue
            self._les_assign_value(current, key, value)
        if current_id:
            results.append(current)

        logger.debug("LES report parsed")
        return results

    @staticmethod
    def _les_strip_ansi(text: str) -> str:
        return strip_ansi_sequences(text)

    def _les_parse_line(self, line_c):
        """ identify line type and return (key, value)"""
        line = self._les_strip_ansi(line_c)
        if line.startswith("[+] ["):
            match = re.match(r"^\[\+\]\s*\[([^\]]+)\]\s*(.+)$", line)
            if match:
                return "header", {
                    "id": match.group(1).strip(),
                    "title": match.group(2).strip(),
                }
            return None, None
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
            current.tags = [
                t.strip() for t in value.split(",") if t.strip()
            ]
        elif base in ("download url", "ext-url"):
            current.download_urls.append(value)
        elif base == "comments":
            current.comments = value


class ReconFeeds:
    """
    get data from cve org and KEV, GitHub search
    using LocalRecon kernel version
    """
    def __init__(self):
        self.kev_kern_vuln = []

    @staticmethod
    def get_kev():
        """download CISA KEV catalog"""
        res = httpx.get(
            CISA_KEV_URL,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        res.raise_for_status()
        with open(CISA_KEV_PATH, 'wb') as f:
            f.write(res.content)
        logger.info(f"Downloaded KEV catalog: {len(res.content)} bytes")

    def load_kev(self):
        """load CISA KEV catalog and filter for Kernel products"""
        if not os.path.exists(CISA_KEV_PATH):
            logger.info("KEV catalog not found, downloading...")
            self.get_kev()

        with open(CISA_KEV_PATH, "r") as f:
            data = json.load(f)

        # CISA KEV format: {"title": "...", "vulnerabilities": [...]}
        if isinstance(data, dict):
            vulns = data.get('vulnerabilities', [])
        elif isinstance(data, list):
            vulns = data
        else:
            logger.warning(f"Unexpected KEV format: {type(data)}")
            return

        self.kev_kern_vuln = []
        for vuln in vulns:
            product = vuln.get('product', '')
            vendor = vuln.get('vendorProject', '')
            if product and 'kernel' in product.lower():
                self.kev_kern_vuln.append(vuln)
            elif vendor and 'linux' in vendor.lower():
                self.kev_kern_vuln.append(vuln)

        logger.debug(f"KEV vulnerabilities: {len(self.kev_kern_vuln)}")

    # TODO: KEV check with build date
    @staticmethod
    def github_search(kern_version):
        """ search PoC on the GitHub by kernel version """
        data = httpx.get(
            GITHUB_API_URL.format(q="cve " + kern_version)
        ).json()

        repos: List[dict] = []
        for repo in data.get('items', []):
            repos.append({
                'name': repo['name'],
                'full_name': repo['full_name'],
                'clone_url': repo['clone_url'],
                'description': repo['description'],
                'stars': repo['stargazers_count'],
                'language': repo['language']
            })

        return repos

    @staticmethod
    def _cve_org_details(cveID: str):
        return httpx.get(CVEORG_BASE_URL + cveID).json()

    @staticmethod
    def _filter_by_date(nist_result, min_ts: int) -> List[Dict]:
        if min_ts is None:
            return nist_result.get('vulnerabilities', [])
        return filter_items_by_date(
            nist_result.get('vulnerabilities', []),
            date_field='published',
            min_timestamp=min_ts
        )

    def nist_search(self, kern_r_version, date):
        # Search for vulnerabilities in NIST database
        url = NIST_API_URL.format(version=kern_r_version)
        try:
            response = httpx.get(url)
            response.raise_for_status()
            res_filtered = self._filter_by_date(response.json(), date)
            return res_filtered
        except Exception as e:
            logger.warning(f"NIST search error: {str(e)}")
            return {}

    @staticmethod
    def osv_search(kern_r_version):
        # Search for vulnerabilities in OSV database
        payload = {
            "version": kern_r_version,
            "package": {
                "name": "linux",
                "ecosystem": "Linux"
            }
        }
        try:
            response = httpx.post(OSV_API_URL, json=payload)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.warning(f"OSV search error: {str(e)}")
            return {}

    def get_cve_details(self, cve_id: str) -> dict:
        """filter CVE metadata using the configured API, need for db"""
        try:
            data = self._cve_org_details(cve_id)
        except Exception as e:
            logger.warning(f"{cve_id} get_cve_details error: {str(e)}")
            return {}
        cve_obj = data.get("cve", {})
        descriptions = cve_obj.get("descriptions", [])
        description = next((
            item.get("value") for item in descriptions
            if item.get("lang") == "en"
        ), None)
        if not description and descriptions:
            description = descriptions[0].get("value")

        # try CVSS v3.1, then v3.0, then v2
        metrics = cve_obj.get("metrics", {})
        cvss_score = None
        cvss_severity = None
        cvss_vector = None
        # FIXME
        for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                metric = metric_list[0]
                cvss_data = metric.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_severity = cvss_data.get("baseSeverity")
                cvss_vector = cvss_data.get("vectorString")
                break

        logger.info(f"found {cve_id} CVSS score: {cvss_score}")
        logger.debug(f"found {cve_id} details raw data: {data}")
        return {
            "description": description,
            "cvss_v3_score": cvss_score,
            "cvss_v3_vector": cvss_vector,
            "severity": cvss_severity,
            "raw": data,
            "nist_url": f"{CVEORG_BASE_URL}{cve_id}",
        }


if __name__ == '__main__':
    # basic tests
    lr = LocalRecon()
    kern_vs: str = lr.get_kernel_version_simple()
    print(f"LocalRecon test - Kernel version: {kern_vs},"
          f" System: {lr.environment_info.get('system')}")

    kernel_version: str = lr.get_kernel_version_simple()
    build_date: int | None = lr.get_kernel_build_date(kernel_version)
    lynis_result: List[KernelAuditItem] = lr.get_lynis_scan_details()
    linpeas_result: KernelLPE | None = lr.get_linpeas_scan_details()
    les_result: List[LesCVEItem] = lr.get_les_scan_details()

    print("Local tools")
    print(json.dumps(lynis_result, indent=2))
    print(json.dumps(linpeas_result, indent=2))
    print(json.dumps(les_result, indent=2))

    rf = ReconFeeds()
    nist_result: List[Dict] = rf.nist_search(kernel_version, build_date)
    osv_result: List[Dict] = rf.osv_search(kernel_version)
    github_result: List[Dict] = rf.github_search("6.18.2")

    print(f"ReconFeeds test - NIST: {nist_result},\n"
          f" OSV: {osv_result}, \n GitHub: {github_result} results")
