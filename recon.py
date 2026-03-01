import shutil
from pathlib import Path
import subprocess
import os
import re
import json
import platform
from datetime import datetime, timezone
from typing import List, Dict

import httpx
from config import (
    CISA_KEV_PATH, CISA_KEV_URL, CH_API_URL,
    CVEORG_BASE_URL, GITHUB_API_URL, NIST_API_URL,
    OSV_API_URL, LYNIS_REPORT_FILE, LYNIS_BINARY,
    LYNIS_LOG_FILE, LINPEAS_OUT_JSON, PATH_LINPEAS
)

from lib_tools.peas2json import parse_peass


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

    def get_kernel_version(self):
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
            except Exception:
                pass

        return kernel_info

    def get_environment_info(self):
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

        username_default = os.environ.get('USERNAME', 'user')
        username = os.environ.get('USER', username_default)
        env_info['username'] = username

        profile_default = os.environ.get(
            'USERPROFILE', '/home')
        home_dir = os.environ.get('HOME', profile_default)
        env_info['home_dir'] = home_dir

        return env_info

    def get_kernel_version_simple(self):
        """kernel version string"""
        return ".".join(re.split(r"[+-]",
                        platform.release())[0].split(".")[:3])

    def get_kernel_build_date(self, version):
        """get build date by git and simple version,
        for now by changelog works well enough"""
        # TODO: use KernelCI or git ls instead later
        major = version.split('.')[0]
        response = httpx.get(
            CH_API_URL.format(major=major, version=version)
        )
        response.raise_for_status()

        for line in response.text.split('\n')[:10]:
            if line.startswith('Date:'):
                date_str = line.replace('Date:', '').strip()
                try:
                    return int(datetime.strptime(
                        date_str, '%a, %d %b %Y').timestamp())
                except Exception:
                    try:
                        return int(datetime.strptime(
                            date_str, '%a %b %d %H:%M:%S %Y %z'
                        ).timestamp())
                    except Exception:
                        return None

    # TODO: Linux Exploit Suggester and etc
    def run_lynis_audit(self) -> bool:
        cmd = [
            LYNIS_BINARY, "audit", "system",
            "-Q", "-q", "--no-colors",  # minimal scan
            "--report-file", LYNIS_REPORT_FILE,
            "--log-file", LYNIS_LOG_FILE,
        ]

        try:
            subprocess.run(cmd, check=True)
            return True
        except Exception:
            return False

    def _dat_parse_key(self, raw_key: str):
        match = re.fullmatch(r"([^\[]+)(?:\[(.*?)\])?", raw_key)
        if not match:
            return raw_key, None
        return match.group(1), match.group(2)

    def _dat_ensure_list(self, container, key, value):
        if key not in container:
            container[key] = [value]
        else:
            if not isinstance(container[key], list):
                container[key] = [container[key]]
            container[key].append(value)

    def _dat_assign_value(
        self, results: dict, base: str,
        inner: str | None, value: str
    ) -> None:
        """Assign value to results dict by inner key type"""
        if inner is None:  # key=value
            if base in results:
                self._dat_ensure_list(results, base, value)
            else:
                results[base] = value
        elif inner == "":  # key[]=value
            self._dat_ensure_list(results, base, value)
        else:  # key[name]=value
            if base not in results:
                results[base] = {}
            if not isinstance(results[base], dict):
                raise ValueError(
                    f"Key '{base}' used both as scalar/list and dict")
            results[base][inner] = value

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

    def _parse_lynis_datl_entry(
        self, entry: str, category_prefix: str
    ) -> dict | None:
        """
        Parse a single dat entry into a dict
        Returns None if entry is invalid or doesn't match prefix
        """
        parts = entry.split("|")
        if len(parts) < 3:
            return None

        test_id, category, kv_blob = parts[0], parts[1], parts[2]
        if not test_id.startswith(category_prefix + "-"):
            return None

        item = {"test_id": test_id, "category": category}
        # Parse key:value;key:value;
        for pair in kv_blob.split(";"):
            if ":" in pair:
                key, value = pair.split(":", 1)
                item[key.strip()] = value.strip()

        return item

    def extract_lynis_kernel_details(
        self, parsed_data: dict, category_prefix: str = "KRNL",
        type_ent: str = "details"
    ) -> List[Dict]:
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

        return results

    def _find_linpeas(self) -> str | None:
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

    def convert_linpeas_to_dict(
        self, output_path: Path, json_path: Path
    ) -> dict:
        return parse_peass(str(output_path), None)

    def _extract_basic_info_peas(self, data: dict) -> dict:
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

    def _extract_cves_from_peas(self, sys_info: dict) -> dict:
        cves_list = []
        ker = sys_info.get("sections", {}).get("Kernel Exploit Registry", {})
        matched = ker.get("sections", {}).get("Matched CVEs", {})
        for line in matched.get("lines", []):
            text = line.get("clean_text", "")
            if text.startswith("CVE-"):
                cves_list.append(text)
        return {"cves": cves_list} if cves_list else {}

    def _extract_kernel_modules_peas(self, sys_info: dict) -> dict:
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

    def extract_useful_info_peas(self, data: dict) -> dict:
        useful = {}
        useful.update(self._extract_basic_info_peas(data))
        sys_info = data.get("System Information", {})
        if sys_info:
            useful.update(self._extract_cves_from_peas(sys_info))
            useful.update(self._extract_kernel_modules_peas(sys_info))
        return useful

    def get_lynis_scan_details(
        self, report_path: str = LYNIS_REPORT_FILE
    ) -> List[Dict]:
        """ lynis facade and filter"""
        if not Path(report_path).exists():
            self.run_lynis_audit()
        parsed: dict = self.parse_lynis_dat_report(report_path)
        return self.extract_lynis_kernel_details(parsed)

    def get_linpeas_scan_details(
        self,  output_path: str = "/tmp/linpeas_report.txt",
        json_path: str = "/tmp/linpeas_report.json"  # FIXME:
    ) -> dict:
        """ linpeas facade """
        linpeas = self._find_linpeas()
        if not linpeas:
            return {}

        Path(output_path).unlink(missing_ok=True)
        self.run_linpeas(output_path)
        data: dict = self.convert_linpeas_to_dict(Path(output_path), None)
        return self.extract_useful_info_peas(data)


class ReconFeeds:
    """
    get data from cve org and KEV, github search
    using LocalRecon kernel version
    """
    def __init__(self):
        self.kev_kern_vuln = []

    def get_kev(self):
        res = httpx.get(CISA_KEV_URL)
        with open(CISA_KEV_PATH, 'wb') as f:
            f.write(res.content)

    def load_kev(self):
        with open(CISA_KEV_PATH, "r") as f:
            res: list = [json.load(f),]

        for vuln in res[0]['vulnerabilities']:
            if vuln['product'] == "Kernel":
                self.kev_kern_vuln.append(vuln)

    def cve_org_details(self, cveID):
        return httpx.get(CVEORG_BASE_URL + cveID).json()

    def github_search(self, kern_version):
        """ search PoC on the github by kernel version """
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

    def _filter_by_date(self, nist_result, min_ts: int) -> List[Dict]:
        """ to filter vulns before release"""
        min_dt = datetime.fromtimestamp(min_ts, tz=timezone.utc)
        out: List[Dict] = []
        for it in nist_result.get('vulnerabilities', []):
            pub = it.get('cve', {}).get('published')
            if not pub:
                continue
            dt = None
            # ISO-like (with optional Z or +HH:MM)
            try:
                dt = datetime.fromisoformat(pub.replace('Z', '+00:00'))
            except Exception:
                pass
            # RFC-like: "Thu Dec xx xx:xx:xx xxxx +0100"
            if dt is None:
                try:
                    # %a %b %d %H:%M:%S %Y %z
                    # (weekday, month, day, time, year, tz offset)
                    dt = datetime.strptime(pub, '%a %b %d %H:%M:%S %Y %z')
                except Exception:
                    pass
            # Fallback: drop fractional seconds and timezone,
            # parse as '%Y-%m-%dT%H:%M:%S'
            if dt is None:
                try:
                    base = pub.split('.')[0]
                    dt = datetime.strptime(base, '%Y-%m-%dT%H:%M:%S')
                    dt = dt.replace(tzinfo=timezone.utc)
                except Exception:
                    for fmt in (
                        '%Y-%m-%d %H:%M:%S', '%d %b %Y %H:%M:%S',
                        '%a, %d %b %Y %H:%M:%S %z'
                    ):
                        try:
                            dt = datetime.strptime(pub, fmt)
                            break
                        except Exception:
                            continue
            if dt is None:
                continue
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.astimezone(timezone.utc)
            if dt >= min_dt:
                out.append(it)
        return out

    def nist_search(self, kern_r_version, date):
        # Search for vulnerabilities in NIST database
        url = NIST_API_URL.format(version=kern_r_version)
        try:
            response = httpx.get(url)
            response.raise_for_status()
            res_filtered = self._filter_by_date(response.json(), date)
            return res_filtered
        except Exception as e:
            print(f"NIST search error: {str(e)}")
            return {}

    def osv_search(self, kern_r_version):
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
            print(f"OSV search error: {str(e)}")
            return {}


if __name__ == '__main__':
    # basic tests
    lr = LocalRecon()
    kern_vs: str = lr.get_kernel_version_simple()
    print(f"LocalRecon test - Kernel version: {kern_vs},"
          f" System: {lr.environment_info.get('system')}")

    rf = ReconFeeds()
    kernel_version: str = lr.get_kernel_version_simple()
    build_date: int = lr.get_kernel_build_date(kernel_version)

    nist_result = rf.nist_search(kernel_version, build_date)
    osv_result = rf.osv_search(kernel_version)
    github_result = rf.github_search("6.18.2")

    print(f"ReconFeeds test - NIST: {nist_result},\n"
          f" OSV: {osv_result}, \n GitHub: {github_result} results")

    lynis_result: List[Dict] = lr.get_lynis_scan_details()
    linpeas_result: dict = lr.get_linpeas_scan_details()

    print("Local tools")
    print(json.dumps(lynis_result, indent=2))
    print(json.dumps(linpeas_result, indent=2))
