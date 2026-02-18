import os
import json
import platform
from datetime import datetime, timezone
from typing import List, Dict

import httpx
from config import (
    CISA_KEV_PATH, CISA_KEV_URL, CH_API_URL,
    CVEORG_BASE_URL, GITHUB_API_URL, NIST_API_URL,
    OSV_API_URL
)


class LocalRecon:
    """
    get kernel version from different sources
    get information about its environment
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
        return str(platform.release()).split('+')[:1][0]

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

    # TODO: LinPEAS, lynis, Linux Exploit Suggester and etc


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

    def github_search(self, cveID):
        """ search PoC on the github by CVE """
        data = httpx.get(
            GITHUB_API_URL.format(q=cveID)
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
    github_result = rf.github_search("CVE-2024-1086")

    print(f"ReconFeeds test - NIST: {nist_result},\n"
          f" OSV: {osv_result}, \n GitHub: {github_result} results")
