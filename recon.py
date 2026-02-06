import os
import json
import platform
from typing import List

import httpx


CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/" \
               "known_exploited_vulnerabilities_schema.json"

CISA_KEV_PATH = "known_exploited_vulnerabilities.json"
CVEORG_BASE_URL = "https://cveawg.mitre.org/api/cve/"
GITHUB_URL = "https://github.com/search?q={q}%20&type=repositories"
GITHUB_API_URL = "https://api.github.com/search/repositories?q={q}+language:c&sort=stars&order=desc"
NIST_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:o:linux:linux_kernel:{version}:*"
OSV_API_URL = "https://api.osv.dev/v1/query"


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
        return platform.release()

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

    def nist_search(self, kern_r_version):
        pass

    def osv_search(self, kern_r_version):
        pass


if __name__ == '__main__':
    # just test
    pass