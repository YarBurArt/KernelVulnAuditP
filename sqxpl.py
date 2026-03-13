#!/usr/bin/env python3
"""
Search and collect CVE Linux kernel xpls in C, Ruby, Python

Example output: [
{
    "url": "https://github.com/LLfam/CVE-2024-1086",
    "language": "C",
    "description": null,  # cant from that readme
    "stars": 21,
    "compile_cmd": "gcc exp.c -o exp -lnftnl -lmnl",
    "test_cmd": "./exp",
    "requirements": null,  # not in the readme
    "notes": "CPU: 0 PID: 218 at mm/
        slab_common.c:935 free_large_kmalloc+0x5e/0x90",
    "cve_id": "CVE-2024-1086"
},]
"""
import subprocess
import shutil
import json
import re
import base64
from typing import List, Dict, Any, Optional
from pathlib import Path
import httpx

from config import VERSIONS_RE, REQUIREMENTS_RE, POCS_BASE_PATH
from core import (
    extract_section_by_header,
    extract_code_block_commands,
    clean_command_string
)

class GitHubExploitSearcher:
    """base search GitHub for CVE xpls/pocs"""
    SEARCH_REPOS = "https://api.github.com/search/repositories"
    SEARCH_CODE = "https://api.github.com/search/code"
    LANGUAGES = ["C", "Python", "Ruby"]
    EXPLOIT_KEYWORDS = [
        "exploit", "poc", "proof-of-concept", "vulnerability",
        "cve", "privilege escalation", "privesc", "kernel exploit"
    ]

    def __init__(self, templates_file: str = "tmplxpl.json"):
        """Initialize searcher"""
        self.templates_file = templates_file
        self.templates = self._load_templates()

        self.headers = {"User-Agent": "curl/7.54.1"}

    def _load_templates(self) -> Dict[str, Any]:
        """load xpl templates from JSON"""
        if Path(self.templates_file).exists():
            with open(self.templates_file, 'r') as f:
                return json.load(f)
        return {"templates": []}

    def _save_templates(self):
        """save templates back to JSON"""
        with open(self.templates_file, 'w') as f:
            json.dump(self.templates, f, indent=2)

    def get_template(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """get template for a CVE if it exists"""
        for tmpl in self.templates.get("templates", []):
            if tmpl.get("cve_id") == cve_id:
                return tmpl

    def search_repositories(
        self, cve_id: str, max_results: int = 10
    ) -> List[Dict[str, Any]]:
        """ search by id like CVE-2024-1086 """
        results = []
        # check template first
        template = self.get_template(cve_id)
        if template:
            # print(f"template for {cve_id}")
            return template.get("github_repos", [])
        # FIXME: lang filters
        # lang_filters = " OR ".join(
        # [f"language:{lang}" for lang in self.LANGUAGES])
        params = {
            "q": cve_id, "sort": "stars", "order": "desc",
            "per_page": min(max_results, 30)
        }

        try:
            response = httpx.get(
                self.SEARCH_REPOS, headers=self.headers,
                params=params, timeout=30.0
            )
            if response.status_code == 200:
                data = response.json()

                for repo in data.get("items", [])[:max_results]:
                    repo_info = self._extract_repo_info(repo, cve_id)
                    if repo_info:
                        results.append(repo_info)
        except Exception as e:  # FIXME
            print(e)
        return results

    def _extract_repo_info(
        self, repo: Dict[str, Any], cve_id: str
    ) -> Optional[Dict[str, Any]]:
        """extract relevant info from repository"""
        html_url = repo.get("html_url", "")
        language = repo.get("language", "")
        description = repo.get("description", "")
        if language not in self.LANGUAGES:
            return None

        readme_content = self._get_readme(repo)
        res_ins = self._parse_instructions(
            readme_content, language
        )
        compile_cmd, test_cmd, requirements = res_ins
        # TODO: typing results objects
        return {
            "url": html_url,
            "language": language,
            "description": description,
            "stars": repo.get("stargazers_count", 0),
            "compile_cmd": compile_cmd,
            "test_cmd": test_cmd,
            "requirements": requirements,
            "notes": self._extract_notes(readme_content),
            "cve_id": cve_id
        }

    def _get_readme(self, repo: Dict[str, Any]) -> str:
        """fetch README content from repository
        to get run conditions"""
        owner = repo.get("owner", {}).get("login")
        name = repo.get("name")

        if not owner or not name:
            return ""

        readme_url = f"https://api.github.com/repos/{owner}/{name}/readme"

        try:
            response = httpx.get(
                readme_url, headers=self.headers, timeout=15.0
            )
            if response.status_code == 200:
                data = response.json()
                content = base64.b64decode(
                    data.get("content", "")
                ).decode('utf-8', errors='ignore')
                return content
        except Exception as e:
            print(f"[!] README fetch error: {e}")
        return ""

    def _parse_instructions(
        self, readme: str, language: str
    ) -> tuple[Optional[str], Optional[str], Optional[str]]:
        """
        trying parse compile and test instructions from README
        """
        if not readme:
            return None, None, None

        # later with readme_lower = readme.lower()
        compile_cmd = None
        if language == "C":
            compile_cmd = self._extract_c_compile(readme)
        elif language in ["Python", "Ruby"]:
            compile_cmd = None  # doesn't need compilation

        test_cmd = self._extract_test_command(readme, language)
        requirements = self._extract_requirements(readme)

        return compile_cmd, test_cmd, requirements

    def _extract_c_compile(self, readme: str) -> Optional[str]:
        patterns = [
            r'gcc\s+[^\n]+',
            r'make\s*(?:all)?',
            r'cc\s+[^\n]+',
            r'clang\s+[^\n]+'
        ]
        
        commands = extract_code_block_commands(
            readme, patterns, languages=['bash', 'sh', 'shell', '']
        )
        if commands:
            return clean_command_string(commands[0])
        
        for pattern in patterns:
            matches = re.findall(pattern, readme, re.IGNORECASE | re.MULTILINE)
            if matches:
                return clean_command_string(matches[0])
        
        return None

    def _extract_test_command(
        self, readme: str, language: str
    ) -> Optional[str]:
        patterns = []

        if language == "C":
            patterns = [
                r'\./[a-zA-Z0-9_-]+(?:\s+[^\n]+)?',
                r'sudo\s+\./[a-zA-Z0-9_-]+(?:\s+[^\n]+)?'
            ]
        elif language == "Python":
            patterns = [
                r'python3?\s+[a-zA-Z0-9_.-]+\.py(?:\s+[^\n]+)?',
                r'\./[a-zA-Z0-9_-]+\.py(?:\s+[^\n]+)?'
            ]
        elif language == "Ruby":
            patterns = [
                r'ruby\s+[a-zA-Z0-9_.-]+\.rb(?:\s+[^\n]+)?',
                r'\./[a-zA-Z0-9_-]+\.rb(?:\s+[^\n]+)?'
            ]

        for pattern in patterns:
            matches = re.findall(pattern, readme, re.MULTILINE)
            if matches:
                return clean_command_string(matches[0])
        
        return None

    def _extract_requirements(self, readme: str) -> Optional[str]:
        req_patterns = [REQUIREMENTS_RE, VERSIONS_RE]
        extracted = extract_section_by_header(readme, req_patterns, max_length=500)
        if extracted:
            return extracted
        
        kernel_pattern = r'kernel\s+(?:version\s+)?[\d.]+(?:\s*-\s*[\d.]+)?'
        kernel_matches = re.findall(kernel_pattern, readme, re.IGNORECASE)
        if kernel_matches:
            return kernel_matches[0].strip()

        return None

    def _extract_notes(self, readme: str) -> str:
        """Extract notes or warnings from README"""
        note_patterns = [
            r'(?:note|warning|important|disclaimer)[\s:]+([^\n#]+)',
            r'\*\*(?:note|warning|important)\*\*[\s:]+([^\n]+)'
        ]

        notes = []
        for pattern in note_patterns:
            matches = re.findall(pattern, readme, re.IGNORECASE)
            notes.extend(matches)

        if notes:
            combined = ' | '.join([n.strip() for n in notes[:3]])
            return combined[:500]
        lines = readme.split('\n')
        for line in lines[:10]:  # else just description
            if line.strip() and not line.startswith('#'):
                return line.strip()[:200]

        return ""

    def add_to_template(
        self, cve_id: str, name: str,
        description: str,
        repos: List[Dict[str, Any]],
        in_cisa_kev: bool = False,
        compile_cmd: str = "cc main.c",
        test_cmd: str = "./a.out"
    ):
        """add a new xpl template entry,
        which know execution conditions"""

        existing = self.get_template(cve_id)
        if existing:
            print(f"[!] Template for {cve_id} already exists")
            existing['github_repos'] = repos
            existing['name'] = name
            existing['description'] = description
            existing['in_cisa_kev'] = in_cisa_kev
            return existing
        else:
            result = {
                "cve_id": cve_id,
                "name": name,
                "description": description,
                "github_repos": repos,
                "in_cisa_kev": in_cisa_kev,
                "compile_cmd": compile_cmd,
                "test_cmd": test_cmd
            }
            self.templates['templates'].append(result)
            return result

        self._save_templates()

    def load_xpls(expls: List[Dict[str, any]]) -> List[Dict[str, any]]:
        """ download PoCs into /tmp/kernauditp/CVE-id/username_repo """
        base_dir = Path(POCS_BASE_PATH)
        base_dir.mkdir(parents=True, exist_ok=True)
        downloaded_l = []

        for xpl in expls:
            url = xpl.get("url")
            cve_id = xpl.get("cve_id")
            if not url or not cve_id:
                continue
            # extract username and repo from URL for path
            parts = url.rstrip("/").split("/")
            if len(parts) < 2:  # invalid url
                continue
            username = parts[-2]
            repo = parts[-1].replace(".", "_").lower()
            repo_name = f"{username}_{repo}"
            target_dir = base_dir / cve_id / repo_name

            # clean existing folder
            if target_dir.exists():
                shutil.rmtree(target_dir)
            target_dir.parent.mkdir(parents=True, exist_ok=True)
            try:
                subprocess.run(
                    ["git", "clone", url, str(target_dir)],
                    check=True,
                    capture_output=True
                )
                xpl["local_path"] = str(target_dir)
                downloaded_l.append(xpl)
            except subprocess.CalledProcessError:
                continue  # FIXME:
        return downloaded_l


def main():
    """ just for test """
    searcher = GitHubExploitSearcher()
    templ: List[dict] = searcher.templates.get("templates", [])
    print("saved templates: ", json.dumps(templ, indent=2))
    repos: List[dict] = searcher.search_repositories(
        "CVE-2024-1086", max_results=100
    )
    print("found cve repos: ", json.dumps(repos, indent=2))
    # pocs_downloaded = searcher.load_xpls(repos)


if __name__ == "__main__":
    main()
