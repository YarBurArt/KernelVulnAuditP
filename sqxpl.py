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

import base64
import json
import logging
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, NotRequired, TypedDict

import httpx

from config import POCS_BASE_PATH, REQUIREMENTS_RE, VERSIONS_RE

logger = logging.getLogger(f"kernel_audit.{__name__}")


class PocInfo(TypedDict):
    """one PoC candidate and its run instructions, as discovered on GitHub.

    url and cve_id are always present on records produced by the searcher;
    local_path is added by load_xpls once a checkout exists. compile_cmd /
    test_cmd are None when the README carries no build/run instructions.
    """

    url: str
    cve_id: str
    local_path: NotRequired[str]
    language: str | None
    description: str | None
    stars: int | None
    compile_cmd: str | None
    test_cmd: str | None
    requirements: str | None
    notes: str | None


def extract_section_by_header(
    text: str, header_patterns: list[str], max_length: int = 500
) -> str | None:
    """Grab a readable excerpt for the description where the whole README
    would be too noisy; shortens long match runs so a CVE row stays dense."""
    for pattern in header_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE | re.MULTILINE)
        if matches:
            extracted = matches[0].strip()
            extracted = re.sub(r"\[.*?]\(.*?\)", "", extracted)
            extracted = extracted.replace("*", "").replace("`", "")
            extracted = " ".join(extracted.split())

            if 10 < len(extracted) < max_length:
                return extracted

    return None


def extract_code_block_commands(
    text: str, command_patterns: list[str], languages: list[str] | Any = None
) -> list[str]:
    """Pull the runnable lines out of Markdown code fences: PoC READMEs
    embed build/run instructions as fenced blocks, and we only execute the
    commands that actually carry a recognized tool keyword."""
    commands = []

    lang_pattern = r"(?:" + "|".join(languages) + r")?" if languages else r""
    block_pattern = rf"`({lang_pattern})?\n(.*?)`"

    for block in re.findall(block_pattern, text, re.DOTALL):
        content = block[1] if isinstance(block, tuple) else block
        for pattern in command_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            commands.extend(matches)

    return commands


def clean_command_string(cmd: str) -> str:
    """Drop Markdown backtick wrappers and stray newlines so a copied
    command can be run verbatim by the shell."""
    cmd = cmd.replace("`", "").replace("`", "")
    cmd = cmd.split("\n")[0]
    return cmd.strip()

#: GitHub search API rate limits unauthenticated clients to 10 req/min; keep a
#: small safety margin so a batch of CVEs does not 403 out silently.
_SEARCH_MIN_INTERVAL = 6.0
_search_gate = threading.Lock()
_search_last = 0.0


def _throttle_search() -> None:
    """serialize GitHub API calls to stay under the rate limit."""
    global _search_last
    with _search_gate:
        now = time.monotonic()
        wait = _SEARCH_MIN_INTERVAL - (now - _search_last)
        if wait > 0:
            time.sleep(wait)
        _search_last = time.monotonic()


class GitHubExploitSearcher:
    """base search GitHub for CVE xpls/pocs"""

    SEARCH_REPOS = "https://api.github.com/search/repositories"
    SEARCH_CODE = "https://api.github.com/search/code"
    LANGUAGES = ("C", "Python", "Ruby")
    EXPLOIT_KEYWORDS = (
        "exploit",
        "poc",
        "proof-of-concept",
        "vulnerability",
        "cve",
        "privilege escalation",
        "privesc",
        "kernel exploit",
    )

    def __init__(self, templates_file: str = "tmplxpl.json"):
        """Initialize searcher"""
        self.templates_file = templates_file
        self.templates = self._load_templates()

        self.headers = {"User-Agent": "curl/7.54.1"}

    def _load_templates(self) -> dict[str, Any]:
        """load xpl templates from JSON"""
        if Path(self.templates_file).exists():
            with open(self.templates_file, "r") as f:
                return json.load(f)
        return {"templates": []}

    def _save_templates(self):
        """save templates back to JSON"""
        with open(self.templates_file, "w") as f:
            json.dump(self.templates, f, indent=2)

    def get_template(self, cve_id: str) -> dict[str, Any] | None:
        """get template for a CVE if it exists"""
        for tmpl in self.templates.get("templates", []):
            if tmpl.get("cve_id") == cve_id:
                return tmpl
        return None

    def search_repositories(
        self, cve_id: str, max_results: int = 10
    ) -> list[PocInfo]:
        """search by id like CVE-2024-1086"""
        # check template first
        template = self.get_template(cve_id)
        if template:
            # print(f"template for {cve_id}")
            return template.get("github_repos", [])

        # Fetch a larger pool than max_results: _extract_repo_info drops
        # top-ranked repos (e.g. Shell PoCs outranking C ones), so the
        # interesting results are not necessarily the first N by stars.
        pool_size = min(max(max_results * 3, 10), 30)
        params: dict[str, str | int] = {
            "q": cve_id,
            "sort": "stars",
            "order": "desc",
            "per_page": pool_size,
        }

        try:
            response = self._github_get(self.SEARCH_REPOS, params=params)
            if response.status_code != 200:
                logger.warning(
                    "GitHub search for %s returned HTTP %s: %s",
                    cve_id,
                    response.status_code,
                    response.text[:200],
                )
                return []
            data = response.json()

            results = []
            for repo in data.get("items", []):
                repo_info = self._extract_repo_info(repo, cve_id)
                if repo_info:
                    results.append(repo_info)
                if len(results) >= max_results:
                    break
        except (httpx.HTTPError, ValueError) as e:
            logger.warning("GitHub search for %s failed: %s", cve_id, e)
        return results

    def _github_get(
        self,
        url: str,
        *,
        params: dict[str, str | int] | None = None,
        timeout: float = 30.0,
        attempts: int = 3,
    ):
        """GET with a politeness gate and bounded retries on rate limiting."""
        for attempt in range(attempts):
            _throttle_search()
            response = httpx.get(
                url, headers=self.headers, params=params, timeout=timeout
            )
            if response.status_code not in (403, 429) or attempt == attempts - 1:
                return response
            retry_after = response.headers.get("Retry-After")
            delay = 0.0
            if retry_after:
                try:
                    delay = float(retry_after)
                except (TypeError, ValueError):
                    delay = 0.0
            delay = max(delay, 2.0 * (attempt + 1))
            time.sleep(min(delay, 30.0))
        return response

    def _extract_repo_info(
        self, repo: dict[str, Any], cve_id: str
    ) -> PocInfo | None:
        """extract relevant info from repository"""
        html_url = repo.get("html_url", "")
        language = repo.get("language", "")
        description = repo.get("description", "")
        if language not in self.LANGUAGES:
            return None

        readme_content = self._get_readme(repo)
        compile_cmd, test_cmd, requirements = self._parse_instructions(
            readme_content, language
        )
        return PocInfo(
            url=html_url,
            language=language,
            description=description,
            stars=repo.get("stargazers_count", 0),
            compile_cmd=compile_cmd,
            test_cmd=test_cmd,
            requirements=requirements,
            notes=self._extract_notes(readme_content),
            cve_id=cve_id,
        )

    def _get_readme(self, repo: dict[str, Any]) -> str:
        """fetch README content from repository
        to get run conditions"""
        owner = repo.get("owner", {}).get("login")
        name = repo.get("name")

        if not owner or not name:
            return ""

        readme_url = f"https://api.github.com/repos/{owner}/{name}/readme"

        try:
            response = httpx.get(readme_url, headers=self.headers, timeout=15.0)
            if response.status_code == 200:
                data = response.json()
                content = base64.b64decode(data.get("content", "")).decode(
                    "utf-8", errors="ignore"
                )
                return content
        except (httpx.HTTPError, ValueError) as e:
            logger.warning("[!] README fetch error for %s/%s: %s", owner, name, e)
        return ""

    def _parse_instructions(
        self, readme: str, language: str
    ) -> tuple[str | None, str | None, str | None]:
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

    @staticmethod
    def _extract_c_compile(readme: str) -> str | None:
        patterns = [
            r"gcc\s+[^\n]+",
            r"make\s*(?:all)?",
            r"cc\s+[^\n]+",
            r"clang\s+[^\n]+",
        ]

        commands = extract_code_block_commands(
            readme, patterns, languages=["bash", "sh", "shell", ""]
        )
        if commands:
            return clean_command_string(commands[0])

        for pattern in patterns:
            matches = re.findall(pattern, readme, re.IGNORECASE | re.MULTILINE)
            if matches:
                return clean_command_string(matches[0])

        return None

    @staticmethod
    def _extract_test_command(readme: str, language: str) -> str | None:
        patterns = []

        if language == "C":
            patterns = [
                r"\./[a-zA-Z0-9_.][a-zA-Z0-9_.-]*(?:\s+[^\n]+)?",
                r"sudo\s+\./[a-zA-Z0-9_.][a-zA-Z0-9_.-]*(?:\s+[^\n]+)?",
            ]
        elif language == "Python":
            patterns = [
                r"python3?\s+[a-zA-Z0-9_.-]+\.py(?:\s+[^\n]+)?",
                r"\./[a-zA-Z0-9_.-]+\.py(?:\s+[^\n]+)?",
            ]
        elif language == "Ruby":
            patterns = [
                r"ruby\s+[a-zA-Z0-9_.-]+\.rb(?:\s+[^\n]+)?",
                r"\./[a-zA-Z0-9_.-]+\.rb(?:\s+[^\n]+)?",
            ]

        for pattern in patterns:
            for match in re.finditer(pattern, readme, re.MULTILINE):
                candidate = clean_command_string(match.group(0))
                if not candidate:
                    continue
                # skip markdown image refs like ![](./imgs/poc.png)
                prefix = readme[max(0, match.start() - 3): match.start()]
                if prefix.endswith("](") or candidate.startswith("./imgs"):
                    continue
                return candidate

        return None

    @staticmethod
    def _extract_requirements(readme: str) -> str | None:
        req_patterns = [REQUIREMENTS_RE, VERSIONS_RE]
        extracted = extract_section_by_header(readme, req_patterns, max_length=500)
        if extracted:
            return extracted

        kernel_pattern = r"kernel\s+(?:version\s+)?[\d.]+(?:\s*-\s*[\d.]+)?"
        kernel_matches = re.findall(kernel_pattern, readme, re.IGNORECASE)
        if kernel_matches:
            return kernel_matches[0].strip()

        return None

    @staticmethod
    def _extract_notes(readme: str) -> str:
        """Extract notes or warnings from README"""
        note_patterns = [
            r"(?:note|warning|important|disclaimer)[\s:]+([^\n#]+)",
            r"\*\*(?:note|warning|important)\*\*[\s:]+([^\n]+)",
        ]

        notes = []
        for pattern in note_patterns:
            matches = re.findall(pattern, readme, re.IGNORECASE)
            notes.extend(matches)

        if notes:
            combined = " | ".join([n.strip() for n in notes[:3]])
            return combined[:500]
        lines = readme.split("\n")
        for line in lines[:10]:  # else just description
            if line.strip() and not line.startswith("#"):
                return line.strip()[:200]

        return ""

    def add_to_template(
        self,
        cve_id: str,
        name: str,
        description: str,
        repos: list[PocInfo],
        in_cisa_kev: bool = False,
        compile_cmd: str = "cc main.c",
        test_cmd: str = "./a.out",
    ):
        """add a new xpl template entry,
        which know execution conditions"""

        existing = self.get_template(cve_id)
        if existing:
            print(f"[!] Template for {cve_id} already exists")
            existing["github_repos"] = repos
            existing["name"] = name
            existing["description"] = description
            existing["in_cisa_kev"] = in_cisa_kev
            self._save_templates()
            return existing
        else:
            result = {
                "cve_id": cve_id,
                "name": name,
                "description": description,
                "github_repos": repos,
                "in_cisa_kev": in_cisa_kev,
                "compile_cmd": compile_cmd,
                "test_cmd": test_cmd,
            }
            self.templates["templates"].append(result)
            self._save_templates()
            return result

    @staticmethod
    def load_xpls(expls: list[PocInfo]) -> list[PocInfo]:
        """download PoCs into <POCS_BASE_PATH>/CVE-id/username_repo"""
        base_dir = Path(POCS_BASE_PATH)
        base_dir.mkdir(parents=True, exist_ok=True)
        downloaded_l: list[PocInfo] = []

        for xpl in expls:
            url: str | None = xpl.get("url", None)
            cve_id: str | None = xpl.get("cve_id", None)
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
                    capture_output=True,
                )
                xpl["local_path"] = str(target_dir)
                _fix_stale_compile_cmd(xpl, target_dir)
                downloaded_l.append(xpl)
            except subprocess.CalledProcessError:
                continue  # FIXME:
        return downloaded_l


def _fix_stale_compile_cmd(xpl: PocInfo, target_dir: Path) -> None:
    """Rewrite a compile_cmd whose source file is missing from the cloned
    repo (stale README instructions) to reference the actual single C
    source file present at the repo root."""
    compile_cmd = xpl.get("compile_cmd")
    if not compile_cmd or "make" in str(compile_cmd).split():
        return
    refs = re.findall(r"[\w.-]+\.c\b", str(compile_cmd))
    if not refs:
        return
    root_c = sorted(p.name for p in target_dir.glob("*.c") if p.is_file())
    if len(root_c) != 1 or root_c[0] in refs:
        return
    xpl["compile_cmd"] = re.sub(
        r"[\w.-]+\.c\b",
        lambda m: root_c[0] if m.group(0) in refs else m.group(0),
        str(compile_cmd),
    )

