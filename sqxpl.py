#!/usr/bin/env python3
"""
Search and collect CVE Linux kernel xpls in C, Ruby, Python
"""
import httpx
import json
import re
import base64
from typing import List, Dict, Any, Optional
from pathlib import Path
from time import sleep


# TODO: logging

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
        
        self.headers = { "User-Agent": "curl/7.54.1",}
    
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
    
    def search_repositories(self, cve_id: str, max_results: int = 10) -> List[Dict[str, Any]]:
        """ search by id like CVE-2024-1086 """
        results = []
        # check template first
        template = self.get_template(cve_id)
        if template:
            print(f"[+] Found template for {cve_id}")
            return template.get("github_repos", [])
        # FIXME: lang filters
        # lang_filters = " OR ".join([f"language:{lang}" for lang in self.LANGUAGES])
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
                total_count = data.get("total_count", 0)
                print(f"[+] Found {total_count} repositories")
                
                for repo in data.get("items", [])[:max_results]:
                    repo_info = self._extract_repo_info(repo, cve_id)
                    if repo_info:
                        results.append(repo_info)
        except Exception as e:
            print(f"[!] Search error: {e}")
        
        return results
    
    def _extract_repo_info(self, repo: Dict[str, Any], cve_id: str) -> Optional[Dict[str, Any]]:
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
                content = base64.b64decode(data.get("content", "")).decode('utf-8', errors='ignore')
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
        
        readme_lower = readme.lower()
        compile_cmd = None
        if language == "C":
            compile_cmd = self._extract_c_compile(readme)
        elif language in ["Python", "Ruby"]:
            compile_cmd = None  # doesn't need compilation
        
        test_cmd = self._extract_test_command(readme, language)
        requirements = self._extract_requirements(readme)
        
        return compile_cmd, test_cmd, requirements
    
    def _extract_c_compile(self, readme: str) -> Optional[str]:
        """extract C compilation commands"""
        patterns = [
            r'gcc\s+[^\n]+',
            r'make\s*(?:all)?',
            r'cc\s+[^\n]+',
            r'clang\s+[^\n]+'
        ]
        
        for pattern in patterns:
            matches = re.findall(
                pattern, readme, re.IGNORECASE | re.MULTILINE
            )
            if matches:
                cmd = matches[0].strip()
                cmd = cmd.replace('```', '').replace('`', '')
                return cmd
        # look in md code blocks
        code_blocks = re.findall(
            r'```(?:bash|sh|shell)?\n(.*?)```', readme, re.DOTALL
        )
        for block in code_blocks:
            for pattern in patterns:
                matches = re.findall(pattern, block, re.IGNORECASE)
                if matches:
                    return matches[0].strip()
        
    def _extract_test_command(self, readme: str, language: str) -> Optional[str]:
        """Extract test/run command"""
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
                cmd = matches[0].strip()
                cmd = cmd.replace('```', '').replace('`', '')
                return cmd
    
    def _extract_requirements(self, readme: str) -> Optional[str]:
        """Extract requirements/conditions to run"""
        # for sections about requirements
        req_patterns = [
            r'(?:requirements?|prerequisites?|dependencies|kernel version|affected versions?)[\s:]+([^\n#]+(?:\n(?!#)[^\n]+)*)',
            r'(?:tested on|works on|vulnerable)[\s:]+([^\n#]+)',
        ]
        
        for pattern in req_patterns:
            matches = re.findall(pattern, readme, re.IGNORECASE | re.MULTILINE)
            if matches:
                req = matches[0].strip()
                # clean it
                req = re.sub(r'\[.*?\]\(.*?\)', '', req)  # markdown links
                req = req.replace('*', '').replace('`', '')
                req = ' '.join(req.split())  #  whitespace
                if len(req) > 10 and len(req) < 500:
                    return req
        # any kernel version mentions
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
        self, 
        cve_id: str, 
        name: str, 
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

    def print_list_templates(self):
        templates = self.templates.get("templates", [])
        
        if not templates:
            print("[-] No templates found")
            return
        
        print(f"\n[+] Found {len(templates)} templates:")
        for tmpl in templates:
            kev_marker = "[KEV]" if tmpl.get("in_cisa_kev") else ""
            print(f"\n{tmpl['cve_id']} - {tmpl['name']} {kev_marker}")
            print(f"  {tmpl['description']}")
            print(f"  Repos: {len(tmpl.get('github_repos', []))}")
            
            for repo in tmpl.get('github_repos', []):
                print(f"    - {repo['url']} ({repo['language']})")
                if repo.get('compile_cmd'):
                    print(f"      Compile: {repo['compile_cmd']}")
                if repo.get('test_cmd'):
                    print(f"      Test: {repo['test_cmd']}")


def main():
    """CLI interface just for test"""
    import sys
    
    searcher = GitHubExploitSearcher()
    
    if len(sys.argv) < 2:
        return
    
    command = sys.argv[1]
    
    if command.lower() == "list":
        searcher.print_list_templates()
        return

    cve_id = command.upper()
    searcher.search_repositories(cve_id, max_results=100)
    
if __name__ == "__main__":
    main()
