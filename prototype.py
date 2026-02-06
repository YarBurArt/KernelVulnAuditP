import os
import json
import stat
import httpx
import shutil
import subprocess
from typing import List


CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/" \
               "known_exploited_vulnerabilities_schema.json"

CISA_KEV_PATH = "known_exploited_vulnerabilities.json"
CVEORG_BASE_URL = "https://cveawg.mitre.org/api/cve/"
GITHUB_URL = "https://github.com/search?q={}%20&type=repositories"
PACKETSTORM_URL = "https://packetstorm.news/download/" # ...file_id


def main():
    # res = httpx.get(CISA_KEV_URL)
    # print(res.json()[0].keys())
    with open(CISA_KEV_PATH, "r") as f:
        res: list = [json.load(f),]

    kern_cve = []
    # print(res[0]['vulnerabilities'][0].keys())
    for vuln in res[0]['vulnerabilities']:
        if vuln['product'] == "Kernel":  # 26
            kern_cve.append(vuln)

    d_urls_list = []
    # for cve in kern_cve: print(cve.values())
    for cve in kern_cve:
        cve_details = httpx.get(CVEORG_BASE_URL + cve["cveID"]).json()
        # print(cve_details["containers"]["cna"]["references"][0]["url"])
        for refc in cve_details["containers"]["cna"]["references"]:
            if "packetstormsecurity.com/files" in refc["url"]:
                print(refc["url"])
                # save to data
                d_url = PACKETSTORM_URL + refc["url"].split("/")[4]
                d_urls_list.append(d_url)

    with httpx.Client(cookies={"tos": "20250922"}) as cli:
        for url in d_urls_list:
            # idk why, but it takes both to d_urls_list
            url = url.replace("packetstormsecurity.com", "packetstorm.news")
            rsp = cli.get(url)
            with open("./data/" + url.split("/")[-1], "wb") as f:
                f.write(rsp.content)
    fix_filename()  # gcc cant find

    return kern_cve


def compile_and_run(src="./data/xpl.c", out="./xpl/tmp.out"):
    """ cc -o ./xpl/tmp.out ./data/xpl.c 
    chmod u+x ./xpl/tmp.out; ./xpl/tmp.out """
    os.makedirs(os.path.dirname(out), exist_ok=True)

    compiler = next((
        shutil.which(c) for c in ("gcc", "clang", "cc")
        if shutil.which(c)), None)
    if compiler is None: return

    proc = subprocess.run([
        compiler, "-o", out, src], stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0: return

    os.chmod(out, os.stat(out).st_mode | stat.S_IXUSR)

    try:
        proc = subprocess.run(
            [out], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, timeout=24
        )
        if proc.returncode != 0: return
    except Exception: return
    return proc.stdout, proc.stderr


def fix_filename(directory='./data'):
    for filename in os.listdir(directory):
        if filename.isdigit():
            file_path = os.path.join(directory, filename)
            mime_type = os.popen(
                f'file --mime-type -b "{file_path}"'
            ).read().strip()
            ext = {'text/x-c': '.c', 
                   'text/x-ruby': '.rb', 
                   'text/x-python': '.py'}.get(mime_type)
            if ext:
                os.rename(file_path, f"{file_path}{ext}")


def get_description(filename):
    with open(filename, 'r', encoding='utf-8') as f:
        if f.read(2) != '/*': return ""
        lines = []
        for line in f:
            if '*/' in line:
                lines.append(line.split('*/')[0])
                return "".join(lines).strip()
            lines.append(line)
    return ""


if __name__ == "__main__":
    kern_cve: List[dict] = main()
    kern_version = subprocess.run(
        ["uname", "-r"], capture_output=True, text=True, check=True
    ).stdout.strip()
    kern_build = subprocess.run(
        ["uname", "-v"], capture_output=True, text=True, check=True
    ).stdout.strip()
    result_s = {
        "started": 0,
        "complated": 0,
        "kernel_version": kern_version,
        "distribution": kern_build,
        "latest_version": "6.18.7",
        "kev_data": kern_cve,  # List[dict]
        "runs": []
    }
    st_c = 0; cmpl_c = 0
    for xpl in os.listdir('./cached_xpl'):
        if xpl.endswith(".c"):
            st_c += 1
            descr = get_description('./cached_xpl/' + xpl)
            res = compile_and_run('./cached_xpl/' + xpl)
            if res is None:
                result_s["runs"].append({
                    "id": xpl[:-2],
                    "description": descr,
                    "status": "Error",
                    "stdout": "", "stderr": "",
                })
            else:
                cmpl_c += 1
                stdout, stderr = res
                result_s["runs"].append({
                    "id": xpl[:-2],
                    "description": descr,
                    "status": "Error",
                    "stdout": stdout, "stderr": stderr,
                })
    result_s["started"] = st_c
    result_s["complated"] = cmpl_c

    with open("report_data.json", "w") as f:
        json.dump(result_s, f, indent=4)
