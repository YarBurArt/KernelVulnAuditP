import contextlib
import json
import os
import resource
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

import httpx

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities_schema.json"
)

CISA_KEV_PATH = "known_exploited_vulnerabilities.json"
CVEORG_BASE_URL = "https://cveawg.mitre.org/api/cve/"
GITHUB_URL = "https://github.com/search?q={}%20&type=repositories"
PACKETSTORM_URL = "https://packetstorm.news/download/"  # ...file_id

_BWRAP_PROTO = shutil.which("bwrap")
_SBX_TMP = "/tmp"  # noqa: S108 - bwrap internal sandbox mount point, not host temp


def _proto_sandbox_preexec(timeout_sec: int):
    def _set_limits():
        with contextlib.suppress(Exception):
            import ctypes

            libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
            libc.prctl(38, 1, 0, 0, 0)  # PR_SET_NO_NEW_PRIVS
        with contextlib.suppress(ValueError):
            resource.setrlimit(
                resource.RLIMIT_CPU, (timeout_sec + 5, timeout_sec + 5)
            )
            resource.setrlimit(
                resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024)
            )
            resource.setrlimit(
                resource.RLIMIT_FSIZE, (64 * 1024 * 1024, 64 * 1024 * 1024)
            )
            resource.setrlimit(resource.RLIMIT_NPROC, (32, 32))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    return _set_limits


def _run_proto_sandboxed(
    binary: Path, timeout: int = 24
) -> subprocess.CompletedProcess:
    run_tmp = tempfile.mkdtemp(prefix="kernaudit-proto-", dir="/tmp")
    os.chmod(run_tmp, 0o700)
    env = os.environ.copy()
    env["LD_PRELOAD"] = ""

    if _BWRAP_PROTO:
        cmd = [
            _BWRAP_PROTO,
            "--die-with-parent",
            "--unshare-all",
            "--new-session",
            "--tmpfs",
            _SBX_TMP,
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind",
            "/bin",
            "/bin",
            "--ro-bind",
            "/lib",
            "/lib",
            "--ro-bind",
            "/lib64",
            "/lib64",
            "--ro-bind",
            "/etc",
            "/etc",
            "--ro-bind",
            str(binary.parent),
            str(binary.parent),
            "--bind",
            run_tmp,
            _SBX_TMP,
            "--chdir",
            _SBX_TMP,
            "--cap-drop",
            "ALL",
            str(binary),
        ]
    else:
        cmd = [str(binary)]

    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            cwd=run_tmp if _BWRAP_PROTO is None else None,
            check=False,
            preexec_fn=_proto_sandbox_preexec(timeout)
            if not _BWRAP_PROTO
            else None,
        )
    finally:
        shutil.rmtree(run_tmp, ignore_errors=True)


def get_vulns():
    # res = httpx.get(CISA_KEV_URL)
    # print(res.json()[0].keys())
    with open(CISA_KEV_PATH) as f:
        res: list = [
            json.load(f),
        ]

    kern_cve = []
    # print(res[0]['vulnerabilities'][0].keys())
    for vuln in res[0]["vulnerabilities"]:
        if vuln["product"] == "Kernel":  # 26
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


def compile_and_run(
    src="./data/xpl.c", out="./xpl/tmp.out"
) -> tuple[str, str] | None:
    """cc -o ./xpl/tmp.out ./data/xpl.c
    chmod u+x ./xpl/tmp.out; ./xpl/tmp.out"""
    os.makedirs(os.path.dirname(out), exist_ok=True)

    compiler = next(
        (shutil.which(c) for c in ("gcc", "clang", "cc") if shutil.which(c)),
        None,
    )
    if compiler is None:
        return None

    proc = subprocess.run(
        [compiler, "-o", out, src],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return None

    os.chmod(out, os.stat(out).st_mode | stat.S_IXUSR)

    try:
        proc = _run_proto_sandboxed(Path(out), timeout=24)
        if proc.returncode != 0:
            return None
    except subprocess.TimeoutExpired:
        return None
    return proc.stdout, proc.stderr


def fix_filename(directory="./data"):
    mime_to_ext = {
        "text/x-c": ".c",
        "text/x-ruby": ".rb",
        "text/x-python": ".py",
    }
    for filename in os.listdir(directory):
        if filename.isdigit():
            file_path = os.path.join(directory, filename)

            file_cmd = shutil.which("file")
            if not file_cmd:
                raise RuntimeError("find utility not found in PATH")

            result = subprocess.run(
                [file_cmd, "--mime-type", "-b", file_path],
                capture_output=True,
                text=True,
                check=True,
            )
            mime_type = result.stdout.strip()
            ext = mime_to_ext.get(mime_type)

            if ext:
                os.rename(file_path, f"{file_path}{ext}")


def get_description(filename):
    with open(filename, encoding="utf-8") as f:
        if f.read(2) != "/*":
            return ""
        lines = []
        for line in f:
            if "*/" in line:
                lines.append(line.split("*/")[0])
                return "".join(lines).strip()
            lines.append(line)
    return ""


def main():
    kern_cve: list[dict] = get_vulns()
    uname_cmd = shutil.which("uname")
    if not uname_cmd:
        raise RuntimeError("uname utility not found in PATH")
    kern_version = subprocess.run(
        [uname_cmd, "-r"], capture_output=True, text=True, check=True
    ).stdout.strip()
    kern_build = subprocess.run(
        [uname_cmd, "-v"], capture_output=True, text=True, check=True
    ).stdout.strip()
    result_s = {
        "started": 0,
        "complated": 0,
        "kernel_version": kern_version,
        "distribution": kern_build,
        "latest_version": "6.18.7",
        "kev_data": kern_cve,  # List[dict]
        "runs": [],
    }
    st_c = 0
    cmpl_c = 0
    for xpl in os.listdir("./cached_xpl"):
        if xpl.endswith(".c"):
            st_c += 1
            descr = get_description("./cached_xpl/" + xpl)
            res = compile_and_run("./cached_xpl/" + xpl)
            if res is None:
                result_s["runs"].append(
                    {
                        "id": xpl[:-2],
                        "description": descr,
                        "status": "Error",
                        "stdout": "",
                        "stderr": "",
                    }
                )
            else:
                cmpl_c += 1
                stdout, stderr = res
                result_s["runs"].append(
                    {
                        "id": xpl[:-2],
                        "description": descr,
                        "status": "Error",
                        "stdout": stdout,
                        "stderr": stderr,
                    }
                )
    result_s["started"] = st_c
    result_s["complated"] = cmpl_c

    with open("report_data.json", "w") as f:
        json.dump(result_s, f, indent=4)


if __name__ == "__main__":
    main()
