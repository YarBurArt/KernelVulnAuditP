from pathlib import Path

from app_services import AppServices


class FakeResult:
    def __init__(self, returncode: int = 0):
        self.stdout = "POC_OK\n"
        self.stderr = ""
        self.returncode = returncode
        self.execution_mode = "virtme-ng"
        self.crashed = False
        self.logs = {"command": "gcc exp.c -o exp && ./exp"}
        self.kernel_info = {}
        self.resources = {}
        self.modules = []
        self.files = []
        self.processes = []


class FakeIsolate:
    def __init__(self):
        self.binary: Path | None = None
        self.script_content = ""

    def run_binary(self, path: Path) -> FakeResult:
        self.binary = path
        self.script_content = Path(path).read_text()
        return FakeResult()


class FakeDB:
    def __init__(self):
        self.saved: list[tuple[str, dict]] = []

    def add_sandbox_run(self, cve_id: str, data: dict) -> None:
        self.saved.append((cve_id, data))


def _make_services() -> AppServices:
    svc = AppServices.__new__(AppServices)
    svc.isolate = FakeIsolate()
    svc.db = FakeDB()
    return svc


def test_execute_poc_chains_compile_then_test(tmp_path):
    svc = _make_services()

    poc = {
        "local_path": str(tmp_path),
        "compile_cmd": "gcc exp.c -o exp -lnftnl -lmnl",
        "test_cmd": "./exp",
    }

    out = svc._execute_poc("CVE-2021-4034", poc)

    assert out["sandbox"]["success"] is True
    assert out["sandbox"]["mode"] == "virtme-ng"
    assert "gcc exp.c -o exp -lnftnl -lmnl && ./exp" in svc.isolate.script_content
    assert f"cd {tmp_path}" in svc.isolate.script_content

    assert svc.db.saved
    cve_id, sandbox_data = svc.db.saved[0]
    assert cve_id == "CVE-2021-4034"
    assert "gcc exp.c -o exp -lnftnl -lmnl && ./exp" == sandbox_data["stdin"]


def test_execute_poc_runs_test_cmd_when_no_compile(tmp_path):
    svc = _make_services()

    poc = {
        "local_path": str(tmp_path),
        "test_cmd": "./a.out",
    }

    out = svc._execute_poc("CVE-2021-1", poc)

    assert out["sandbox"]["success"] is True
    assert svc.isolate.script_content.count("&&") == 0
    assert "./a.out" in svc.isolate.script_content


def test_execute_poc_runs_compile_cmd_when_no_test(tmp_path):
    svc = _make_services()

    poc = {
        "local_path": str(tmp_path),
        "compile_cmd": "cc main.c -o main",
    }

    out = svc._execute_poc("CVE-2021-2", poc)

    assert out["sandbox"]["success"] is True
    assert "cc main.c -o main" in svc.isolate.script_content
    assert " && " not in svc.isolate.script_content


def test_execute_poc_requires_repo():
    svc = _make_services()

    assert svc._execute_poc("CVE-2021-3", {}) == {}
    assert svc._execute_poc("CVE-2021-3", {"test_cmd": "./a"}) == {}
    assert svc._execute_poc("CVE-2021-3", {"local_path": "/tmp/x"}) == {}


def test_build_runner_script(tmp_path):
    script = AppServices._build_runner_script(tmp_path, "make && ./run")

    content = script.read_text()
    assert content.startswith("#!/bin/sh\nset -e\n")
    assert f"cd {tmp_path}" in content
    assert "make && ./run" in content
    script.unlink()
