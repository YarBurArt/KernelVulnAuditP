import logging
import re
from collections.abc import Callable

logger = logging.getLogger(f"kernel_audit.{__name__}")

QEMU_CRASH_PATTERNS = (
    r"kernel panic",
    r"Oops:",
    r"BUG:",
    r"segfault",
    r"general protection fault",
)

VIRTME_CRASH_PATTERNS = (
    r"kernel panic",
    r"segmentation fault",
    r"general protection fault",
    r"BUG:",
    r"Oops:",
    r"Call Trace:",
)


class ParseVmResults:
    """
    parse internal results collected from VMs (like guest serial output)
    """

    @staticmethod
    def parse_exit_code(output: str) -> int:
        exit_code = 0
        for line in output.splitlines():
            if line.startswith("EXIT_CODE="):
                try:
                    exit_code = int(line.removeprefix("EXIT_CODE="))
                except ValueError:
                    pass
        return exit_code

    @staticmethod
    def detect_crash(output: str, patterns: tuple) -> bool:
        return any(re.search(p, output, re.IGNORECASE) for p in patterns)

    @staticmethod
    def parse_guest_output(
        output: str, log: Callable[[str, str], None] | None = None
    ) -> tuple[
        dict[str, str],
        dict[str, str],
        list[str],
        list[str],
        list[str],
    ]:
        sections: dict[str, list[str]] = {}
        current: str | None = None

        for line in output.splitlines():
            line = line.rstrip()

            if line.startswith("==========") and line.endswith("=========="):
                current = line.strip("= ").lower().replace(" ", "_")
                assert current is not None
                sections[current] = []
                continue

            if current is not None:
                sections[current].append(line)

        def _log(key: str, value: str) -> None:
            if log is not None:
                log(key, value)
            else:
                logger.debug("parse %s: %s", key, value)

        kernel_info = {}
        resources = {}
        modules = []
        files = []
        processes = []

        try:
            uname = sections.get("vm_start", [])
            if len(uname) >= 2:
                kernel_info["date"] = uname[0]
                kernel_info["uname"] = uname[1]
        except Exception as e:
            _log("parse_vm_start_error", str(e))

        try:
            cmdline = sections.get("cmdline", [])
            if cmdline:
                kernel_info["cmdline"] = "\n".join(cmdline)
        except Exception as e:
            _log("parse_cmdline_error", str(e))

        try:
            dmesg = sections.get("dmesg", [])
            if dmesg:
                kernel_info["dmesg"] = "\n".join(dmesg)
        except Exception as e:
            _log("parse_dmesg_error", str(e))

        try:
            cpu = sections.get("cpu", [])
            if cpu:
                resources["cpuinfo"] = "\n".join(cpu)
        except Exception as e:
            _log("parse_cpu_error", str(e))

        try:
            mem = sections.get("memory", [])
            if mem:
                resources["meminfo"] = "\n".join(mem)
        except Exception as e:
            _log("parse_mem_error", str(e))

        try:
            res = sections.get("resources", [])
            if len(res) >= 1:
                resources["loadavg"] = res[0]
            if len(res) >= 2:
                resources["stat"] = "\n".join(res[1:])
        except Exception as e:
            _log("parse_resources_error", str(e))

        try:
            modules = [line for line in sections.get("modules", []) if line.strip()]
            if not modules:
                dmesg = sections.get("dmesg", [])
                for line in dmesg:
                    match = re.search(r"] ([a-zA-Z0-9_]+) loaded", line)
                    if match:
                        modules.append(match.group(1))
        except Exception as e:
            _log("parse_modules_error", str(e))

        try:
            files = [
                line for line in sections.get("filesystem_snapshot", []) if line.strip()
            ]
        except Exception as e:
            _log("parse_files_error", str(e))

        try:
            processes = [
                line for line in sections.get("process_list", []) if line.strip()
            ]
        except Exception as e:
            _log("parse_processes_error", str(e))

        return kernel_info, resources, modules, files, processes
