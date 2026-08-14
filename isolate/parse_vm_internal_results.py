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

        kernel_info = {}
        resources = {}
        modules = []
        files = []
        processes = []

        # Pure dict/list reads: no guard needed, a failure here is a bug we
        # want to surface rather than a recoverable runtime condition.
        uname = sections.get("vm_start", [])
        if len(uname) >= 2:
            kernel_info["date"] = uname[0]
            kernel_info["uname"] = uname[1]

        cmdline = sections.get("cmdline", [])
        if cmdline:
            kernel_info["cmdline"] = "\n".join(cmdline)

        dmesg = sections.get("dmesg", [])
        if dmesg:
            kernel_info["dmesg"] = "\n".join(dmesg)

        cpu = sections.get("cpu", [])
        if cpu:
            resources["cpuinfo"] = "\n".join(cpu)

        mem = sections.get("memory", [])
        if mem:
            resources["meminfo"] = "\n".join(mem)

        res = sections.get("resources", [])
        if len(res) >= 1:
            resources["loadavg"] = res[0]
        if len(res) >= 2:
            resources["stat"] = "\n".join(res[1:])

        modules = [line for line in sections.get("modules", []) if line.strip()]
        if not modules:
            dmesg = sections.get("dmesg", [])
            for line in dmesg:
                match = re.search(r"] ([a-zA-Z0-9_]+) loaded", line)
                if match:
                    modules.append(match.group(1))

        files = [
            line for line in sections.get("filesystem_snapshot", []) if line.strip()
        ]
        processes = [
            line for line in sections.get("process_list", []) if line.strip()
        ]

        return kernel_info, resources, modules, files, processes
