"""Domain entities of a kernel-vulnerability audit.

The core of the whole project: the things the audit knows about a host
kernel, itz vulnerabilities, exploits, and the outcome of testing a PoC in
a sandbox. This module is pure Python stdlib and depends on nothing else in
the project. Everything else in the repo depends on these types.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Literal


@dataclass
class SecurityRecommendationType:
    """unified security recommendation (from lynis or other sources)"""

    test_id: str = ""
    category: str = ""
    description: str = ""
    field_name: str = ""
    expected_value: str = ""
    actual_value: str = ""
    status: str = ""
    severity: str = ""
    source: str = "lynis"
    raw_data: dict = field(default_factory=dict)


@dataclass
class KernelLPE:
    os: str = ""
    user_groups: str = ""
    hostname: str = ""
    cves: list[str] = field(default_factory=list)


@dataclass
class CVEFinding:
    cve_id: str

    description: str = ""
    severity: str = ""

    cvss_score: float | None = None
    source: str = ""

    references: list[str] = field(default_factory=list)

    raw_data: dict[str, Any] = field(default_factory=dict)


@dataclass
class GitHubPoC:
    cve_id: str

    repo_name: str
    repo_url: str

    description: str = ""
    stars: int = 0
    language: str = ""


@dataclass
class HostEnvironmentVariable:
    """single environment variable from os.environ"""

    name: str
    value: str


@dataclass
class HostKernelParameter:
    """single sysctl /proc/sys kernel parameter"""

    parameter_name: str
    parameter_value: str


@dataclass
class HostBootParameter:
    """single parsed kernel command-line parameter"""

    parameter_name: str
    parameter_value: str


@dataclass
class HostKernelModule:
    """single loaded kernel module (/proc/modules)"""

    module_name: str
    size: int | None = None
    refcount: int | None = None
    used_by: str | None = None
    state: str | None = None
    address: str | None = None


@dataclass
class HostKernelHardening:
    """single kernel hardening recommendation (lynis)"""

    test_id: str = ""
    category: str = ""
    description: str = ""
    field_name: str = ""
    expected_value: str = ""
    actual_value: str = ""
    status: str = ""
    severity: str = ""
    related: str = ""
    solution: str = ""
    details: str = ""


@dataclass
class HostSELinuxBoolean:
    """single SELinux boolean"""

    boolean_name: str
    value: bool


@dataclass
class HostUser:
    """single user account from /etc/passwd"""

    username: str
    uid: int | None = None
    gid: int | None = None
    home_dir: str | None = None
    shell: str | None = None
    gecos: str | None = None
    last_login: datetime | None = None
    locked: bool | None = None


@dataclass
class HostGroup:
    """single group from /etc/group with its member names"""

    group_name: str
    gid: int | None = None
    members: list[str] = field(default_factory=list)


@dataclass
class HostNamespace:
    """single process namespace (/proc/<pid>/ns/*)"""

    pid: int
    process_name: str = ""
    namespace_type: str = ""
    inode: str = ""


@dataclass
class HostCgroup:
    """single process cgroup attachment"""

    pid: int
    path: str = ""
    process_name: str = ""
    hierarchy_id: int | None = None
    controllers: str = ""
    cgroup_version: int | None = None


@dataclass
class HostProcess:
    """interesting process found during recon"""

    pid: int
    ppid: int | None = None
    name: str = ""
    username: str | None = None
    executable: str | None = None
    cmdline: str | None = None
    cwd: str | None = None
    state: str | None = None
    is_root: bool | None = None
    notable: bool | None = None


@dataclass
class HostFile:
    """interesting file found during recon"""

    path: str
    file_type: str | None = None
    mode: str | None = None
    owner_uid: int | None = None
    owner_name: str | None = None
    group_gid: int | None = None
    group_name: str | None = None
    size: int | None = None
    suid: bool = False
    sgid: bool = False
    sticky: bool = False
    world_writable: bool = False
    user_writable: bool = False
    group_writable: bool = False
    readable: bool = False
    executable: bool = False
    symlink_target: str | None = None
    notable: bool = False


@dataclass
class HostFileCapabilities:
    """file with security capabilities set (getcap output)"""

    path: str
    owner_name: str | None = None
    cap_effective: str | None = None
    cap_permitted: str | None = None
    cap_inheritable: str | None = None
    cap_bounding: str | None = None
    cap_ambient: str | None = None


@dataclass
class HostProcessCapabilities:
    """process capability masks (/proc/<pid>/status)"""

    pid: int
    process_name: str = ""
    username: str | None = None
    cap_effective: str | None = None
    cap_permitted: str | None = None
    cap_inheritable: str | None = None
    cap_bounding: str | None = None
    cap_ambient: str | None = None
    secbits: str | None = None
    no_new_privs: bool | None = None


@dataclass(frozen=True)
class KernelInfo:
    """kernel details captured inside the sandboxed guest (VM start)."""

    uname: str = ""
    date: str = ""
    cmdline: str = ""
    dmesg: str = ""


@dataclass(frozen=True)
class VmResources:
    """host resource samples captured inside the sandboxed guest."""

    cpuinfo: str = ""
    meminfo: str = ""
    loadavg: str = ""
    stat: str = ""


@dataclass(frozen=True)
class RunLogs:
    """diagnostic step log written by the sandbox backend while running.

    Each field is one named log entry; backends leave the fields they never
    produce unset instead of stashing arbitrary keys in a dict.
    """

    stage: str | None = None
    binary: str | None = None
    timeout: str | None = None
    initrd_created: str | None = None
    kernel_path: str | None = None
    command: str | None = None
    kernel: str | None = None
    initrd: str | None = None
    qemu_returncode: str | None = None
    stdout_size: str | None = None
    stderr_size: str | None = None
    exit_code: str | None = None
    initrd_contents: str | None = None
    initrd_size: str | None = None
    virtme_returncode: str | None = None
    kernel_version: str | None = None
    warning: str | None = None
    binary_path: str | None = None
    binary_permissions: str | None = None
    working_directory: str | None = None
    user: str | None = None
    signal: str | None = None
    timeout_stdout_size: str | None = None
    timeout_stderr_size: str | None = None
    error: str | None = None


@dataclass
class SandboxRunResult:
    """Outcome of executing a binary inside the sandbox.

    Produced by the isolate adapter for every PoC execution and used as
    the source of truth for persistence, reporting, and the TUI. Every field
    is typed; no attribute-poking on loose objects.
    """

    stdout: str
    stderr: str
    returncode: int
    execution_mode: Literal["virtme-ng", "qemu", "host"]
    duration_ms: float
    crashed: bool = False

    logs: RunLogs = field(default_factory=RunLogs)

    kernel_info: KernelInfo = field(default_factory=KernelInfo)
    resources: VmResources = field(default_factory=VmResources)
    modules: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    processes: list[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        """Whether the payload exited cleanly (returncode 0, no crash)."""
        return self.returncode == 0

    def to_json(self) -> str:
        import json

        return json.dumps(asdict(self), indent=4)


# names of the collection attributes dropped for header-only host_info listings
HOST_INFO_CHILD_FIELDS: tuple[str, ...] = (
    "environment_variables",
    "kernel_parameters",
    "boot_parameters",
    "kernel_modules",
    "kernel_hardening",
    "selinux_booleans",
    "users",
    "groups",
    "namespaces",
    "cgroups",
    "processes",
    "files",
    "file_capabilities",
    "process_capabilities",
)


@dataclass
class HostInfo:
    """host environment snapshot aggregate.

    Scalar fields mirror the host_info columns; each collection mirrors a
    child table. ID/timestamps are managed by the persistence layer.
    """

    id: int | None = None
    captured_at: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None

    hostname: str = ""
    kernel_version: str = ""
    kernel_release: str = ""
    kernel_build: str = ""
    kernel_name: str = ""
    machine: str = ""
    platform_release: str = ""
    platform_system: str = ""
    platform_version: str = ""
    platform: str = ""
    proc_version: str = ""
    node: str = ""
    processor: str = ""
    architecture: str = ""
    distribution: str = ""
    current_directory: str = ""
    username: str = ""
    home_dir: str = ""
    boot_cmdline: str = ""
    selinux_enabled: bool | None = None
    selinux_status: str = ""
    selinux_policy: str = ""
    selinux_mode: str = ""
    selinux_mount: str = ""
    notes: str = ""

    environment_variables: list[HostEnvironmentVariable] = field(default_factory=list)
    kernel_parameters: list[HostKernelParameter] = field(default_factory=list)
    boot_parameters: list[HostBootParameter] = field(default_factory=list)
    kernel_modules: list[HostKernelModule] = field(default_factory=list)
    kernel_hardening: list[HostKernelHardening] = field(default_factory=list)
    selinux_booleans: list[HostSELinuxBoolean] = field(default_factory=list)
    users: list[HostUser] = field(default_factory=list)
    groups: list[HostGroup] = field(default_factory=list)
    namespaces: list[HostNamespace] = field(default_factory=list)
    cgroups: list[HostCgroup] = field(default_factory=list)
    processes: list[HostProcess] = field(default_factory=list)
    files: list[HostFile] = field(default_factory=list)
    file_capabilities: list[HostFileCapabilities] = field(default_factory=list)
    process_capabilities: list[HostProcessCapabilities] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """serialize to a JSON-safe dict (mirrors the ORM HostInfo row)."""
        result = asdict(self)
        for key in ("captured_at", "created_at", "updated_at"):
            value = result.get(key)
            if isinstance(value, datetime):
                result[key] = value.isoformat()
        for user in result.get("users", []):
            if isinstance(user.get("last_login"), datetime):
                user["last_login"] = user["last_login"].isoformat()
        return result


@dataclass
class Exploit:
    """a known exploit/PoC linked to a vulnerability."""

    id: int | None = None
    vulnerability_id: int | None = None
    exploit_type: str | None = None
    source: str | None = None
    url: str | None = None
    verified: bool = False
    date_published: datetime | None = None


@dataclass
class CisaKevEntry:
    """a CISA Known Exploited Vulnerabilities catalog entry."""

    id: int | None = None
    vulnerability_id: int | None = None
    date_added: datetime | None = None
    due_date: datetime | None = None
    required_action: str | None = None
    known_ransomware: bool = False
    notes: str | None = None
    vendor_project: str | None = None
    product: str | None = None


@dataclass
class SandboxRun:
    """a persisted sandbox execution result."""

    id: int | None = None
    vulnerability_id: int | None = None
    run_timestamp: datetime | None = None
    sandbox_platform: str | None = None
    exploit_file_hash: str | None = None
    execution_success: bool = False
    exit_code: int | None = None
    crashed: bool = False
    stdout: str | None = None
    stderr: str | None = None
    stdin: str | None = None
    open_processes: list[Any] = field(default_factory=list)
    open_files: list[Any] = field(default_factory=list)
    modules: list[Any] = field(default_factory=list)
    kernel_info: dict[str, Any] = field(default_factory=dict)
    resources: dict[str, Any] = field(default_factory=dict)
    notes: str | None = None


@dataclass
class Reference:
    """an external reference/link for a vulnerability."""

    id: int | None = None
    vulnerability_id: int | None = None
    url: str = ""
    ref_type: str | None = None
    source: str | None = None


@dataclass
class AffectedProduct:
    """a product/package affected by a vulnerability."""

    id: int | None = None
    vulnerability_id: int | None = None
    vendor: str | None = None
    product: str | None = None
    version: str | None = None
    cpe: str | None = None
    package_ecosystem: str | None = None
    package_name: str | None = None


@dataclass
class Vulnerability:
    """a vulnerability row (CVE summary / search result, or write patch)."""

    cve_id: str
    id: int | None = None
    description: str | None = None
    published_date: datetime | None = None
    last_modified_date: datetime | None = None
    cvss_v2_score: float | None = None
    cvss_v3_score: float | None = None
    cvss_v3_vector: str | None = None
    severity: str | None = None
    cwe_ids: list[str] = field(default_factory=list)
    in_cisa_kev: bool = False
    has_exploit: bool = False
    exploit_count: int = 0
    github_refs: int = 0
    exploitdb_refs: int = 0
    sources: list[str] = field(default_factory=list)
    raw_data: dict[str, Any] = field(default_factory=dict)
    criticality_score: int = 0
    known_ransomware: bool = False
    created_at: datetime | None = None
    updated_at: datetime | None = None


@dataclass
class VulnerabilityDetail(Vulnerability):
    """a vulnerability with all related data (exploits, KEV, runs, refs)."""

    affected_products: list[AffectedProduct] = field(default_factory=list)
    references: list[Reference] = field(default_factory=list)
    exploits: list[Exploit] = field(default_factory=list)
    cisa_kev: CisaKevEntry | None = None
    sandbox_runs: list[SandboxRun] = field(default_factory=list)


@dataclass
class Statistics:
    """aggregated vulnerability statistics."""

    total: int = 0
    by_severity: dict[str, int] = field(default_factory=dict)
    with_exploits: int = 0
    in_cisa_kev: int = 0
    ransomware_related: int = 0
    critical_count: int = 0
    avg_cvss: float = 0.0


@dataclass
class SecurityRecommendation:
    """a persisted security recommendation (from lynis/hardening checks)."""

    id: int | None = None
    test_id: str | None = None
    category: str | None = None
    description: str | None = None
    field_name: str | None = None
    expected_value: str | None = None
    actual_value: str | None = None
    status: str | None = None
    severity: str | None = None
    source: str | None = None
    raw_data: dict[str, Any] = field(default_factory=dict)
    created_at: datetime | None = None


@dataclass
class RecommendationStats:
    """aggregated security recommendation statistics."""

    total: int = 0
    by_category: dict[str, int] = field(default_factory=dict)
    by_status: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)


@dataclass
class PocExecution:
    """one PoC candidate and its sandbox outcome during execution tests.

    sandbox and sandbox_error are mutually exclusive: a run that
    reached the VM fills sandbox, any earlier failure (compile/build/
    sandbox start) fills sandbox_error, and both stay None when no
    local checkout was available.
    """

    url: str = ""
    language: str = ""
    stars: int = 0
    compile_cmd: str = ""
    test_cmd: str = ""
    sandbox: SandboxRunResult | None = None
    sandbox_error: str | None = None


@dataclass
class CveExecution:
    """one CVE with the PoC executions attempted for it."""

    cve_id: str = ""
    description: str = ""
    cvss_v3_score: float | None = None
    severity: str = ""
    sources: list[str] = field(default_factory=list)
    pocs: list[PocExecution] = field(default_factory=list)


@dataclass
class ExecutionReport:
    """typed output of the execution-tests run.

    build_date is the formatted string the presentation layers print
    directly; stats mirrors the aggregate row from the DB.
    """

    kernel: str = ""
    build_date: str | None = None
    cves_processed: int = 0
    stats: Statistics = field(default_factory=Statistics)
    entries: list[CveExecution] = field(default_factory=list)