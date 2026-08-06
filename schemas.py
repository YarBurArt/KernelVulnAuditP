from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class KernelAuditItem:
    """raw lynis audit item (legacy, kept for recon compat)"""

    test_id: str
    category: str
    desc: str
    field: str
    prefval: str
    value: str


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

    @classmethod
    def from_kernel_audit(cls, item: KernelAuditItem) -> SecurityRecommendationType:
        """convert KernelAuditItem to SecurityRecommendation"""
        status = "OK"
        severity = "INFO"

        raw = item.raw_data if hasattr(item, "raw_data") else {}
        warning = raw.get("warning", "")
        suggestion = raw.get("suggestion", "")
        solution = raw.get("solution", "")

        desc = item.desc
        if solution:
            status = "FAIL"
            severity = "HIGH"
            desc = solution
        elif warning or suggestion:
            status = "WARNING"
            severity = "MEDIUM"
            if suggestion and not desc:
                desc = suggestion

        return cls(
            test_id=item.test_id,
            category=item.category,
            description=desc,
            field_name=item.field,
            expected_value=item.prefval,
            actual_value=item.value,
            status=status,
            severity=severity,
            source="lynis",
            raw_data=raw,
        )

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> SecurityRecommendationType:
        """create from lynis-style dict"""
        item = KernelAuditItem(
            test_id=data.get("test_id", ""),
            category=data.get("category", ""),
            desc=data.get("desc", "") or data.get("description", ""),
            field=data.get("field", ""),
            prefval=data.get("prefval", ""),
            value=data.get("value", ""),
        )
        rec = cls.from_kernel_audit(item)
        rec.raw_data.update(data)
        return rec


@dataclass
class KernelLPE:
    os: str = ""
    user_groups: str = ""
    hostname: str = ""
    cves: list[str] = field(default_factory=list)


@dataclass
class LesCVEItem:
    cve_id: str = ""
    title: str = ""
    details: str = ""
    exposure: str = ""
    tags: list[str] = field(default_factory=list)
    download_urls: list[str] = field(default_factory=list)
    comments: str = ""


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
class LocalReconResult:
    kernel: str = ""
    system: str = ""
    build_date: int = 0
    kernel_lpe: KernelLPE = field(default_factory=KernelLPE)
    possible_cves: list[LesCVEItem] = field(default_factory=list)
    security_recommendations: list[SecurityRecommendationType] = field(
        default_factory=list
    )
    selinux_booleans: list[HostSELinuxBoolean] = field(default_factory=list)
    file_capabilities: list[HostFileCapabilities] = field(default_factory=list)
    process_capabilities: list[HostProcessCapabilities] = field(
        default_factory=list
    )
    selinux_hardening: list[SecurityRecommendationType] = field(
        default_factory=list
    )
    capability_hardening: list[SecurityRecommendationType] = field(
        default_factory=list
    )


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


@dataclass
class HostInfoData:
    """host environment snapshot transfer type (matches DB host_info).

    ID/timestamps are managed by the DB layer. Scalar fields mirror the
    host_info columns; each collection mirrors a child table.
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
        """serialize to a JSON-safe dict (mirrors the ORM HostInfo.to_dict)."""
        result = asdict(self)
        for key in ("captured_at", "created_at", "updated_at"):
            value = result.get(key)
            if isinstance(value, datetime):
                result[key] = value.isoformat()
        for user in result.get("users", []):
            if isinstance(user.get("last_login"), datetime):
                user["last_login"] = user["last_login"].isoformat()
        return result


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
class FeedsReconResult:
    findings: list[CVEFinding] = field(default_factory=list)
    pocs: list[GitHubPoC] = field(default_factory=list)


@dataclass
class ReconResult:
    local: LocalReconResult = field(default_factory=LocalReconResult)
    feeds: FeedsReconResult = field(default_factory=FeedsReconResult)
