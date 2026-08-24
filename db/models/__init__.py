from sqlalchemy.orm import DeclarativeBase

from db.models.host import (
    HostBootParameter,
    HostCgroup,
    HostEnvironmentVariable,
    HostFile,
    HostFileCapabilities,
    HostGroup,
    HostGroupMember,
    HostInfo,
    HostKernelHardening,
    HostKernelModule,
    HostKernelParameter,
    HostNamespace,
    HostProcess,
    HostProcessCapabilities,
    HostSELinuxBoolean,
    HostUser,
)
from db.models.recommendation import SecurityRecommendation
from db.models.vulnerability import (
    AffectedProduct,
    CISAKEVEntry,
    Exploit,
    Reference,
    SandboxRun,
    Vulnerability,
)


class Base(DeclarativeBase):
    pass


__all__ = [
    "AffectedProduct",
    "Base",
    "CISAKEVEntry",
    "Exploit",
    "HostBootParameter",
    "HostCgroup",
    "HostEnvironmentVariable",
    "HostFile",
    "HostFileCapabilities",
    "HostGroup",
    "HostGroupMember",
    "HostInfo",
    "HostKernelHardening",
    "HostKernelModule",
    "HostKernelParameter",
    "HostNamespace",
    "HostProcess",
    "HostProcessCapabilities",
    "HostSELinuxBoolean",
    "HostUser",
    "Reference",
    "SandboxRun",
    "SecurityRecommendation",
    "Vulnerability",
]
