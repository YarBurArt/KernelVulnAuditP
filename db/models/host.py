from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import (
    Mapped,
    mapped_column,
    relationship,
)

from db.models import Base


class HostEnvironmentVariable(Base):
    """environment variable captured from os.environ"""

    __tablename__ = "host_environment_variables"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host_info_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("host_info.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    value: Mapped[str | None] = mapped_column(Text)

    host_info: Mapped[HostInfo] = relationship(back_populates="environment_variables")

    __table_args__ = (
        UniqueConstraint("host_info_id", "name", name="uq_host_env_var"),
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "host_info_id": self.host_info_id,
            "name": self.name,
            "value": self.value,
        }


class HostKernelParameter(Base):
    """sysctl kernel parameter from /proc/sys"""

    __tablename__ = "host_kernel_parameters"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host_info_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("host_info.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    parameter_name: Mapped[str] = mapped_column(String(255), nullable=False)
    parameter_value: Mapped[str | None] = mapped_column(String(500))

    host_info: Mapped[HostInfo] = relationship(back_populates="kernel_parameters")

    __table_args__ = (
        UniqueConstraint("host_info_id", "parameter_name", name="uq_host_kernel_param"),
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "host_info_id": self.host_info_id,
            "parameter_name": self.parameter_name,
            "parameter_value": self.parameter_value,
        }


class HostBootParameter(Base):
    """kernel command-line parameter parsed from /proc/cmdline"""

    __tablename__ = "host_boot_parameters"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host_info_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("host_info.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    parameter_name: Mapped[str] = mapped_column(String(255), nullable=False)
    parameter_value: Mapped[str | None] = mapped_column(String(1000))

    host_info: Mapped[HostInfo] = relationship(back_populates="boot_parameters")

    __table_args__ = (
        UniqueConstraint("host_info_id", "parameter_name", name="uq_host_boot_param"),
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "host_info_id": self.host_info_id,
            "parameter_name": self.parameter_name,
            "parameter_value": self.parameter_value,
        }


class HostKernelModule(Base):
    """loaded kernel module from /proc/modules"""

    __tablename__ = "host_kernel_modules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host_info_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("host_info.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    module_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    size: Mapped[int | None] = mapped_column(Integer)
    refcount: Mapped[int | None] = mapped_column(Integer)
    used_by: Mapped[str | None] = mapped_column(String(500))
    state: Mapped[str | None] = mapped_column(String(50))
    address: Mapped[str | None] = mapped_column(String(50))

    host_info: Mapped[HostInfo] = relationship(back_populates="kernel_modules")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "host_info_id": self.host_info_id,
            "module_name": self.module_name,
            "size": self.size,
            "refcount": self.refcount,
            "used_by": self.used_by,
            "state": self.state,
            "address": self.address,
        }


class HostKernelHardening(Base):
    """kernel hardening recommendation from lynis params.prf"""

    __tablename__ = "host_kernel_hardening"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host_info_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("host_info.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    test_id: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    category: Mapped[str | None] = mapped_column(String(100))
    description: Mapped[str | None] = mapped_column(Text)
    field_name: Mapped[str | None] = mapped_column(String(255))
    expected_value: Mapped[str | None] = mapped_column(Text)
    actual_value: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str | None] = mapped_column(String(50))
    severity: Mapped[str | None] = mapped_column(String(50))
    related: Mapped[str | None] = mapped_column(Text)
    solution: Mapped[str | None] = mapped_column(Text)
    details: Mapped[str | None] = mapped_column(Text)

    host_info: Mapped[HostInfo] = relationship(back_populates="kernel_hardening")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "host_info_id": self.host_info_id,
            "test_id": self.test_id,
            "category": self.category,
            "description": self.description,
            "field_name": self.field_name,
            "expected_value": self.expected_value,
            "actual_value": self.actual_value,
            "status": self.status,
            "severity": self.severity,
            "related": self.related,
            "solution": self.solution,
            "details": self.details,
        }


class HostSELinuxBoolean(Base):
    """SELinux boolean toggle"""

    __tablename__ = "host_selinux_booleans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host_info_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("host_info.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    boolean_name: Mapped[str] = mapped_column(String(255), nullable=False)
    value: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    host_info: Mapped[HostInfo] = relationship(back_populates="selinux_booleans")

    __table_args__ = (
        UniqueConstraint("host_info_id", "boolean_name", name="uq_host_selinux_bool"),
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "host_info_id": self.host_info_id,
            "boolean_name": self.boolean_name,
            "value": self.value,
        }


class HostUser(Base):
    """user account from /etc/passwd"""

    __tablename__ = "host_users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host_info_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("host_info.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    username: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    uid: Mapped[int | None] = mapped_column(Integer)
    gid: Mapped[int | None] = mapped_column(Integer)
    home_dir: Mapped[str | None] = mapped_column(String(1000))
    shell: Mapped[str | None] = mapped_column(String(255))
    gecos: Mapped[str | None] = mapped_column(String(500))
    last_login: Mapped[datetime | None] = mapped_column(DateTime)
    locked: Mapped[bool | None] = mapped_column(Boolean)

    host_info: Mapped[HostInfo] = relationship(back_populates="users")

    __table_args__ = (
        UniqueConstraint("host_info_id", "username", name="uq_host_user"),
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "host_info_id": self.host_info_id,
            "username": self.username,
            "uid": self.uid,
            "gid": self.gid,
            "home_dir": self.home_dir,
            "shell": self.shell,
            "gecos": self.gecos,
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "locked": self.locked,
        }


class HostGroup(Base):
    """group from /etc/group"""

    __tablename__ = "host_groups"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host_info_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("host_info.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    group_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    gid: Mapped[int | None] = mapped_column(Integer)

    host_info: Mapped[HostInfo] = relationship(back_populates="groups")
    members: Mapped[list[HostGroupMember]] = relationship(
        back_populates="group",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        UniqueConstraint("host_info_id", "group_name", name="uq_host_group"),
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "host_info_id": self.host_info_id,
            "group_name": self.group_name,
            "gid": self.gid,
            "members": [m.to_dict() for m in self.members],
        }


class HostGroupMember(Base):
    """membership of a user in a host group"""

    __tablename__ = "host_group_members"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host_group_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("host_groups.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    username: Mapped[str] = mapped_column(String(100), nullable=False)

    group: Mapped[HostGroup] = relationship(back_populates="members")

    __table_args__ = (
        UniqueConstraint("host_group_id", "username", name="uq_host_group_member"),
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "host_group_id": self.host_group_id,
            "username": self.username,
        }


class HostNamespace(Base):
    """namespace attachment of a process (/proc/<pid>/ns/*)"""

    __tablename__ = "host_namespaces"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host_info_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("host_info.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    pid: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    process_name: Mapped[str | None] = mapped_column(String(255))
    namespace_type: Mapped[str] = mapped_column(String(50), nullable=False)
    inode: Mapped[str | None] = mapped_column(String(50))

    host_info: Mapped[HostInfo] = relationship(back_populates="namespaces")

    __table_args__ = (
        UniqueConstraint(
            "host_info_id", "pid", "namespace_type", name="uq_host_namespace"
        ),
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "host_info_id": self.host_info_id,
            "pid": self.pid,
            "process_name": self.process_name,
            "namespace_type": self.namespace_type,
            "inode": self.inode,
        }


class HostCgroup(Base):
    """cgroup attachment of a process"""

    __tablename__ = "host_cgroups"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host_info_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("host_info.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    pid: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    process_name: Mapped[str | None] = mapped_column(String(255))
    hierarchy_id: Mapped[int | None] = mapped_column(Integer)
    path: Mapped[str] = mapped_column(String(1000), nullable=False)
    controllers: Mapped[str | None] = mapped_column(String(500))
    cgroup_version: Mapped[int | None] = mapped_column(Integer)

    host_info: Mapped[HostInfo] = relationship(back_populates="cgroups")

    __table_args__ = (
        UniqueConstraint("host_info_id", "pid", "path", name="uq_host_cgroup"),
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "host_info_id": self.host_info_id,
            "pid": self.pid,
            "process_name": self.process_name,
            "hierarchy_id": self.hierarchy_id,
            "path": self.path,
            "controllers": self.controllers,
            "cgroup_version": self.cgroup_version,
        }


class HostProcess(Base):
    """interesting process found during recon"""

    __tablename__ = "host_processes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host_info_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("host_info.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    pid: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    ppid: Mapped[int | None] = mapped_column(Integer)
    name: Mapped[str | None] = mapped_column(String(255))
    username: Mapped[str | None] = mapped_column(String(100))
    executable: Mapped[str | None] = mapped_column(String(1000))
    cmdline: Mapped[str | None] = mapped_column(Text)
    cwd: Mapped[str | None] = mapped_column(String(1000))
    state: Mapped[str | None] = mapped_column(String(20))
    is_root: Mapped[bool | None] = mapped_column(Boolean)
    notable: Mapped[bool | None] = mapped_column(Boolean)

    host_info: Mapped[HostInfo] = relationship(back_populates="processes")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "host_info_id": self.host_info_id,
            "pid": self.pid,
            "ppid": self.ppid,
            "name": self.name,
            "username": self.username,
            "executable": self.executable,
            "cmdline": self.cmdline,
            "cwd": self.cwd,
            "state": self.state,
            "is_root": self.is_root,
            "notable": self.notable,
        }


class HostFile(Base):
    """interesting file found during recon"""

    __tablename__ = "host_files"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host_info_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("host_info.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    path: Mapped[str] = mapped_column(String(2000), nullable=False, index=True)
    file_type: Mapped[str | None] = mapped_column(String(50))
    mode: Mapped[str | None] = mapped_column(String(20))
    owner_uid: Mapped[int | None] = mapped_column(Integer)
    owner_name: Mapped[str | None] = mapped_column(String(100))
    group_gid: Mapped[int | None] = mapped_column(Integer)
    group_name: Mapped[str | None] = mapped_column(String(100))
    size: Mapped[int | None] = mapped_column(Integer)
    suid: Mapped[bool] = mapped_column(Boolean, default=False)
    sgid: Mapped[bool] = mapped_column(Boolean, default=False)
    sticky: Mapped[bool] = mapped_column(Boolean, default=False)
    world_writable: Mapped[bool] = mapped_column(Boolean, default=False)
    user_writable: Mapped[bool] = mapped_column(Boolean, default=False)
    group_writable: Mapped[bool] = mapped_column(Boolean, default=False)
    readable: Mapped[bool] = mapped_column(Boolean, default=False)
    executable: Mapped[bool] = mapped_column(Boolean, default=False)
    symlink_target: Mapped[str | None] = mapped_column(String(2000))
    notable: Mapped[bool] = mapped_column(Boolean, default=False)

    host_info: Mapped[HostInfo] = relationship(back_populates="files")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "host_info_id": self.host_info_id,
            "path": self.path,
            "file_type": self.file_type,
            "mode": self.mode,
            "owner_uid": self.owner_uid,
            "owner_name": self.owner_name,
            "group_gid": self.group_gid,
            "group_name": self.group_name,
            "size": self.size,
            "suid": self.suid,
            "sgid": self.sgid,
            "sticky": self.sticky,
            "world_writable": self.world_writable,
            "user_writable": self.user_writable,
            "group_writable": self.group_writable,
            "readable": self.readable,
            "executable": self.executable,
            "symlink_target": self.symlink_target,
            "notable": self.notable,
        }


class HostFileCapabilities(Base):
    """file with security capabilities (getcap output)"""

    __tablename__ = "host_file_capabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host_info_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("host_info.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    path: Mapped[str] = mapped_column(String(2000), nullable=False, index=True)
    owner_name: Mapped[str | None] = mapped_column(String(100))
    cap_effective: Mapped[str | None] = mapped_column(String(100))
    cap_permitted: Mapped[str | None] = mapped_column(String(100))
    cap_inheritable: Mapped[str | None] = mapped_column(String(100))
    cap_bounding: Mapped[str | None] = mapped_column(String(100))
    cap_ambient: Mapped[str | None] = mapped_column(String(100))

    host_info: Mapped[HostInfo] = relationship(back_populates="file_capabilities")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "host_info_id": self.host_info_id,
            "path": self.path,
            "owner_name": self.owner_name,
            "cap_effective": self.cap_effective,
            "cap_permitted": self.cap_permitted,
            "cap_inheritable": self.cap_inheritable,
            "cap_bounding": self.cap_bounding,
            "cap_ambient": self.cap_ambient,
        }


class HostProcessCapabilities(Base):
    """process capability masks (/proc/<pid>/status)"""

    __tablename__ = "host_process_capabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host_info_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("host_info.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    pid: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    process_name: Mapped[str | None] = mapped_column(String(255))
    username: Mapped[str | None] = mapped_column(String(100))
    cap_effective: Mapped[str | None] = mapped_column(String(100))
    cap_permitted: Mapped[str | None] = mapped_column(String(100))
    cap_inheritable: Mapped[str | None] = mapped_column(String(100))
    cap_bounding: Mapped[str | None] = mapped_column(String(100))
    cap_ambient: Mapped[str | None] = mapped_column(String(100))
    secbits: Mapped[str | None] = mapped_column(String(100))
    no_new_privs: Mapped[bool | None] = mapped_column(Boolean)

    host_info: Mapped[HostInfo] = relationship(back_populates="process_capabilities")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "host_info_id": self.host_info_id,
            "pid": self.pid,
            "process_name": self.process_name,
            "username": self.username,
            "cap_effective": self.cap_effective,
            "cap_permitted": self.cap_permitted,
            "cap_inheritable": self.cap_inheritable,
            "cap_bounding": self.cap_bounding,
            "cap_ambient": self.cap_ambient,
            "secbits": self.secbits,
            "no_new_privs": self.no_new_privs,
        }


class HostInfo(Base):
    """host environment snapshot collected by LocalRecon.

    Standalone snapshot table (no link to vulnerabilities), used by the
    report to explain why isolated vulnerability tests behave the way they
    do. Each collection maps to a child table holding typed columns.
    """

    __tablename__ = "host_info"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    captured_at: Mapped[datetime | None] = mapped_column(DateTime, index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), index=True)
    kernel_version: Mapped[str | None] = mapped_column(String(100), index=True)
    kernel_release: Mapped[str | None] = mapped_column(String(100))
    kernel_build: Mapped[str | None] = mapped_column(String(255))
    kernel_name: Mapped[str | None] = mapped_column(String(50))
    machine: Mapped[str | None] = mapped_column(String(50))
    platform_release: Mapped[str | None] = mapped_column(String(100))
    platform_system: Mapped[str | None] = mapped_column(String(50))
    platform_version: Mapped[str | None] = mapped_column(String(255))
    platform: Mapped[str | None] = mapped_column(String(255))
    proc_version: Mapped[str | None] = mapped_column(Text)
    node: Mapped[str | None] = mapped_column(String(255))
    processor: Mapped[str | None] = mapped_column(String(255))
    architecture: Mapped[str | None] = mapped_column(String(100))
    distribution: Mapped[str | None] = mapped_column(String(200))
    current_directory: Mapped[str | None] = mapped_column(String(1000))
    username: Mapped[str | None] = mapped_column(String(100))
    home_dir: Mapped[str | None] = mapped_column(String(1000))
    boot_cmdline: Mapped[str | None] = mapped_column(Text)
    selinux_enabled: Mapped[bool | None] = mapped_column(Boolean)
    selinux_status: Mapped[str | None] = mapped_column(String(50))
    selinux_policy: Mapped[str | None] = mapped_column(String(200))
    selinux_mode: Mapped[str | None] = mapped_column(String(50))
    selinux_mount: Mapped[str | None] = mapped_column(String(255))
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    environment_variables: Mapped[list[HostEnvironmentVariable]] = relationship(
        back_populates="host_info",
        cascade="all, delete-orphan",
    )
    kernel_parameters: Mapped[list[HostKernelParameter]] = relationship(
        back_populates="host_info",
        cascade="all, delete-orphan",
    )
    boot_parameters: Mapped[list[HostBootParameter]] = relationship(
        back_populates="host_info",
        cascade="all, delete-orphan",
    )
    kernel_modules: Mapped[list[HostKernelModule]] = relationship(
        back_populates="host_info",
        cascade="all, delete-orphan",
    )
    kernel_hardening: Mapped[list[HostKernelHardening]] = relationship(
        back_populates="host_info",
        cascade="all, delete-orphan",
    )
    selinux_booleans: Mapped[list[HostSELinuxBoolean]] = relationship(
        back_populates="host_info",
        cascade="all, delete-orphan",
    )
    users: Mapped[list[HostUser]] = relationship(
        back_populates="host_info",
        cascade="all, delete-orphan",
    )
    groups: Mapped[list[HostGroup]] = relationship(
        back_populates="host_info",
        cascade="all, delete-orphan",
    )
    namespaces: Mapped[list[HostNamespace]] = relationship(
        back_populates="host_info",
        cascade="all, delete-orphan",
    )
    cgroups: Mapped[list[HostCgroup]] = relationship(
        back_populates="host_info",
        cascade="all, delete-orphan",
    )
    processes: Mapped[list[HostProcess]] = relationship(
        back_populates="host_info",
        cascade="all, delete-orphan",
    )
    files: Mapped[list[HostFile]] = relationship(
        back_populates="host_info",
        cascade="all, delete-orphan",
    )
    file_capabilities: Mapped[list[HostFileCapabilities]] = relationship(
        back_populates="host_info",
        cascade="all, delete-orphan",
    )
    process_capabilities: Mapped[list[HostProcessCapabilities]] = relationship(
        back_populates="host_info",
        cascade="all, delete-orphan",
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "captured_at": self.captured_at.isoformat() if self.captured_at else None,
            "hostname": self.hostname,
            "kernel_version": self.kernel_version,
            "kernel_release": self.kernel_release,
            "kernel_build": self.kernel_build,
            "kernel_name": self.kernel_name,
            "machine": self.machine,
            "platform_release": self.platform_release,
            "platform_system": self.platform_system,
            "platform_version": self.platform_version,
            "platform": self.platform,
            "proc_version": self.proc_version,
            "node": self.node,
            "processor": self.processor,
            "architecture": self.architecture,
            "distribution": self.distribution,
            "current_directory": self.current_directory,
            "username": self.username,
            "home_dir": self.home_dir,
            "boot_cmdline": self.boot_cmdline,
            "selinux_enabled": self.selinux_enabled,
            "selinux_status": self.selinux_status,
            "selinux_policy": self.selinux_policy,
            "selinux_mode": self.selinux_mode,
            "selinux_mount": self.selinux_mount,
            "notes": self.notes,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "environment_variables": [e.to_dict() for e in self.environment_variables],
            "kernel_parameters": [p.to_dict() for p in self.kernel_parameters],
            "boot_parameters": [b.to_dict() for b in self.boot_parameters],
            "kernel_modules": [m.to_dict() for m in self.kernel_modules],
            "kernel_hardening": [h.to_dict() for h in self.kernel_hardening],
            "selinux_booleans": [b.to_dict() for b in self.selinux_booleans],
            "users": [u.to_dict() for u in self.users],
            "groups": [g.to_dict() for g in self.groups],
            "namespaces": [n.to_dict() for n in self.namespaces],
            "cgroups": [c.to_dict() for c in self.cgroups],
            "processes": [p.to_dict() for p in self.processes],
            "files": [f.to_dict() for f in self.files],
            "file_capabilities": [fc.to_dict() for fc in self.file_capabilities],
            "process_capabilities": [
                pc.to_dict() for pc in self.process_capabilities
            ],
        }
