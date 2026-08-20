from dataclasses import MISSING, asdict, fields
from typing import Any

from sqlalchemy.orm import Session, selectinload

from core import entities
from core.entities import HostInfo
from db.models import (
    HostBootParameter,
    HostCgroup,
    HostEnvironmentVariable,
    HostFile,
    HostFileCapabilities,
    HostGroup,
    HostGroupMember,
    HostKernelHardening,
    HostKernelModule,
    HostKernelParameter,
    HostNamespace,
    HostProcess,
    HostProcessCapabilities,
    HostSELinuxBoolean,
    HostUser,
)
from db.models import (
    HostInfo as HostInfoRow,
)


def entity_write_dict(record: Any) -> dict[str, Any]:
    """Flatten a core entity into the dict form the backends persist.

    Fields left at their dataclass default are treated as "not provided" and
    omitted, so a partial upsert never wipes previously stored columns.
    """
    out: dict[str, Any] = {}
    for key, value in asdict(record).items():
        info = record.__dataclass_fields__[key]
        if info.default is not MISSING:
            default = info.default
        elif info.default_factory is not MISSING:
            default = info.default_factory()
        else:
            # required field (no default) — always part of the write
            out[key] = value
            continue
        if value != default:
            out[key] = value
    return out


def build_host_row(host_data: HostInfo) -> HostInfoRow:
    """map scalar host fields to a HostInfo row."""
    return HostInfoRow(
        captured_at=host_data.captured_at,
        hostname=host_data.hostname or None,
        kernel_version=host_data.kernel_version or None,
        kernel_release=host_data.kernel_release or None,
        kernel_build=host_data.kernel_build or None,
        kernel_name=host_data.kernel_name or None,
        machine=host_data.machine or None,
        platform_release=host_data.platform_release or None,
        platform_system=host_data.platform_system or None,
        platform_version=host_data.platform_version or None,
        platform=host_data.platform or None,
        proc_version=host_data.proc_version or None,
        node=host_data.node or None,
        processor=host_data.processor or None,
        architecture=host_data.architecture or None,
        distribution=host_data.distribution or None,
        current_directory=host_data.current_directory or None,
        username=host_data.username or None,
        home_dir=host_data.home_dir or None,
        boot_cmdline=host_data.boot_cmdline or None,
        selinux_enabled=host_data.selinux_enabled,
        selinux_status=host_data.selinux_status or None,
        selinux_policy=host_data.selinux_policy or None,
        selinux_mode=host_data.selinux_mode or None,
        selinux_mount=host_data.selinux_mount or None,
        notes=host_data.notes or None,
    )


def add_environment_variables(
    session: Session,
    host_id: int,
    items: list[entities.HostEnvironmentVariable],
) -> None:
    session.add_all(
        HostEnvironmentVariable(host_info_id=host_id, name=v.name, value=v.value)
        for v in items
    )


def add_kernel_parameters(
    session: Session,
    host_id: int,
    items: list[entities.HostKernelParameter],
) -> None:
    session.add_all(
        HostKernelParameter(
            host_info_id=host_id,
            parameter_name=p.parameter_name,
            parameter_value=p.parameter_value,
        )
        for p in items
    )


def add_boot_parameters(
    session: Session,
    host_id: int,
    items: list[entities.HostBootParameter],
) -> None:
    session.add_all(
        HostBootParameter(
            host_info_id=host_id,
            parameter_name=p.parameter_name,
            parameter_value=p.parameter_value,
        )
        for p in items
    )


def add_kernel_modules(
    session: Session,
    host_id: int,
    items: list[entities.HostKernelModule],
) -> None:
    session.add_all(
        HostKernelModule(
            host_info_id=host_id,
            module_name=m.module_name,
            size=m.size,
            refcount=m.refcount,
            used_by=m.used_by,
            state=m.state,
            address=m.address,
        )
        for m in items
    )


def add_kernel_hardening(
    session: Session,
    host_id: int,
    items: list[entities.HostKernelHardening],
) -> None:
    session.add_all(
        HostKernelHardening(
            host_info_id=host_id,
            test_id=h.test_id or "KRNL-6000",
            category=h.category,
            description=h.description,
            field_name=h.field_name,
            expected_value=h.expected_value,
            actual_value=h.actual_value,
            status=h.status,
            severity=h.severity,
            related=h.related,
            solution=h.solution,
            details=h.details,
        )
        for h in items
    )


def add_selinux_booleans(
    session: Session,
    host_id: int,
    items: list[entities.HostSELinuxBoolean],
) -> None:
    session.add_all(
        HostSELinuxBoolean(
            host_info_id=host_id,
            boolean_name=b.boolean_name,
            value=b.value,
        )
        for b in items
    )


def add_users(
    session: Session,
    host_id: int,
    items: list[entities.HostUser],
) -> None:
    session.add_all(
        HostUser(
            host_info_id=host_id,
            username=u.username,
            uid=u.uid,
            gid=u.gid,
            home_dir=u.home_dir,
            shell=u.shell,
            gecos=u.gecos,
            last_login=u.last_login,
            locked=u.locked,
        )
        for u in items
    )


def add_groups(
    session: Session,
    host_id: int,
    items: list[entities.HostGroup],
) -> None:
    for group in items:
        grp = HostGroup(
            host_info_id=host_id, group_name=group.group_name, gid=group.gid
        )
        session.add(grp)
        session.flush()
        session.add_all(
            HostGroupMember(host_group_id=grp.id, username=member)
            for member in group.members
        )


def add_namespaces(
    session: Session,
    host_id: int,
    items: list[entities.HostNamespace],
) -> None:
    session.add_all(
        HostNamespace(
            host_info_id=host_id,
            pid=n.pid,
            process_name=n.process_name,
            namespace_type=n.namespace_type,
            inode=n.inode,
        )
        for n in items
    )


def add_cgroups(
    session: Session,
    host_id: int,
    items: list[entities.HostCgroup],
) -> None:
    session.add_all(
        HostCgroup(
            host_info_id=host_id,
            pid=c.pid,
            process_name=c.process_name,
            hierarchy_id=c.hierarchy_id,
            path=c.path,
            controllers=c.controllers,
            cgroup_version=c.cgroup_version,
        )
        for c in items
    )


def add_processes(
    session: Session,
    host_id: int,
    items: list[entities.HostProcess],
) -> None:
    session.add_all(
        HostProcess(
            host_info_id=host_id,
            pid=p.pid,
            ppid=p.ppid,
            name=p.name,
            username=p.username,
            executable=p.executable,
            cmdline=p.cmdline,
            cwd=p.cwd,
            state=p.state,
            is_root=p.is_root,
            notable=p.notable,
        )
        for p in items
    )


def add_files(
    session: Session,
    host_id: int,
    items: list[entities.HostFile],
) -> None:
    session.add_all(
        HostFile(
            host_info_id=host_id,
            path=f.path,
            file_type=f.file_type,
            mode=f.mode,
            owner_uid=f.owner_uid,
            owner_name=f.owner_name,
            group_gid=f.group_gid,
            group_name=f.group_name,
            size=f.size,
            suid=f.suid,
            sgid=f.sgid,
            sticky=f.sticky,
            world_writable=f.world_writable,
            user_writable=f.user_writable,
            group_writable=f.group_writable,
            readable=f.readable,
            executable=f.executable,
            symlink_target=f.symlink_target,
            notable=f.notable,
        )
        for f in items
    )


def add_file_capabilities(
    session: Session,
    host_id: int,
    items: list[entities.HostFileCapabilities],
) -> None:
    session.add_all(
        HostFileCapabilities(
            host_info_id=host_id,
            path=fc.path,
            owner_name=fc.owner_name,
            cap_effective=fc.cap_effective,
            cap_permitted=fc.cap_permitted,
            cap_inheritable=fc.cap_inheritable,
            cap_bounding=fc.cap_bounding,
            cap_ambient=fc.cap_ambient,
        )
        for fc in items
    )


def add_process_capabilities(
    session: Session,
    host_id: int,
    items: list[entities.HostProcessCapabilities],
) -> None:
    session.add_all(
        HostProcessCapabilities(
            host_info_id=host_id,
            pid=pc.pid,
            process_name=pc.process_name,
            username=pc.username,
            cap_effective=pc.cap_effective,
            cap_permitted=pc.cap_permitted,
            cap_inheritable=pc.cap_inheritable,
            cap_bounding=pc.cap_bounding,
            cap_ambient=pc.cap_ambient,
            secbits=pc.secbits,
            no_new_privs=pc.no_new_privs,
        )
        for pc in items
    )


def add_children(
    session: Session,
    host_id: int,
    host_data: HostInfo,
) -> None:
    """persist every host data category as child rows under host_id."""
    add_environment_variables(session, host_id, host_data.environment_variables)
    add_kernel_parameters(session, host_id, host_data.kernel_parameters)
    add_boot_parameters(session, host_id, host_data.boot_parameters)
    add_kernel_modules(session, host_id, host_data.kernel_modules)
    add_kernel_hardening(session, host_id, host_data.kernel_hardening)
    add_selinux_booleans(session, host_id, host_data.selinux_booleans)
    add_users(session, host_id, host_data.users)
    add_groups(session, host_id, host_data.groups)
    add_namespaces(session, host_id, host_data.namespaces)
    add_cgroups(session, host_id, host_data.cgroups)
    add_processes(session, host_id, host_data.processes)
    add_files(session, host_id, host_data.files)
    add_file_capabilities(session, host_id, host_data.file_capabilities)
    add_process_capabilities(session, host_id, host_data.process_capabilities)


def build_host_model(session: Session, host_data: HostInfo) -> HostInfoRow:
    """map a HostInfo entity to a HostInfo row plus child rows."""
    _check_child_types(host_data)
    host = build_host_row(host_data)
    session.add(host)
    session.flush()
    add_children(session, host.id, host_data)
    return host


def _check_child_types(host_data: HostInfo) -> None:
    """fail fast with a clear error before any rows are written.

    HostInfo children are typed collections of core entities; a stray
    dict (or any other object) reaching the mapper would otherwise surface
    as an opaque AttributeError deep inside a child builder.
    """
    from typing import get_args, get_origin

    for field_info in fields(HostInfo):
        value = getattr(host_data, field_info.name)
        origin = get_origin(field_info.type)
        if origin is not list or not value:
            continue
        expected = get_args(field_info.type)[0]
        for item in value:
            if not isinstance(item, expected):
                raise TypeError(
                    f"host_data.{field_info.name} must contain {expected.__name__} "
                    f"items, got {type(item).__name__}"
                )


def query_host_with_children(session: Session) -> Any:
    return session.query(HostInfoRow).options(
        selectinload(HostInfoRow.environment_variables),
        selectinload(HostInfoRow.kernel_parameters),
        selectinload(HostInfoRow.boot_parameters),
        selectinload(HostInfoRow.kernel_modules),
        selectinload(HostInfoRow.kernel_hardening),
        selectinload(HostInfoRow.selinux_booleans),
        selectinload(HostInfoRow.users),
        selectinload(HostInfoRow.groups).selectinload(HostGroup.members),
        selectinload(HostInfoRow.namespaces),
        selectinload(HostInfoRow.cgroups),
        selectinload(HostInfoRow.processes),
        selectinload(HostInfoRow.files),
        selectinload(HostInfoRow.file_capabilities),
        selectinload(HostInfoRow.process_capabilities),
    )


def host_header(host: HostInfoRow) -> HostInfo:
    """map scalar HostInfo fields only (no child rows)."""
    return HostInfo(
        id=host.id,
        captured_at=host.captured_at,
        created_at=host.created_at,
        updated_at=host.updated_at,
        hostname=host.hostname or "",
        kernel_version=host.kernel_version or "",
        kernel_release=host.kernel_release or "",
        kernel_build=host.kernel_build or "",
        kernel_name=host.kernel_name or "",
        machine=host.machine or "",
        platform_release=host.platform_release or "",
        platform_system=host.platform_system or "",
        platform_version=host.platform_version or "",
        platform=host.platform or "",
        proc_version=host.proc_version or "",
        node=host.node or "",
        processor=host.processor or "",
        architecture=host.architecture or "",
        distribution=host.distribution or "",
        current_directory=host.current_directory or "",
        username=host.username or "",
        home_dir=host.home_dir or "",
        boot_cmdline=host.boot_cmdline or "",
        selinux_enabled=host.selinux_enabled,
        selinux_status=host.selinux_status or "",
        selinux_policy=host.selinux_policy or "",
        selinux_mode=host.selinux_mode or "",
        selinux_mount=host.selinux_mount or "",
        notes=host.notes or "",
    )


def environment_variables_to_data(
    rows: list[HostEnvironmentVariable],
) -> list[entities.HostEnvironmentVariable]:
    return [
        entities.HostEnvironmentVariable(name=v.name, value=v.value or "") for v in rows
    ]


def kernel_parameters_to_data(
    rows: list[HostKernelParameter],
) -> list[entities.HostKernelParameter]:
    return [
        entities.HostKernelParameter(
            parameter_name=p.parameter_name, parameter_value=p.parameter_value or ""
        )
        for p in rows
    ]


def boot_parameters_to_data(
    rows: list[HostBootParameter],
) -> list[entities.HostBootParameter]:
    return [
        entities.HostBootParameter(
            parameter_name=p.parameter_name, parameter_value=p.parameter_value or ""
        )
        for p in rows
    ]


def kernel_modules_to_data(
    rows: list[HostKernelModule],
) -> list[entities.HostKernelModule]:
    return [
        entities.HostKernelModule(
            module_name=m.module_name,
            size=m.size,
            refcount=m.refcount,
            used_by=m.used_by,
            state=m.state,
            address=m.address,
        )
        for m in rows
    ]


def kernel_hardening_to_data(
    rows: list[HostKernelHardening],
) -> list[entities.HostKernelHardening]:
    return [
        entities.HostKernelHardening(
            test_id=h.test_id,
            category=h.category or "",
            description=h.description or "",
            field_name=h.field_name or "",
            expected_value=h.expected_value or "",
            actual_value=h.actual_value or "",
            status=h.status or "",
            severity=h.severity or "",
            related=h.related or "",
            solution=h.solution or "",
            details=h.details or "",
        )
        for h in rows
    ]


def selinux_booleans_to_data(
    rows: list[HostSELinuxBoolean],
) -> list[entities.HostSELinuxBoolean]:
    return [
        entities.HostSELinuxBoolean(boolean_name=b.boolean_name, value=b.value)
        for b in rows
    ]


def users_to_data(rows: list[HostUser]) -> list[entities.HostUser]:
    return [
        entities.HostUser(
            username=u.username,
            uid=u.uid,
            gid=u.gid,
            home_dir=u.home_dir,
            shell=u.shell,
            gecos=u.gecos,
            last_login=u.last_login,
            locked=u.locked,
        )
        for u in rows
    ]


def groups_to_data(rows: list[HostGroup]) -> list[entities.HostGroup]:
    return [
        entities.HostGroup(
            group_name=g.group_name,
            gid=g.gid,
            members=[m.username for m in g.members],
        )
        for g in rows
    ]


def namespaces_to_data(
    rows: list[HostNamespace],
) -> list[entities.HostNamespace]:
    return [
        entities.HostNamespace(
            pid=n.pid,
            process_name=n.process_name or "",
            namespace_type=n.namespace_type,
            inode=n.inode or "",
        )
        for n in rows
    ]


def cgroups_to_data(rows: list[HostCgroup]) -> list[entities.HostCgroup]:
    return [
        entities.HostCgroup(
            pid=c.pid,
            path=c.path,
            process_name=c.process_name or "",
            hierarchy_id=c.hierarchy_id,
            controllers=c.controllers or "",
            cgroup_version=c.cgroup_version,
        )
        for c in rows
    ]


def processes_to_data(rows: list[HostProcess]) -> list[entities.HostProcess]:
    return [
        entities.HostProcess(
            pid=p.pid,
            ppid=p.ppid,
            name=p.name or "",
            username=p.username,
            executable=p.executable,
            cmdline=p.cmdline,
            cwd=p.cwd,
            state=p.state,
            is_root=p.is_root,
            notable=p.notable,
        )
        for p in rows
    ]


def files_to_data(rows: list[HostFile]) -> list[entities.HostFile]:
    return [
        entities.HostFile(
            path=f.path,
            file_type=f.file_type,
            mode=f.mode,
            owner_uid=f.owner_uid,
            owner_name=f.owner_name,
            group_gid=f.group_gid,
            group_name=f.group_name,
            size=f.size,
            suid=f.suid or False,
            sgid=f.sgid or False,
            sticky=f.sticky or False,
            world_writable=f.world_writable or False,
            user_writable=f.user_writable or False,
            group_writable=f.group_writable or False,
            readable=f.readable or False,
            executable=f.executable or False,
            symlink_target=f.symlink_target,
            notable=f.notable or False,
        )
        for f in rows
    ]


def file_capabilities_to_data(
    rows: list[HostFileCapabilities],
) -> list[entities.HostFileCapabilities]:
    return [
        entities.HostFileCapabilities(
            path=fc.path,
            owner_name=fc.owner_name,
            cap_effective=fc.cap_effective,
            cap_permitted=fc.cap_permitted,
            cap_inheritable=fc.cap_inheritable,
            cap_bounding=fc.cap_bounding,
            cap_ambient=fc.cap_ambient,
        )
        for fc in rows
    ]


def process_capabilities_to_data(
    rows: list[HostProcessCapabilities],
) -> list[entities.HostProcessCapabilities]:
    return [
        entities.HostProcessCapabilities(
            pid=pc.pid,
            process_name=pc.process_name or "",
            username=pc.username,
            cap_effective=pc.cap_effective,
            cap_permitted=pc.cap_permitted,
            cap_inheritable=pc.cap_inheritable,
            cap_bounding=pc.cap_bounding,
            cap_ambient=pc.cap_ambient,
            secbits=pc.secbits,
            no_new_privs=pc.no_new_privs,
        )
        for pc in rows
    ]


def to_data(host: HostInfoRow, include_children: bool = True) -> HostInfo:
    data = host_header(host)
    if not include_children:
        return data
    data.environment_variables = environment_variables_to_data(
        host.environment_variables
    )
    data.kernel_parameters = kernel_parameters_to_data(host.kernel_parameters)
    data.boot_parameters = boot_parameters_to_data(host.boot_parameters)
    data.kernel_modules = kernel_modules_to_data(host.kernel_modules)
    data.kernel_hardening = kernel_hardening_to_data(host.kernel_hardening)
    data.selinux_booleans = selinux_booleans_to_data(host.selinux_booleans)
    data.users = users_to_data(host.users)
    data.groups = groups_to_data(host.groups)
    data.namespaces = namespaces_to_data(host.namespaces)
    data.cgroups = cgroups_to_data(host.cgroups)
    data.processes = processes_to_data(host.processes)
    data.files = files_to_data(host.files)
    data.file_capabilities = file_capabilities_to_data(host.file_capabilities)
    data.process_capabilities = process_capabilities_to_data(
        host.process_capabilities
    )
    return data