from datetime import UTC, datetime

from schemas import (
    HostInfoData,
    HostUser,
    KernelAuditItem,
    SecurityRecommendationType,
)


def _kit(
    *,
    desc: str = "a check",
    field: str = "fs.suid_dumpable",
    prefval: str = "0",
    value: str = "2",
    raw: dict | None = None,
) -> KernelAuditItem:
    item = KernelAuditItem(
        test_id="KRNL-6000",
        category="kernel",
        desc=desc,
        field=field,
        prefval=prefval,
        value=value,
    )
    if raw is not None:
        item.raw_data = raw
    return item


def test_from_kernel_audit_defaults_to_ok():
    rec = SecurityRecommendationType.from_kernel_audit(_kit())

    assert rec.test_id == "KRNL-6000"
    assert rec.category == "kernel"
    assert rec.description == "a check"
    assert rec.field_name == "fs.suid_dumpable"
    assert rec.expected_value == "0"
    assert rec.actual_value == "2"
    assert rec.status == "OK"
    assert rec.severity == "INFO"
    assert rec.source == "lynis"
    assert rec.raw_data == {}


def test_from_kernel_audit_solution_promotes_to_fail():
    item = _kit(raw={"solution": "set fs.suid_dumpable=0"})
    rec = SecurityRecommendationType.from_kernel_audit(item)

    assert rec.status == "FAIL"
    assert rec.severity == "HIGH"
    assert rec.description == "set fs.suid_dumpable=0"
    assert rec.raw_data == {"solution": "set fs.suid_dumpable=0"}


def test_from_kernel_audit_warning_or_suggestion():
    rec = SecurityRecommendationType.from_kernel_audit(
        _kit(desc="", raw={"warning": "risk", "suggestion": "advice"})
    )

    assert rec.status == "WARNING"
    assert rec.severity == "MEDIUM"
    assert rec.description == "advice"


def test_from_kernel_audit_warning_without_suggestion_keeps_desc():
    rec = SecurityRecommendationType.from_kernel_audit(
        _kit(desc="existing desc", raw={"warning": "risk"})
    )

    assert rec.status == "WARNING"
    assert rec.severity == "MEDIUM"
    assert rec.description == "existing desc"


def test_from_kernel_audit_solution_wins_over_suggestion():
    rec = SecurityRecommendationType.from_kernel_audit(
        _kit(raw={"solution": "the fix", "suggestion": "advice"})
    )

    assert rec.status == "FAIL"
    assert rec.severity == "HIGH"
    assert rec.description == "the fix"


def test_from_dict_roundtrip():
    rec = SecurityRecommendationType.from_dict(
        {
            "test_id": "KRNL-7000",
            "category": "selinux",
            "description": "desc here",
            "field": "boolean",
            "prefval": "on",
            "value": "off",
            "source": "recon",
        }
    )

    assert rec.test_id == "KRNL-7000"
    assert rec.category == "selinux"
    assert rec.description == "desc here"
    assert rec.field_name == "boolean"
    assert rec.expected_value == "on"
    assert rec.actual_value == "off"
    assert rec.raw_data["source"] == "recon"


def test_from_dict_uses_desc_fallback():
    rec = SecurityRecommendationType.from_dict({"desc": "fallback desc"})
    assert rec.description == "fallback desc"


def test_to_dict_serializes_user_last_login():
    host = HostInfoData(
        users=[
            HostUser(
                username="bob",
                last_login=datetime(2024, 5, 1, 12, 0, 0, tzinfo=UTC),
            ),
            HostUser(username="alice"),
        ]
    )

    data = host.to_dict()

    assert data["users"][0]["last_login"] == "2024-05-01T12:00:00+00:00"
    assert data["users"][1]["last_login"] is None