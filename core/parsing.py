"""Domain parsing: turn raw strings and API payloads into domain values.

Pure stdlib, no project dependencies. These functions implement the parsing
rules of the vulnerability domain (dates, CVSS metrics, CVE identifiers,
native descriptions, sysctl value normalization).
"""

import re
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any

_CVSS_DICT_KEYS = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2")
_CVSS_LIST_KEYS = ("cvssV3_1", "cvssV3_0", "cvssV2_0", "cvssV4_0")

CVE_RE = re.compile(r"(CVE-\d{4}-\d+)", re.IGNORECASE)


def parse_date_string(date_str: str) -> datetime | None:
    """Parse an ISO-8601 or RFC-2822 date string into a UTC-aware datetime.

    Naive inputs are interpreted as UTC; aware inputs are converted to UTC,
    so the result never depends on the host's local timezone.
    """
    if not date_str:
        return None

    dt: datetime | None = None
    try:
        dt = datetime.fromisoformat(date_str)
    except ValueError:
        # fromisoformat may reject over-precise fractional seconds; retry the
        # truncated form (the original code parsed "%Y-%m-%dT%H:%M:%S" here)
        base = date_str.split(".")[0]
        try:
            dt = datetime.fromisoformat(base)
        except ValueError:
            dt = None

    if dt is None:
        try:
            dt = parsedate_to_datetime(date_str)
        except (TypeError, ValueError):
            dt = None

    if dt is None:
        return None

    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def filter_items_by_date(
    items: list[dict[str, Any]],
    date_field: str = "published",
    min_timestamp: int | Any = None,
) -> list[dict[str, Any]]:
    """filter list of dicts by date field"""
    if min_timestamp is None:
        return items

    min_dt = datetime.fromtimestamp(min_timestamp, tz=UTC)
    result = []

    for item in items:
        cve_obj = item.get("cve", {}) if isinstance(item, dict) else {}
        date_str = None

        if cve_obj and date_field in cve_obj:
            date_str = cve_obj[date_field]
        elif isinstance(item, dict) and date_field in item:
            date_str = item[date_field]

        if not isinstance(date_str, str):
            continue

        dt = parse_date_string(date_str)
        if dt is None:
            continue

        if dt >= min_dt:
            result.append(item)

    return result


def extract_cvss(metrics: Any) -> tuple[Any, Any, Any]:
    """extract (base_score, severity, vector) from CVSS metrics"""
    if isinstance(metrics, dict):
        for metric_key in _CVSS_DICT_KEYS:
            for m in metrics.get(metric_key, []):
                cvss_data = m.get("cvssData", {})
                score = cvss_data.get("baseScore")
                if score is not None:
                    return (
                        score,
                        cvss_data.get("baseSeverity"),
                        cvss_data.get("vectorString"),
                    )
        return None, None, None

    for metric in metrics or []:
        for cvss_key in _CVSS_LIST_KEYS:
            cvss_data = metric.get(cvss_key)
            if cvss_data:
                score = cvss_data.get("baseScore")
                if score is not None:
                    return (
                        score,
                        cvss_data.get("baseSeverity"),
                        cvss_data.get("vectorString"),
                    )
    return None, None, None


def extract_cve_ids(text: str) -> list[str]:
    """extract all CVE ids from text via CVE_RE"""
    return list(CVE_RE.findall(text))


def extract_english_description(descriptions: Any) -> str:
    """extract the english description from a CVE descriptions list"""
    descriptions = descriptions or []
    for item in descriptions:
        if isinstance(item, dict) and item.get("lang") == "en":
            value = item.get("value")
            if value:
                return str(value)
    if descriptions:
        first = descriptions[0]
        if isinstance(first, dict):
            return str(first.get("value") or "")
    return ""


def norm_sysctl_value(value: Any) -> str:
    """normalize sysctl possible values for kernel params check"""
    if value is None:
        return ""
    text = str(value).strip().strip('"').strip("'")
    if not text:
        return ""
    low = text.lower()
    if low in ("yes", "true", "on", "enabled"):
        return "1"
    if low in ("no", "false", "off", "disabled"):
        return "0"
    if re.fullmatch(r"[+-]?\d+", text):
        return str(int(text))
    return low