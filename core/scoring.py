"""Domain scoring: compute the risk score of a vulnerability record"""

from typing import Any


def calculate_criticality_score(data: dict[str, Any]) -> int:
    """calc criticality score in range 0..100."""

    def clamp(value: int) -> int:
        return max(0, min(100, value))

    def as_float(value: Any) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return 0.0

    score = 0

    cvss = as_float(data.get("cvss_v3_score") or data.get("cvss_v2_score"))
    severity = (data.get("severity") or "").upper()

    if cvss >= 9.0:
        score += 65
        score += int((cvss - 9.0) * 10)  # 9.8 -> +8
    elif cvss >= 7.0:
        score += 45
        score += int((cvss - 7.0) * 10)
    elif cvss >= 4.0:
        score += 20
        score += int((cvss - 4.0) * 8)
    elif cvss > 0:
        score += int(cvss * 4)

    if severity == "CRITICAL":
        score += 10
    elif severity == "HIGH":
        score += 5

    if data.get("in_cisa_kev"):
        score += 20
        if data.get("known_ransomware"):
            score += 10

    if data.get("has_exploit"):
        score += 15
        score += min(int(data.get("exploit_count") or 0) * 2, 10)

    score += min(int(data.get("github_refs") or 0) * 2, 10)
    score += min(int(data.get("exploitdb_refs") or 0) * 2, 10)

    return clamp(score)