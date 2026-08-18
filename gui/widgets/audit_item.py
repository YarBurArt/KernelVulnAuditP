"""Hardening finding rows for the scan tabs"""

from __future__ import annotations

from typing import Any

from textual.widgets import Collapsible, Static

from gui.shared.colors import SEVERITY_COLORS
from gui.shared.formatting import markup_escape, rec_severity
from term import unicode_glyph


def _clip(text: str, width: int) -> str:
    if len(text) <= width:
        return text.ljust(width)
    return text[: max(width - 1, 0)] + unicode_glyph("…", "...")


class AuditItem(Static):
    """One hardening finding on a single aligned line: severity, test id, field, diff and a short hint.
    field_width pads the field column to the widest field in the list so
    the diff starts at the same column in term on every row
    """

    def __init__(
        self,
        rec: Any,
        field_width: int = 30,
        exp_width: int = 10,
        act_width: int = 8,
        *args,
        **kwargs,
    ) -> None:
        super().__init__(
            *args, self._line(rec, field_width, exp_width, act_width), **kwargs
        )

    @staticmethod
    def _line(rec: Any, field_width: int, exp_width: int, act_width: int) -> str:
        severity, _ = rec_severity(rec)
        color = SEVERITY_COLORS.get(severity, "#8b949e")
        sev = markup_escape(f"[{severity}]").ljust(7)
        test_id = markup_escape(f"[{rec.test_id}]").ljust(12)
        field = _clip(markup_escape(rec.field_name or rec.category or ""), field_width)
        parts = [
            f"[bold {color}]{sev}[/]",
            f"[dim]{test_id}[/]",
            f"[bold]{field}[/]",
        ]
        expected = str(rec.expected_value or "").strip()
        actual = str(rec.actual_value or "").strip()
        status = str(getattr(rec, "status", "") or "")
        if status != "ok" and (expected or actual):
            exp = _clip(markup_escape(expected or ""), exp_width)
            act = _clip(markup_escape(actual or "missing"), act_width)
            parts.append(
                f"([bold {color}]expected {exp}[/]"
                f" | [bold {color}]actual {act}[/])"
            )
        desc = str(rec.description or "").strip()
        if desc.lower() == "no description":
            desc = ""
        # Drop the description when it only re-states a long actual value
        redundant = (
            len(actual) >= 20
            and actual.lower() in desc.lower()
        )
        if desc and not redundant:
            parts.append(markup_escape(desc))
        return " ".join(parts).rstrip()


class CapsItem(Collapsible):
    """A capability finding grouped by its capability set"""

    def __init__(self, group: dict[str, Any], field_width: int = 30, *args, **kwargs) -> None:
        status = str(group.get("status") or "").lower()
        severity = "CRIT" if status == "fail" else "WARN"
        color = SEVERITY_COLORS.get(severity, "#8b949e")
        sev = markup_escape(f"[{severity}]").ljust(7)
        count = int(group.get("count") or group.get("left") or 1)
        count_tag = markup_escape(f"[x{count}]").ljust(7)
        cap_set = str(group.get("right") or group.get("key") or "")
        field = _clip(markup_escape(cap_set), field_width)
        title = " ".join(
            [
                f"[bold {color}]{sev}[/]",
                f"[dim]{count_tag}[/]",
                f"[bold]{field}[/]",
            ]
        ).rstrip()

        children: list[Static] = [
            Static("Expected: none", classes="mono"),
            Static(f"Actual:   {markup_escape(cap_set)}", classes="mono"),
        ]
        holders = [
            line
            for line in str(group.get("detail") or "").splitlines()
            if line.strip()
        ]
        if holders:
            children.append(
                Static(f"Holders ({count}):", classes="mono-bold section-label")
            )
            children.extend(
                Static(markup_escape(line), classes="mono dim") for line in holders
            )

        super().__init__(
            *args,
            *children,
            title=title,
            collapsed=True,
            collapsed_symbol=unicode_glyph("▶", ">"),
            expanded_symbol=unicode_glyph("▼", "v"),
            **kwargs,
        )
