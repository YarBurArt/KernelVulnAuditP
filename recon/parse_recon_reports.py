import re
from pathlib import Path
from typing import Any, Dict, List

from core import (
    parse_key_with_brackets,
    ensure_list_in_dict,
    assign_value_by_key_type,
    parse_key_value_pairs,
    strip_ansi_sequences,
)
from lib_tools.peas2json import parse_peass
from recon.remote_feeds_recon import logger, CVE_RE
from schemas import KernelAuditItem, KernelLPE, LesCVEItem


class ParseReports:
    """
    parse security reports from audit tools
    """

    @staticmethod
    def _dat_parse_key(raw_key: str):
        return parse_key_with_brackets(raw_key)

    @staticmethod
    def _dat_ensure_list(container, key, value):
        ensure_list_in_dict(container, key, value)

    @staticmethod
    def _dat_assign_value(
        results: dict, base: str, inner: str | None, value: str
    ) -> None:
        assign_value_by_key_type(results, base, inner, value)

    def parse_lynis_dat_report(self, report_path) -> Dict:
        """
        Parse Lynis .dat file (key=value per line or key[]=v1|v2)
        Returns nested dict structure.
        """
        results: dict[str, Any] = {}
        path = Path(report_path)

        if not path.exists():
            logger.warning("Lynis report file %s does not exist", report_path)
            raise FileNotFoundError(f"Lynis report not found at {report_path}")

        with path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                raw_key, value = line.split("=", 1)
                raw_key = raw_key.strip()
                value = value.strip()
                base, inner = self._dat_parse_key(raw_key)

                self._dat_assign_value(results, base, inner, value)

        return results

    @staticmethod
    def _parse_lynis_datl_entry(
        entry: str, category_prefix: str
    ) -> KernelAuditItem | None:
        parts = entry.split("|")
        if len(parts) < 3:
            logger.debug("lynis entry %s does not have 3 parts", entry)
            return None

        test_id, category, kv_blob = parts[0], parts[1], parts[2]
        if not test_id.startswith(category_prefix + "-"):
            logger.debug("lynis entry %s does not have category %s", entry, category)
            return None

        parsed = parse_key_value_pairs(kv_blob)
        logger.debug("lynis entry parsed: %s", entry)
        return KernelAuditItem(
            test_id=test_id,
            category=category,
            desc=parsed.get("desc", ""),
            field=parsed.get("field", ""),
            prefval=parsed.get("prefval", ""),
            value=parsed.get("value", ""),
        )

    def extract_lynis_kernel_details(
        self,
        parsed_data: dict,
        category_prefix: str = "KRNL",  # TODO: parse more usefull
        type_ent: str = "details",
    ) -> List[KernelAuditItem]:
        """
        Parse dat entries by category and filters it
        """
        results: list[KernelAuditItem] = []
        entries = parsed_data.get(type_ent, [])
        if not isinstance(entries, list):
            entries = [entries]

        for entry in entries:
            item: KernelAuditItem | None = self._parse_lynis_datl_entry(
                entry, category_prefix
            )
            if item:
                results.append(item)

        logger.debug("extracted %d lynis entries: %s", len(results), results)
        return results

    @staticmethod
    def convert_linpeas_to_dict(output_path: str, json_path: str = "") -> dict:
        return parse_peass(output_path, json_path)

    @staticmethod
    def _extract_basic_info_peas(data: dict) -> dict:
        info = {}
        for line in data.get("Basic information", {}).get("lines", []):
            text = line.get("clean_text", "").strip()
            colors = line.get("colors", {})
            if text.startswith("OS:"):
                info["os"] = text.replace("OS:", "").strip()
            elif text.startswith("User & Groups:"):
                info["user_groups"] = text.replace("User & Groups:", "").strip()
            elif text.startswith("Hostname:"):
                info["hostname"] = text.replace("Hostname:", "").strip()
            elif any(c in colors for c in ("RED", "REDYELLOW")):
                info.setdefault("findings", []).append(text)
        return info

    @staticmethod
    def _extract_cves_from_peas(sys_info: dict) -> dict:
        cves_list = []
        ker = sys_info.get("sections", {}).get("Kernel Exploit Registry", {})
        matched = ker.get("sections", {}).get("Matched CVEs", {})
        for line in matched.get("lines", []):
            text = line.get("clean_text", "")
            match = CVE_RE.search(text)
            if match:
                cves_list.append(match.group(1))
        return {"cves": cves_list} if cves_list else {}

    @staticmethod
    def _extract_kernel_modules_peas(sys_info: dict) -> dict:
        mods_info = {}
        kmi = sys_info.get("sections", {}).get("Kernel Modules Information", {})
        for mod_name, mod_data in kmi.get("sections", {}).items():
            for line in mod_data.get("lines", []):
                text = line.get("clean_text", "")
                colors = line.get("colors", {})
                if text and any(c in colors for c in ("RED", "REDYELLOW")):
                    mods_info[mod_name] = text
        return {"kernel_modules": mods_info} if mods_info else {}

    def extract_useful_info_peas(self, data: dict) -> KernelLPE:
        useful = {}
        useful.update(self._extract_basic_info_peas(data))
        sys_info = data.get("System Information", {})
        if sys_info:
            useful.update(self._extract_cves_from_peas(sys_info))
            useful.update(self._extract_kernel_modules_peas(sys_info))
        return KernelLPE(
            os=useful.get("os", {}),
            user_groups=useful.get("user_groups", {}),
            hostname=useful.get("hostname", {}),
            cves=useful.get("cves", {}),
        )

    def parse_les_report(self, report: str | None = None) -> list[LesCVEItem]:
        """Parse LES plain-text output into a list of findings"""
        assert report is not None  # DEBUG
        path = Path(report)
        if not path.exists():
            logger.info("LES report not found: %s", report)
            return []

        text = path.read_text(encoding="utf-8", errors="ignore")
        results: list[LesCVEItem] = []
        current: LesCVEItem | None = None
        current_id = None
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            key, value = self._les_parse_line(line)
            logger.debug("les report key %s : %s", key, repr(value))
            if key == "header":
                if current_id and current:
                    results.append(current)
                current_id = value["id"]
                current = LesCVEItem(cve_id=value["cve_id"], title=value["title"])
                continue

            if current_id is None or key is None:
                continue
            if current:
                self._les_assign_value(current, key, value)
        if current_id and current:
            results.append(current)

        logger.debug("LES report parsed")
        return results

    @staticmethod
    def _les_strip_ansi(text: str) -> str:
        return strip_ansi_sequences(text)

    def _les_parse_line(self, line_c):
        """identify line type and return (key, value)"""
        line = self._les_strip_ansi(line_c)

        # New LES format:
        # [+] [CVE-2025-32463] sudo-chwoot
        match = re.match(
            r"^\[\+\]\s*\[(CVE-\d{4}-\d+)\]\s*(.+)$", line, flags=re.IGNORECASE
        )
        if match:
            return "header", {
                "id": match.group(1).upper(),
                "cve_id": match.group(1).upper(),
                "title": match.group(2).strip(),
            }

        if ":" not in line:
            return None, None

        key, value = line.split(":", 1)
        return key.strip().lower(), value.strip()

    @staticmethod
    def _les_assign_value(current: LesCVEItem, base, value):
        if base == "details":
            current.details = value
        elif base == "exposure":
            current.exposure = value
        elif base == "tags":
            current.tags = [t.strip() for t in value.split(",") if t.strip()]
        elif base in ("download url", "ext-url"):
            current.download_urls.append(value)
        elif base == "comments":
            current.comments = value

    @staticmethod
    def _parse_lynis_sysctl_line(
        line: str, line_no: int
    ) -> tuple[str, dict[str, str]] | None:
        """parse config-data=sysctl... line"""
        payload = line.removeprefix("config-data=")
        parts = [part.strip() for part in payload.split(";")]

        if len(parts) < 6:
            logger.debug("skip malformed params.prf line %d: %s", line_no, line)
            return None

        if parts[0].lower() != "sysctl":
            return None

        setting = parts[1]

        return setting, {
            "test_id": "KRNL-6000",
            "category": "Kernel",
            "field_name": setting,
            "expected_value": parts[2],
            "description": parts[4] if len(parts) > 4 else "",
            "related": parts[5] if len(parts) > 5 else "",
            "solution": parts[6] if len(parts) > 6 else "",
            "raw": line,
        }

    def load_lynis_params_prf(
        self,
        params_path: str | Path = "params.prf",
    ) -> dict[str, list[dict[str, str]]]:
        """
        parse Lynis profile-like params.prf and collect sysctl recommendations
        from format like:
        config-data=sysctl;setting;expected;points;description;related;solution;...
        """
        path = Path(params_path)
        if not path.is_file():
            raise FileNotFoundError(f"Lynis params.prf not found: {path}")

        result: dict[str, list[dict[str, str]]] = {}
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as f:
                for line_no, raw_line in enumerate(f, start=1):
                    line = raw_line.strip()
                    if (
                        not line
                        or line.startswith("#")
                        or not line.startswith("config-data=")
                    ):
                        continue

                    parsed = self._parse_lynis_sysctl_line(line, line_no)
                    if parsed is None:
                        continue

                    setting, item = parsed
                    result.setdefault(setting, []).append(item)

            logger.debug(
                "loaded %d sysctl recommendations",
                sum(len(items) for items in result.values()),
            )
            return result
        except FileNotFoundError:
            raise
        except PermissionError as e:
            logger.warning("permission denied reading params.prf: %s", e)
        except OSError as e:
            logger.warning("os error reading params.prf: %s", e)
        except Exception as e:
            logger.exception("unexpected error parsing params.prf: %s", e)
        return {}
