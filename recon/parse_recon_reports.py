import logging
import re
from pathlib import Path
from typing import Any

from core import (
    CVE_RE,
    assign_value_by_key_type,
    ensure_list_in_dict,
    extract_cve_ids,
    extract_cvss,
    extract_english_description,
    filter_items_by_date,
    parse_key_value_pairs,
    parse_key_with_brackets,
    strip_ansi_sequences,
)
from lib_tools.peas2json import parse_peass
from schemas import CVEFinding, GitHubPoC, KernelAuditItem, KernelLPE, LesCVEItem

logger = logging.getLogger(f"kernel_audit.{__name__}")


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

    def parse_lynis_dat_report(self, report_path) -> dict:
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
    ) -> list[KernelAuditItem]:
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
        res: dict | None = parse_peass(output_path, json_path)
        if res is None:
            logger.debug("lynis report not found or not parsed at %s", output_path)
            raise ValueError("Could not parse PEAS output")
        return res

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
            r"^\[\+]\s*\[(CVE-\d{4}-\d+)]\s*(.+)$", line, flags=re.IGNORECASE
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

        solution = parts[6] if len(parts) > 6 else ""
        details = ""
        if solution.startswith("url:"):
            details = solution[4:]
        elif solution.startswith("text:"):
            details = solution[5:]
        elif solution not in ("-", ""):
            logger.debug(
                "skip non-solution field %s in params.prf line %d", solution, line_no
            )
        else:
            details = ""

        return setting, {
            "test_id": "KRNL-6000",
            "category": "Kernel",
            "field_name": setting,
            "expected_value": parts[2],
            "description": parts[4] if len(parts) > 4 else "",
            "related": parts[5] if len(parts) > 5 else "",
            "solution": details,
            "details": details,
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
        return {}

    @staticmethod
    def reformat_cve_details(data_raw: dict) -> dict:
        """reformat NIST CVE 2.0 payload into the CVE JSON 5.x record shape"""
        vulns = data_raw.get("vulnerabilities", [])
        if not vulns:
            return {}
        nist_cve = vulns[0].get("cve", {})
        if not nist_cve:
            return {}

        descriptions = nist_cve.get("descriptions", [])
        published = nist_cve.get("published", "")
        modified = nist_cve.get("lastModified", "")
        source_id = nist_cve.get("sourceIdentifier", "")

        metrics = []
        nist_metrics = nist_cve.get("metrics", {})
        for nk, mk in (
            ("cvssMetricV40", "cvssV4_0"),
            ("cvssMetricV31", "cvssV3_1"),
            ("cvssMetricV30", "cvssV3_0"),
            ("cvssMetricV2", "cvssV2_0"),
        ):
            for m in nist_metrics.get(nk, []):
                metrics.append({mk: m.get("cvssData", {})})

        problem_types = []
        for w in nist_cve.get("weaknesses", []):
            for desc in w.get("description", []):
                cv = desc.get("value", "")
                problem_types.append(
                    {
                        "descriptions": [
                            {
                                "lang": desc.get("lang", "en"),
                                "description": cv,
                                "cweId": cv if cv.startswith("CWE-") else "",
                                "type": "CWE",
                            }
                        ]
                    }
                )

        references = []
        for r in nist_cve.get("references", []):
            ref = {"url": r.get("url", "")}
            src = r.get("source")
            if src:
                ref["tags"] = [src]
            references.append(ref)

        affected = []
        for a in nist_cve.get("affected", []):
            item = {
                "vendor": a.get("vendor", ""),
                "product": a.get("product", ""),
                "versions": a.get("versions", []),
            }
            if a.get("modules"):
                item["modules"] = a["modules"]
            affected.append(item)

        return {
            "dataType": "CVE_RECORD",
            "dataVersion": "5.2",
            "cveMetadata": {
                "cveId": nist_cve.get("id", ""),
                "assignerOrgId": source_id,
                "state": nist_cve.get("vulnStatus", "PUBLISHED"),
                "datePublished": published,
                "dateUpdated": modified,
            },
            "containers": {
                "cna": {
                    "providerMetadata": {
                        "orgId": source_id,
                        "dateUpdated": modified,
                    },
                    "descriptions": descriptions,
                    "metrics": metrics,
                    "problemTypes": problem_types,
                    "references": references,
                    "affected": affected,
                }
            },
        }

    @staticmethod
    def parse_nist_findings(data: dict, min_ts: int | None = None) -> list[CVEFinding]:
        """parse NIST CVE 2.0 search payload into CVEFinding list, date-filtered"""
        raw = filter_items_by_date(
            (data or {}).get("vulnerabilities", []),
            date_field="published",
            min_timestamp=min_ts,
        )

        findings: list[CVEFinding] = []
        for item in raw:
            cve = item.get("cve", {})
            cve_id = cve.get("id") or item.get("cveId")
            if not cve_id:
                continue

            description = extract_english_description(cve.get("descriptions", []))
            cvss, severity, _ = extract_cvss(cve.get("metrics", {}))

            findings.append(
                CVEFinding(
                    cve_id=str(cve_id),
                    description=description,
                    severity=severity or "",
                    cvss_score=cvss,
                    source="NIST",
                    references=[],
                    raw_data=item,
                )
            )
        return findings

    @staticmethod
    def parse_github_pocs(data: dict) -> list[GitHubPoC]:
        """parse GitHub repo search payload into GitHubPoC list"""
        results: list[GitHubPoC] = []
        seen: set[str] = set()

        for repo in (data or {}).get("items", []):
            text = " ".join(
                [
                    repo.get("name", "") or "",
                    repo.get("full_name", "") or "",
                    repo.get("description", "") or "",
                ]
            )
            matches = extract_cve_ids(text)
            if not matches:
                continue

            cve_id = matches[0].upper()
            key = f"{cve_id}:{repo.get('full_name', '')}"
            if key in seen:
                continue
            seen.add(key)

            results.append(
                GitHubPoC(
                    cve_id=cve_id,
                    repo_name=repo.get("full_name", ""),
                    repo_url=repo.get("html_url", ""),
                    description=repo.get("description", "") or "",
                    stars=repo.get("stargazers_count", 0),
                    language=repo.get("language") or "",
                )
            )
        return results

    @staticmethod
    def osv_cve_ids(vuln: dict) -> list[str]:
        """resolve one OSV record to concrete CVE ids (aliases-aware)."""
        candidates: list[str] = [vuln.get("id", "")]
        candidates.extend(vuln.get("aliases", []) or [])
        cve_ids = [
            str(c).upper() for c in candidates if str(c).upper().startswith("CVE-")
        ]
        if not cve_ids and vuln.get("id"):
            cve_ids.append(str(vuln["id"]))
        return list(dict.fromkeys(cve_ids))

    @staticmethod
    def build_osv_finding(cve_id: str, vuln: dict) -> CVEFinding:
        """build a base OSV finding; CVSS/severity enrichment happens later"""
        db_specific = vuln.get("database_specific") or {}
        return CVEFinding(
            cve_id=cve_id,
            description=vuln.get("summary", "") or "",
            severity=str(db_specific.get("severity") or ""),
            cvss_score=None,
            source="OSV",
            references=vuln.get("references", []) or [],
            raw_data=vuln,
        )

    @staticmethod
    def extract_cve_details(data: dict, nist_url: str) -> dict:
        """extract {description, cvss, severity, raw} from a cve.org/NIST record"""
        containers = data.get("containers", {}) or {}
        cna = containers.get("cna", {}) or {}
        # cve.org / reformatted NIST use containers.cna, raw NIST 2.0 uses cve
        cve_obj = data.get("cve", {}) or cna

        description = extract_english_description(cve_obj.get("descriptions", []))
        cvss_score, cvss_severity, cvss_vector = extract_cvss(cve_obj.get("metrics"))

        return {
            "description": description,
            "cvss_v3_score": cvss_score,
            "cvss_v3_vector": cvss_vector,
            "severity": cvss_severity,
            "raw": data,
            "nist_url": nist_url,
        }
