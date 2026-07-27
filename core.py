"""
Core utility functions, more independent functionality
Date parsing, dict/list processing, text extraction, criticality calc.
"""
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional



def try_parse(date_str: str, fmt: str) -> Optional[datetime]:
    try:
        return datetime.strptime(date_str, fmt)
    except ValueError:
        return None


def parse_date_string(date_str: str) -> Optional[datetime]:
    if not date_str:
        return None

    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except ValueError:
        dt = None

    if dt is None:
        dt = try_parse(date_str, "%a %b %d %H:%M:%S %Y %z")

    if dt is None:
        base = date_str.split(".")[0]
        dt = try_parse(base, "%Y-%m-%dT%H:%M:%S")
        if dt is not None:
            dt = dt.replace(tzinfo=timezone.utc)

    if dt is None:
        for fmt in (
            "%Y-%m-%d %H:%M:%S",
            "%d %b %Y %H:%M:%S",
            "%a, %d %b %Y %H:%M:%S %z",
            "%Y-%m-%d",
        ):
            dt = try_parse(date_str, fmt)
            if dt is not None:
                break

    if dt is None:
        return None

    return (
        dt.replace(tzinfo=timezone.utc)
        if dt.tzinfo is None
        else dt.astimezone(timezone.utc)
    )


def filter_items_by_date(
    items: List[Dict[str, Any]],
    date_field: str = 'published',
    min_timestamp: int | Any = None
) -> List[Dict[str, Any]]:
    """filter list of dicts by date field"""
    if min_timestamp is None:
        return items

    min_dt = datetime.fromtimestamp(min_timestamp, tz=timezone.utc)
    result = []

    for item in items:
        cve_obj = item.get('cve', {}) if isinstance(item, dict) else {}
        date_str = None

        if cve_obj and date_field in cve_obj:
            date_str = cve_obj[date_field]
        elif isinstance(item, dict) and date_field in item:
            date_str = item[date_field]

        if not date_str:
            continue

        dt = parse_date_string(date_str)
        if dt is None:
            continue

        if dt >= min_dt:
            result.append(item)

    return result


def format_timestamp(
    ts: int, fmt: str = '%Y-%m-%d %H:%M:%S %Z'
) -> Optional[str]:
    """format timestamp to string"""
    if ts is None:
        return None
    try:
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        return dt.strftime(fmt)
    except ValueError:
        return None


def dict_to_display_rows(data: List[Dict[str, Any]]) -> List[List[Any]]:
    """convert list of dicts to transposed table rows"""
    if not data:
        return []

    return [[key] + [d.get(key, '') for d in data] for key in data[0].keys()]


def flatten_dict_value(value: Any, max_length: int = 500) -> str:
    """convert dict/list to display string"""
    if isinstance(value, list) and value and isinstance(value[0], dict):
        result = "\n".join([
            ", ".join(f"{ik}: {iv}" for ik, iv in it.items())
            for it in value
        ])
    elif isinstance(value, dict):
        result = ", ".join(f"{k}: {v}" for k, v in value.items())
    elif isinstance(value, list):
        result = ", ".join(str(v) for v in value)
    else:
        result = str(value) if value is not None else ""

    return result[:max_length]


def merge_dicts_by_key(
    target: Dict[str, Any],
    source: Dict[str, Any],
    keys: List[str] | Any = None
) -> Dict[str, Any]:
    """merge selected keys from source to target"""
    if keys is None:
        target.update(source)
    else:
        for key in keys:
            if key in source:
                target[key] = source[key]
    return target


def safe_get_nested(
    data: Dict[str, Any],
    *keys,
    default: Any = None
) -> Any:
    """safely get nested dict value"""
    current = data
    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return default
    return current


def strip_ansi_sequences(text: str) -> str:
    """remove ANSI escape codes"""
    ansi_pattern = re.compile(r'\x1b\[[0-9;]*m')
    return ansi_pattern.sub('', text)


def extract_section_by_header(
    text: str,
    header_patterns: List[str],
    max_length: int = 500
) -> Optional[str]:
    """extract text section by header pattern"""
    for pattern in header_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE | re.MULTILINE)
        if matches:
            extracted = matches[0].strip()
            extracted = re.sub(r'\[.*?\]\(.*?\)', '', extracted)
            extracted = extracted.replace('*', '').replace('`', '')
            extracted = ' '.join(extracted.split())

            if 10 < len(extracted) < max_length:
                return extracted

    return None


def extract_code_block_commands(
    text: str,
    command_patterns: List[str],
    languages: List[str] | Any= None
) -> List[str]:
    """extract commands from Markdown code blocks"""
    commands = []

    lang_pattern = r'(?:' + '|'.join(languages) + r')?' if languages else r''
    block_pattern = rf'```({lang_pattern})?\n(.*?)```'

    for block in re.findall(block_pattern, text, re.DOTALL):
        content = block[1] if isinstance(block, tuple) else block
        for pattern in command_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            commands.extend(matches)

    return commands


def clean_command_string(cmd: str) -> str:
    """clean command string from Markdown"""
    cmd = cmd.replace('```', '').replace('`', '')
    cmd = cmd.split('\n')[0]
    return cmd.strip()


def parse_key_with_brackets(raw_key: str) -> tuple:
    """parse key with bracket notation: key, key[], key[name]"""
    match = re.fullmatch(r"([^\[]+)(?:\[(.*?)\])?", raw_key)
    if not match:
        return raw_key, None
    return match.group(1), match.group(2)


def ensure_list_in_dict(
    container: Dict[str, Any],
    key: str,
    value: Any
) -> None:
    """ensure key contains list, append value"""
    if key not in container:
        container[key] = [value]
    else:
        if not isinstance(container[key], list):
            container[key] = [container[key]]
        container[key].append(value)


def assign_value_by_key_type(
    results: Dict[str, Any],
    base: str,
    inner: Optional[str],
    value: str
) -> None:
    """assign value based on key type: scalar, list, or dict"""
    if inner is None:  # key=value
        if base in results:
            ensure_list_in_dict(results, base, value)
        else:
            results[base] = value
    elif inner == "":  # key[]=value
        ensure_list_in_dict(results, base, value)
    else:  # key[name]=value
        if base not in results:
            results[base] = {}
        if not isinstance(results[base], dict):
            raise ValueError(f"Key '{base}' used as both scalar/list and dict")
        results[base][inner] = value


def parse_key_value_pairs(
    blob: str,
    separator: str = ";",
    kv_delim: str = ":"
) -> Dict[str, str]:
    """parse key:value;key:value blob"""
    result = {}
    for pair in blob.split(separator):
        if kv_delim in pair:
            key, value = pair.split(kv_delim, 1)
            result[key.strip()] = value.strip()
    return result

def calculate_criticality_score(data: Dict[str, Any]) -> int:
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
        score += int((cvss - 9.0) * 10)   # 9.8 -> +8
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


def chain_get(
    data: Dict[str, Any],
    path: str,
    default: Any = None,
    separator: str = '.'
) -> Any:
    """get nested value using dot notation"""
    keys = path.split(separator)
    current = data

    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        elif isinstance(current, list):
            try:
                idx = int(key)
                current = current[idx]
            except (ValueError, IndexError):
                return default
        else:
            return default

    return current


def filter_list_by_pred(
    items: List[Any],
    predicate: Callable,
    limit: int | Any = None
) -> List[Any]:
    """filter list by predicate with optional limit"""
    result = [item for item in items if predicate(item)]
    if limit is not None:
        result = result[:limit]
    return result


def group_by_key(
    items: List[Dict[str, Any]],
    key: str
) -> Dict[str, List[Dict[str, Any]]]:
    """group list of dicts by key"""
    result: dict[Any, List[Dict[str, Any]]] = {}
    for item in items:
        group_key = item.get(key)
        if group_key is not None:
            if group_key not in result:
                result[group_key] = []
            result[group_key].append(item)
    return result


def count_by_key(
    items: List[Dict[str, Any]],
    key: str
) -> Dict[str, int]:
    """count occurrences by key"""
    result: dict[Any, int] = {}
    for item in items:
        value = item.get(key)
        if value is not None:
            result[value] = result.get(value, 0) + 1
    return result


def update_config_file(
    config_path: Path,
    updates: Dict[str, str]
) -> None:
    """
    update config by dict of {VAR_NAME: new_value}
    where value includes quotes if needed
    """
    config_path = Path(config_path)
    config_content = config_path.read_text(encoding="utf-8")

    for key, replacement in updates.items():
        if replacement.isdigit() or (
            replacement.startswith('-') and replacement[1:].isdigit()
        ):
            pattern = rf'^{key}\s*=\s*\d+'
        elif replacement in ('True', 'False'):
            pattern = rf'^{key}\s*=\s*(True|False)'
        else:
            pattern = rf'^{key}\s*=\s*["\'].*["\']'

        config_content = re.sub(
            pattern,
            f'{key} = {replacement}',
            config_content,
            flags=re.MULTILINE
        )

    config_path.write_text(config_content, encoding="utf-8")

def format_report(data: dict) -> dict:
    """ filter data to format useful report """
    feeds = data.get("feeds", {}) or {}
    findings = feeds.get("findings", [])
    pocs = feeds.get("pocs", [])

    nist_count = 0
    osv_count = 0

    for f in findings:
        src = (f.get("source") or "").upper()
        if src == "NIST":
            nist_count += 1
        elif src == "OSV":
            osv_count += 1

    return {
        "kernel": data.get("kernel", ""),
        "system": data.get("system", ""),
        "build_date": data.get("build_date", 0),
        "nist_count": nist_count,
        "osv_count": osv_count,
        "github_count": len(pocs),
    }

def summarize_sandbox(result) -> Dict[str, Any]:
    """summarize sandbox result by reformat and filter"""
    return {
        "mode": getattr(result, "execution_mode", "unknown"),
        "returncode": getattr(result, "returncode", None),
        "success": getattr(result, "returncode", 1) == 0,
        "crashed": getattr(result, "crashed", False),
        "stdout": getattr(result, "stdout", " "),
        "stderr": getattr(result, "stderr", " "),
        "logs": getattr(result, "logs", {}),
        "kernel_info": getattr(result, "kernel_info", {}),
        "resources": getattr(result, "resources", {}),
        "modules": getattr(result, "modules", []),
        "files": getattr(result, "files", []),
        "processes": getattr(result, "processes", []),
    }

def norm_sysctl_value(value: Any) -> str:
    """ normalize sysctl possible values for kernel params check """
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
