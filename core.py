"""
Core utility functions, more independent functionality
Date parsing, dict/list processing, text extraction, criticality calc.
"""
import re
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Callable


def parse_date_string(date_str: str) -> Optional[datetime]:
    """parse date string to datetime, various formats"""
    if not date_str:
        return None

    dt = None

    # ISO-like
    try:
        dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
    except Exception:
        pass

    # RFC-like
    if dt is None:
        try:
            dt = datetime.strptime(date_str, '%a %b %d %H:%M:%S %Y %z')
        except Exception:
            pass

    # Fallback
    if dt is None:
        try:
            base = date_str.split('.')[0]
            dt = datetime.strptime(base, '%Y-%m-%dT%H:%M:%S')
            dt = dt.replace(tzinfo=timezone.utc)
        except Exception:
            pass

    # More formats
    if dt is None:
        for fmt in ('%Y-%m-%d %H:%M:%S', '%d %b %Y %H:%M:%S',
                    '%a, %d %b %Y %H:%M:%S %z', '%Y-%m-%d'):
            try:
                dt = datetime.strptime(date_str, fmt)
                break
            except Exception:
                continue

    if dt is not None and dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    elif dt is not None:
        dt = dt.astimezone(timezone.utc)

    return dt


def filter_items_by_date(
    items: List[Dict[str, Any]],
    date_field: str = 'published',
    min_timestamp: int = None
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
    except Exception:
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
    keys: List[str] = None
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
    languages: List[str] = None
) -> List[str]:
    """extract commands from markdown code blocks"""
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
    """clean command string from markdown"""
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
    """calc criticality score 0-100"""
    score = 0

    if data.get('in_cisa_kev'):
        score += 40
        if data.get('known_ransomware'):
            score += 20

    if data.get('has_exploit'):
        score += 25
        score += min((data.get('exploit_count') or 0) * 2, 10)

    cvss = data.get('cvss_v3_score') or data.get('cvss_v2_score') or 0
    score += int(cvss * 2)

    score += min((data.get('github_refs') or 0) * 3, 15)
    score += min((data.get('exploitdb_refs') or 0) * 3, 15)

    return min(score, 100)


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
    limit: int = None
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
    result = {}
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
    result = {}
    for item in items:
        value = item.get(key)
        if value is not None:
            result[value] = result.get(value, 0) + 1
    return result


def update_config_file(
    config_path: str,
    updates: Dict[str, str]
) -> None:
    """
    update config by dict of {VAR_NAME: new_value}
    where value includes quotes if needed
    """
    config_path = Path(config_path)
    config_content = config_path.read_text()

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

    config_path.write_text(config_content)
