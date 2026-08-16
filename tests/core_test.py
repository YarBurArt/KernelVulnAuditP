"""Tests for core.py - only stdlib (unittest)."""

import tempfile
import unittest
from datetime import UTC, datetime
from typing import ClassVar

from core import (
    assign_value_by_key_type,
    audit_priority,
    binary_output,
    calculate_criticality_score,
    chain_get,
    clean_command_string,
    count_by_key,
    dedupe_links,
    dict_to_display_rows,
    ensure_list_in_dict,
    extract_code_block_commands,
    extract_cve_ids,
    extract_cvss,
    extract_english_description,
    extract_links,
    extract_section_by_header,
    filter_items_by_date,
    filter_list_by_pred,
    first_resource_line,
    flatten_dict_value,
    format_execution_report,
    format_kernel_line,
    format_report,
    format_run_timestamp,
    format_sandbox_detail,
    format_timestamp,
    group_by_key,
    is_finding,
    is_ok_status,
    is_url,
    merge_dicts_by_key,
    norm_sysctl_value,
    parse_date_string,
    parse_key_value_pairs,
    parse_key_with_brackets,
    rec_context_rows,
    rec_severity,
    safe_get_attr,
    safe_get_nested,
    short_hash,
    status_rank,
    status_severity,
    strip_ansi_sequences,
    suggestion_for,
    summarize_sandbox,
    try_parse,
    update_config_file,
)


class TestDateParsing(unittest.TestCase):
    """date parsing tests"""

    def test_parse_iso_format(self):
        dt = parse_date_string("2024-01-15T10:30:00")
        self.assertIsNotNone(dt)
        self.assertEqual(dt.year, 2024)
        self.assertEqual(dt.month, 1)
        self.assertEqual(dt.day, 15)

    def test_parse_iso_with_z(self):
        dt = parse_date_string("2024-01-15T10:30:00Z")
        self.assertIsNotNone(dt)
        self.assertEqual(dt.tzinfo, UTC)

    def test_parse_iso_with_offset(self):
        dt = parse_date_string("2024-01-15T10:30:00+01:00")
        self.assertIsNotNone(dt)
        self.assertEqual(dt.tzinfo, UTC)

    def test_parse_rfc_format(self):
        dt = parse_date_string("Mon Jan 15 10:30:00 2024 +0000")
        self.assertIsNotNone(dt)
        self.assertEqual(dt.year, 2024)
        self.assertEqual(dt.month, 1)

    def test_parse_simple_date(self):
        dt = parse_date_string("2024-01-15")
        self.assertIsNotNone(dt)
        self.assertEqual(dt.year, 2024)
        self.assertEqual(dt.month, 1)
        self.assertEqual(dt.day, 15)

    def test_parse_invalid_date(self):
        dt = parse_date_string("not-a-date")
        self.assertIsNone(dt)

    def test_parse_empty_string(self):
        dt = parse_date_string("")
        self.assertIsNone(dt)

    def test_parse_none(self):
        dt = parse_date_string(None)
        self.assertIsNone(dt)

    def test_try_parse_naive_format_is_utc_aware(self):
        dt = try_parse("2024-01-15 10:30:00", "%Y-%m-%d %H:%M:%S")
        self.assertIsNotNone(dt)
        self.assertEqual(dt.tzinfo, UTC)

    def test_try_parse_aware_format_keeps_offset(self):
        dt = try_parse("2024-01-15 10:30:00 +0500", "%Y-%m-%d %H:%M:%S %z")
        self.assertIsNotNone(dt)
        self.assertEqual(dt.utcoffset().total_seconds(), 5 * 3600)

    def test_try_parse_invalid(self):
        self.assertIsNone(try_parse("garbage", "%Y-%m-%d"))

    def test_filter_items_by_date_no_min(self):
        items = [
            {"cve": {"published": "2024-01-15T00:00:00Z"}},
            {"cve": {"published": "2023-01-15T00:00:00Z"}},
        ]
        result = filter_items_by_date(items, min_timestamp=None)
        self.assertEqual(len(result), 2)

    def test_filter_items_by_date(self):
        min_ts = int(datetime(2024, 1, 1, tzinfo=UTC).timestamp())
        items = [
            {"cve": {"published": "2024-01-15T00:00:00Z"}},
            {"cve": {"published": "2023-01-15T00:00:00Z"}},
        ]
        result = filter_items_by_date(items, min_timestamp=min_ts)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["cve"]["published"], "2024-01-15T00:00:00Z")

    def test_filter_items_by_date_top_level(self):
        min_ts = int(datetime(2024, 1, 1, tzinfo=UTC).timestamp())
        items = [
            {"published": "2024-01-15T00:00:00Z"},
            {"published": "2023-01-15T00:00:00Z"},
        ]
        result = filter_items_by_date(
            items, date_field="published", min_timestamp=min_ts
        )
        self.assertEqual(len(result), 1)

    def test_format_timestamp(self):
        ts = int(datetime(2024, 1, 15, 10, 30, tzinfo=UTC).timestamp())
        result = format_timestamp(ts)
        self.assertIsNotNone(result)
        self.assertIn("2024", result)

    def test_format_timestamp_none(self):
        result = format_timestamp(None)
        self.assertIsNone(result)


class TestDictListProcessing(unittest.TestCase):
    """dict/list processing tests"""

    def test_dict_to_display_rows(self):
        data = [{"name": "Alice", "age": 30}, {"name": "Bob", "age": 25}]
        result = dict_to_display_rows(data)
        self.assertEqual(len(result), 2)
        self.assertIn(["name", "Alice", "Bob"], result)

    def test_dict_to_display_rows_empty(self):
        result = dict_to_display_rows([])
        self.assertEqual(result, [])

    def test_flatten_dict_value_dict(self):
        value = {"key1": "val1", "key2": "val2"}
        result = flatten_dict_value(value)
        self.assertIn("key1: val1", result)

    def test_flatten_dict_value_list_of_dicts(self):
        value = [{"id": 1, "name": "A"}, {"id": 2, "name": "B"}]
        result = flatten_dict_value(value)
        self.assertIn("id: 1", result)

    def test_flatten_dict_value_list(self):
        value = [1, 2, 3]
        result = flatten_dict_value(value)
        self.assertEqual(result, "1, 2, 3")

    def test_flatten_dict_value_primitive(self):
        self.assertEqual(flatten_dict_value("hello"), "hello")
        self.assertEqual(flatten_dict_value(42), "42")
        self.assertEqual(flatten_dict_value(None), "")

    def test_flatten_dict_value_max_length(self):
        value = {"key": "x" * 1000}
        result = flatten_dict_value(value, max_length=50)
        self.assertLessEqual(len(result), 50)

    def test_merge_dicts_by_key_all(self):
        target = {"a": 1}
        source = {"b": 2, "c": 3}
        result = merge_dicts_by_key(target, source)
        self.assertEqual(result, {"a": 1, "b": 2, "c": 3})

    def test_merge_dicts_by_key_selected(self):
        target = {"a": 1}
        source = {"b": 2, "c": 3}
        result = merge_dicts_by_key(target, source, keys=["b"])
        self.assertEqual(result, {"a": 1, "b": 2})
        self.assertNotIn("c", result)

    def test_safe_get_nested_single(self):
        data = {"a": 1}
        self.assertEqual(safe_get_nested(data, "a"), 1)

    def test_safe_get_nested_deep(self):
        data = {"a": {"b": {"c": 42}}}
        self.assertEqual(safe_get_nested(data, "a", "b", "c"), 42)

    def test_safe_get_nested_missing(self):
        data = {"a": {"b": 1}}
        self.assertEqual(safe_get_nested(data, "a", "c"), None)

    def test_safe_get_nested_default(self):
        data = {"a": 1}
        self.assertEqual(safe_get_nested(data, "b", default="default"), "default")


class TestTextParsing(unittest.TestCase):
    """text parsing tests"""

    def test_strip_ansi_sequences(self):
        text = "\x1b[31mred\x1b[0m normal"
        result = strip_ansi_sequences(text)
        self.assertEqual(result, "red normal")

    def test_strip_ansi_multiple(self):
        text = "\x1b[1m\x1b[32mgreen bold\x1b[0m"
        result = strip_ansi_sequences(text)
        self.assertEqual(result, "green bold")

    def test_extract_section_by_header(self):
        text = "## Requirements\n\nSome requirements here.\n\n## Other"
        patterns = [r"(?:requirements?)[\s:]+([^\n#]+)"]
        result = extract_section_by_header(text, patterns)
        self.assertIsNotNone(result)

    def test_extract_section_not_found(self):
        text = "No sections here"
        patterns = [r"requirements"]
        result = extract_section_by_header(text, patterns)
        self.assertIsNone(result)

    def test_extract_code_block_commands(self):
        text = "```bash\ngcc -O2 test.c -o test\n```"
        patterns = [r"gcc\s+\S+"]
        result = extract_code_block_commands(text, patterns, languages=["bash"])
        self.assertGreaterEqual(len(result), 1)
        self.assertIn("gcc", result[0])

    def test_extract_code_block_commands_no_languages(self):
        text = "```\ngcc -O2 test.c -o test\n```"
        patterns = [r"gcc\s+\S+"]
        result = extract_code_block_commands(text, patterns, languages=[])
        self.assertGreaterEqual(len(result), 1)

    def test_extract_code_block_commands_no_blocks(self):
        text = "No code blocks here"
        result = extract_code_block_commands(text, [r"gcc"], languages=[])
        self.assertEqual(result, [])

    def test_clean_command_string(self):
        cmd = "```gcc test.c```"
        result = clean_command_string(cmd)
        self.assertEqual(result, "gcc test.c")

    def test_clean_command_string_multiline(self):
        cmd = "gcc test.c\nother line"
        result = clean_command_string(cmd)
        self.assertEqual(result, "gcc test.c")


class TestKeyValueParsing(unittest.TestCase):
    """key-value parsing tests"""

    def test_parse_key_with_brackets_simple(self):
        base, inner = parse_key_with_brackets("key")
        self.assertEqual(base, "key")
        self.assertIsNone(inner)

    def test_parse_key_with_brackets_list(self):
        base, inner = parse_key_with_brackets("key[]")
        self.assertEqual(base, "key")
        self.assertEqual(inner, "")

    def test_parse_key_with_brackets_dict(self):
        base, inner = parse_key_with_brackets("key[name]")
        self.assertEqual(base, "key")
        self.assertEqual(inner, "name")

    def test_ensure_list_in_dict_new(self):
        container = {}
        ensure_list_in_dict(container, "key", "value")
        self.assertEqual(container, {"key": ["value"]})

    def test_ensure_list_in_dict_existing(self):
        container = {"key": ["value1"]}
        ensure_list_in_dict(container, "key", "value2")
        self.assertEqual(container, {"key": ["value1", "value2"]})

    def test_ensure_list_in_dict_convert(self):
        container = {"key": "value1"}
        ensure_list_in_dict(container, "key", "value2")
        self.assertEqual(container, {"key": ["value1", "value2"]})

    def test_assign_value_scalar(self):
        results = {}
        assign_value_by_key_type(results, "key", None, "value")
        self.assertEqual(results, {"key": "value"})

    def test_assign_value_list(self):
        results = {}
        assign_value_by_key_type(results, "key", "", "value")
        self.assertEqual(results, {"key": ["value"]})

    def test_assign_value_dict(self):
        results = {}
        assign_value_by_key_type(results, "base", "name", "value")
        self.assertEqual(results, {"base": {"name": "value"}})

    def test_assign_value_error(self):
        results = {"base": "scalar"}
        with self.assertRaises(ValueError):
            assign_value_by_key_type(results, "base", "name", "value")

    def test_parse_key_value_pairs(self):
        blob = "key1:value1;key2:value2"
        result = parse_key_value_pairs(blob)
        self.assertEqual(result, {"key1": "value1", "key2": "value2"})

    def test_parse_key_value_pairs_empty(self):
        result = parse_key_value_pairs("")
        self.assertEqual(result, {})


class TestCriticalityScore(unittest.TestCase):
    """criticality score tests"""

    def test_empty_data(self):
        score = calculate_criticality_score({})
        self.assertEqual(score, 0)

    def test_cisa_kev_only(self):
        score = calculate_criticality_score({"in_cisa_kev": True})
        self.assertGreaterEqual(score, 20)
        self.assertLess(score, 60)

    def test_cisa_kev_ransomware(self):
        score = calculate_criticality_score(
            {"in_cisa_kev": True, "known_ransomware": True}
        )
        self.assertGreater(score, calculate_criticality_score({"in_cisa_kev": True}))

    def test_exploit_only(self):
        score = calculate_criticality_score({"has_exploit": True})
        self.assertGreater(score, 0)

    def test_exploit_multiple(self):
        score_single = calculate_criticality_score({"has_exploit": True})
        score_multi = calculate_criticality_score(
            {"has_exploit": True, "exploit_count": 10}
        )
        self.assertGreater(score_multi, score_single)

    def test_cvss_only(self):
        score_low = calculate_criticality_score({"cvss_v3_score": 3.0})
        score_high = calculate_criticality_score({"cvss_v3_score": 9.8})

        self.assertGreater(score_high, score_low)
        self.assertGreater(score_high, 10)

    def test_full_critical(self):
        score = calculate_criticality_score(
            {
                "in_cisa_kev": True,
                "known_ransomware": True,
                "has_exploit": True,
                "exploit_count": 10,
                "cvss_v3_score": 10.0,
                "github_refs": 10,
                "exploitdb_refs": 10,
            }
        )
        self.assertLessEqual(score, 100)
        self.assertGreater(score, 50)

    def test_max_score_cap(self):
        score = calculate_criticality_score(
            {
                "in_cisa_kev": True,
                "known_ransomware": True,
                "has_exploit": True,
                "exploit_count": 100,
                "cvss_v3_score": 10.0,
                "github_refs": 100,
                "exploitdb_refs": 100,
            }
        )
        self.assertEqual(score, 100)


class TestPipelineUtilities(unittest.TestCase):
    """pipeline utilities tests"""

    def test_chain_get_simple(self):
        data = {"a": 1}
        self.assertEqual(chain_get(data, "a"), 1)

    def test_chain_get_nested(self):
        data = {"a": {"b": {"c": 42}}}
        self.assertEqual(chain_get(data, "a.b.c"), 42)

    def test_chain_get_list_index(self):
        data = {"items": [{"name": "first"}]}
        self.assertEqual(chain_get(data, "items.0.name"), "first")

    def test_chain_get_missing(self):
        data = {"a": 1}
        self.assertEqual(chain_get(data, "b"), None)

    def test_chain_get_default(self):
        data = {"a": 1}
        self.assertEqual(chain_get(data, "b", default="default"), "default")

    def test_filter_list_by_pred(self):
        items = [1, 2, 3, 4, 5]
        result = filter_list_by_pred(items, lambda x: x > 3)
        self.assertEqual(result, [4, 5])

    def test_filter_list_by_pred_limit(self):
        items = [1, 2, 3, 4, 5]
        result = filter_list_by_pred(items, lambda x: x > 2, limit=2)
        self.assertEqual(result, [3, 4])

    def test_group_by_key(self):
        items = [
            {"category": "A", "value": 1},
            {"category": "B", "value": 2},
            {"category": "A", "value": 3},
        ]
        result = group_by_key(items, "category")
        self.assertEqual(len(result), 2)
        self.assertEqual(len(result["A"]), 2)

    def test_count_by_key(self):
        items = [{"status": "OK"}, {"status": "FAIL"}, {"status": "OK"}]
        result = count_by_key(items, "status")
        self.assertEqual(result, {"OK": 2, "FAIL": 1})


class TestCVEHelpers(unittest.TestCase):
    """extract_cve_ids and extract_english_description tests"""

    def test_extract_cve_ids_single(self):
        result = extract_cve_ids("Found CVE-2024-1234 in the advisory")
        self.assertEqual(result, ["CVE-2024-1234"])

    def test_extract_cve_ids_multiple(self):
        result = extract_cve_ids("CVE-2024-0001 and CVE-2024-0002")
        self.assertEqual(result, ["CVE-2024-0001", "CVE-2024-0002"])

    def test_extract_cve_ids_case_insensitive(self):
        result = extract_cve_ids("cve-2024-0003")
        self.assertEqual(result, ["cve-2024-0003"])

    def test_extract_cve_ids_none(self):
        result = extract_cve_ids("no vulns referenced here")
        self.assertEqual(result, [])

    def test_extract_english_description_found(self):
        descriptions = [{"lang": "fr", "value": "truc"}, {"lang": "en", "value": "stuff"}]
        self.assertEqual(extract_english_description(descriptions), "stuff")

    def test_extract_english_description_fallback_first(self):
        descriptions = [{"lang": "fr", "value": "truc"}]
        self.assertEqual(extract_english_description(descriptions), "truc")

    def test_extract_english_description_empty(self):
        self.assertEqual(extract_english_description([]), "")
        self.assertEqual(extract_english_description(None), "")

    def test_extract_english_description_non_dict_skip(self):
        descriptions = ["junk", {"lang": "en", "value": "real"}]
        self.assertEqual(extract_english_description(descriptions), "real")


class TestExtractCvss(unittest.TestCase):
    """extract_cvss tests"""

    def test_extract_cvss_dict_metric(self):
        metrics = {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                        "vectorString": "CVSS:3.1/AV:N",
                    }
                }
            ]
        }
        result = extract_cvss(metrics)
        self.assertEqual(result, (9.8, "CRITICAL", "CVSS:3.1/AV:N"))

    def test_extract_cvss_list_metric(self):
        metrics = [{"cvssV3_1": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]
        result = extract_cvss(metrics)
        self.assertEqual(result, (7.5, "HIGH", None))

    def test_extract_cvss_none(self):
        self.assertEqual(extract_cvss(None), (None, None, None))
        self.assertEqual(extract_cvss({}), (None, None, None))
        self.assertEqual(extract_cvss([]), (None, None, None))


class TestNormSysctl(unittest.TestCase):
    """norm_sysctl_value tests"""

    def test_norm_sysctl_none(self):
        self.assertEqual(norm_sysctl_value(None), "")

    def test_norm_sysctl_empty(self):
        self.assertEqual(norm_sysctl_value("  "), "")

    def test_norm_sysctl_enabled_words(self):
        for word in ("yes", "true", "on", "enabled"):
            self.assertEqual(norm_sysctl_value(f'"{word}"'), "1")
            self.assertEqual(norm_sysctl_value(word.upper()), "1")

    def test_norm_sysctl_disabled_words(self):
        for word in ("no", "false", "off", "disabled"):
            self.assertEqual(norm_sysctl_value(word), "0")

    def test_norm_sysctl_number(self):
        self.assertEqual(norm_sysctl_value("3"), "3")
        self.assertEqual(norm_sysctl_value("-1"), "-1")

    def test_norm_sysctl_free_text(self):
        self.assertEqual(norm_sysctl_value("CHANGE"), "change")


class TestReportHelpers(unittest.TestCase):
    """format_report and summarize_sandbox tests"""

    def test_format_report_counts(self):
        data = {
            "kernel": "5.4.0",
            "system": "Linux x86_64",
            "build_date": 123,
            "feeds": {
                "findings": [
                    {"source": "NIST"},
                    {"source": "OSV"},
                    {"source": "nist"},
                ],
                "pocs": [{}, {}, {}],
            },
        }
        result = format_report(data)
        self.assertEqual(result["kernel"], "5.4.0")
        self.assertEqual(result["system"], "Linux x86_64")
        self.assertEqual(result["build_date"], 123)
        self.assertEqual(result["nist_count"], 2)
        self.assertEqual(result["osv_count"], 1)
        self.assertEqual(result["github_count"], 3)

    def test_format_report_no_feeds(self):
        result = format_report({})
        self.assertEqual(result["nist_count"], 0)
        self.assertEqual(result["osv_count"], 0)
        self.assertEqual(result["github_count"], 0)

    def test_summarize_sandbox(self):
        class Result:
            def __init__(self):
                self.execution_mode = "run"
                self.returncode = 0
                self.crashed = False
                self.stdout = "out"
                self.stderr = ""
                self.logs = {}
                self.kernel_info = {}
                self.resources = {}
                self.modules = []
                self.files = []
                self.processes = []

        summary = summarize_sandbox(Result())
        self.assertEqual(summary["mode"], "run")
        self.assertEqual(summary["returncode"], 0)
        self.assertTrue(summary["success"])
        self.assertFalse(summary["crashed"])
        self.assertEqual(summary["stdout"], "out")

    def test_summarize_sandbox_no_attrs(self):
        summary = summarize_sandbox(object())
        self.assertEqual(summary["mode"], "unknown")
        self.assertIsNone(summary["returncode"])
        self.assertFalse(summary["success"])
        self.assertEqual(summary["stdout"], " ")


class TestUpdateConfigFile(unittest.TestCase):
    """update_config_file tests"""

    def _write_config(self, content):
        tmpdir = tempfile.TemporaryDirectory()
        path = tmpdir.name + "/config.py"
        with open(path, "w") as f:
            f.write(content)
        return tmpdir, path

    def test_update_integer(self):
        tmpdir, path = self._write_config("COUNT = 10\n")
        try:
            update_config_file(path, {"COUNT": "20"})
            with open(path) as f:
                self.assertIn("COUNT = 20", f.read())
        finally:
            tmpdir.cleanup()

    def test_update_boolean(self):
        tmpdir, path = self._write_config("FLAG = False\n")
        try:
            update_config_file(path, {"FLAG": "True"})
            with open(path) as f:
                self.assertIn("FLAG = True", f.read())
        finally:
            tmpdir.cleanup()

    def test_update_string(self):
        tmpdir, path = self._write_config('NAME = "old"\n')
        try:
            update_config_file(path, {"NAME": '"new"'})
            with open(path) as f:
                self.assertIn('NAME = "new"', f.read())
        finally:
            tmpdir.cleanup()


class TestSafeGetAttr(unittest.TestCase):
    """safe_get_attr tests (dict or dataclass-style object access)"""

    def test_dict(self):
        self.assertEqual(safe_get_attr({"a": 1}, "a"), 1)

    def test_dict_missing(self):
        self.assertEqual(safe_get_attr({"a": 1}, "b"), "")

    def test_dict_none_value(self):
        self.assertEqual(safe_get_attr({"a": None}, "a"), "")

    def test_dict_default(self):
        self.assertEqual(safe_get_attr({"a": 1}, "b", "d"), "d")

    def test_object(self):
        class Obj:
            a = 1

        self.assertEqual(safe_get_attr(Obj(), "a"), 1)

    def test_object_missing(self):
        self.assertEqual(safe_get_attr(object(), "a"), "")


class TestStatusHelpers(unittest.TestCase):
    """is_url / is_ok_status / is_finding / status_severity tests"""

    def test_is_url(self):
        self.assertTrue(is_url("https://example.com/a"))
        self.assertTrue(is_url("http://example.com/a"))
        self.assertFalse(is_url("not a url"))
        self.assertFalse(is_url(None))
        self.assertFalse(is_url("http://x"))
        self.assertFalse(is_url(42))

    def test_is_ok_status(self):
        for s in ("", "ok", "OK", "success", "Success ", "pass"):
            self.assertTrue(is_ok_status(s))
        for s in ("fail", "warning", "new", "missing", "mismatch"):
            self.assertFalse(is_ok_status(s))

    def test_is_finding(self):
        self.assertTrue(is_finding("FAIL"))
        self.assertTrue(is_finding("new"))
        self.assertFalse(is_finding("ok"))
        self.assertFalse(is_finding(""))
        self.assertFalse(is_finding(None))

    def test_status_severity(self):
        for s in ("FAIL", "new", "CRIT", "critical", "MISMATCH"):
            self.assertEqual(status_severity(s), "CRIT")
        for s in ("WARNING", "warn", "missing", "removed"):
            self.assertEqual(status_severity(s), "WARN")
        for s in ("OK", "success"):
            self.assertEqual(status_severity(s), "OK")
        self.assertEqual(status_severity(""), "INFO")
        self.assertEqual(status_severity(None), "INFO")
        self.assertEqual(status_severity("bogus"), "INFO")


class TestRecommendationSeverity(unittest.TestCase):
    """rec_severity / audit_priority / status_rank tests"""

    def test_diff_crit(self):
        rec = {"expected_value": 2, "actual_value": 0, "status": "ok"}
        self.assertEqual(rec_severity(rec)[0], "CRIT")

    def test_diff_warn(self):
        rec = {"expected_value": 1, "actual_value": 0, "status": "ok"}
        self.assertEqual(rec_severity(rec)[0], "WARN")

    def test_diff_info(self):
        rec = {"expected_value": 0, "actual_value": 0, "status": "ok"}
        self.assertEqual(rec_severity(rec)[0], "INFO")

    def test_status_fail(self):
        self.assertEqual(rec_severity({"status": "FAIL"})[0], "CRIT")

    def test_status_warning(self):
        self.assertEqual(rec_severity({"status": "WARNING"})[0], "WARN")

    def test_status_mismatch(self):
        self.assertEqual(rec_severity({"status": "mismatch"})[0], "WARN")

    def test_status_missing(self):
        self.assertEqual(rec_severity({"status": "missing"})[0], "WARN")

    def test_info_fallback(self):
        self.assertEqual(rec_severity({"status": ""})[0], "INFO")
        self.assertEqual(rec_severity({})[0], "INFO")

    def test_non_numeric_values_fall_back_to_status(self):
        rec = {"expected_value": "n/a", "actual_value": "n/a", "status": "FAIL"}
        self.assertEqual(rec_severity(rec)[0], "CRIT")

    def test_object_rec(self):
        class Rec:
            expected_value = 5
            actual_value = 3
            status = "ok"

        self.assertEqual(rec_severity(Rec())[0], "CRIT")

    def test_audit_priority(self):
        self.assertEqual(
            audit_priority({"expected_value": 2, "actual_value": 0}), (0, "CRIT")
        )
        self.assertEqual(
            audit_priority({"expected_value": 1, "actual_value": 0}), (1, "WARN")
        )
        self.assertEqual(
            audit_priority({"expected_value": 0, "actual_value": 0}), (2, "INFO")
        )
        self.assertEqual(audit_priority({}), (2, "INFO"))

    def test_status_rank(self):
        self.assertEqual(status_rank({"status": "FAIL"}), 0)
        self.assertEqual(status_rank({"status": "WARNING"}), 1)
        self.assertEqual(status_rank({"status": "ok"}), 2)
        self.assertEqual(status_rank({"status": "bogus"}), 2)
        self.assertEqual(status_rank({}), 2)


class TestRecommendationText(unittest.TestCase):
    """suggestion_for / rec_context_rows tests"""

    def test_suggestion_from_raw_data(self):
        rec = {"raw_data": {"suggestion": "do this"}, "description": "desc"}
        self.assertEqual(suggestion_for(rec), "do this")

    def test_suggestion_falls_back_to_description(self):
        rec = {"raw_data": {}, "description": "some hint"}
        self.assertEqual(suggestion_for(rec), "some hint")

    def test_suggestion_ignores_no_description(self):
        rec = {"raw_data": {}, "description": "No description"}
        self.assertEqual(suggestion_for(rec), "See the docs section for details")

    def test_suggestion_related_fallback(self):
        rec = {"raw_data": {"related": "https://docs.example.com"}}
        self.assertEqual(suggestion_for(rec), "Check with: https://docs.example.com")

    def test_rec_context_rows_selinux(self):
        rec = {"source": "selinux", "raw_data": {"section": "s1", "persistent": "yes"}}
        self.assertEqual(rec_context_rows(rec), ["Section: s1", "Persistent: yes"])

    def test_rec_context_rows_proc(self):
        rec = {"source": "proc", "raw_data": {"username": "u", "pid": 5}}
        self.assertEqual(rec_context_rows(rec), ["User: u", "PID: 5"])

    def test_rec_context_rows_other_source(self):
        self.assertEqual(rec_context_rows({"source": "other"}), [])


class TestLinkExtraction(unittest.TestCase):
    """extract_links / dedupe_links tests"""

    def test_extract_links_from_raw_data(self):
        rec = {
            "raw_data": {
                "solution": "https://example.com/a",
                "details": "https://example.com/b",
                "links": ["https://example.com/a", "https://example.com/c"],
            }
        }
        self.assertEqual(
            extract_links(rec), ["https://example.com/a", "https://example.com/b", "https://example.com/c"]
        )

    def test_extract_links_top_level(self):
        rec = {"link": "https://example.com/x", "links": ["https://example.com/y"]}
        self.assertEqual(extract_links(rec), ["https://example.com/x", "https://example.com/y"])

    def test_extract_links_ignores_non_urls(self):
        rec = {"raw_data": {"solution": "see docs", "url": "https://example.com/d"}}
        self.assertEqual(extract_links(rec), ["https://example.com/d"])

    def test_extract_links_empty(self):
        self.assertEqual(extract_links({}), [])

    def test_dedupe_links_across_recs(self):
        recs = [
            {"raw_data": {"link": "https://example.com/a"}},
            {"raw_data": {"link": "https://example.com/a"}, "links": ["https://example.com/b"]},
        ]
        self.assertEqual(dedupe_links(recs), ["https://example.com/a", "https://example.com/b"])

    def test_dedupe_links_empty(self):
        self.assertEqual(dedupe_links([]), [])
        self.assertEqual(dedupe_links(None), [])


class TestSandboxFormatting(unittest.TestCase):
    """binary_output / format_run_timestamp / short_hash / kernel line tests"""

    def test_binary_output_no_marker(self):
        self.assertEqual(binary_output("  hello  "), "hello")

    def test_binary_output_with_marker(self):
        stdout = (
            "prefix\n========== BINARY OUTPUT START ==========\n"
            "payload\nEXIT_CODE=0\n========== BINARY OUTPUT END ==========\n"
        )
        self.assertEqual(binary_output(stdout), "payload")

    def test_binary_output_drops_exit_code_lines_only_after_marker(self):
        stdout = (
            "EXIT_CODE=1\n========== BINARY OUTPUT START ==========\n"
            "body\nEXIT_CODE=0\n========== BINARY OUTPUT END ==========\n"
        )
        self.assertEqual(binary_output(stdout), "body")

    def test_format_run_timestamp(self):
        self.assertEqual(format_run_timestamp("2024-01-15T10:30:00Z"), "10:30:00")
        self.assertEqual(
            format_run_timestamp("2024-01-15T10:30:00+02:00"), "10:30:00"
        )

    def test_format_run_timestamp_invalid(self):
        self.assertEqual(format_run_timestamp("garbage"), "garbage")
        self.assertEqual(format_run_timestamp(""), "")
        self.assertEqual(format_run_timestamp(None), "")

    def test_short_hash(self):
        self.assertEqual(short_hash("a" * 20), "a" * 12)
        self.assertEqual(short_hash("abc"), "abc")
        self.assertEqual(short_hash(""), "N/A")
        self.assertEqual(short_hash(None), "N/A")

    def test_format_kernel_line(self):
        self.assertEqual(format_kernel_line({"uname": "5.4.0"}), "5.4.0")
        self.assertEqual(format_kernel_line({"date": "some date"}), "some date")
        self.assertEqual(format_kernel_line({}), "N/A")

    def test_first_resource_line(self):
        self.assertEqual(
            first_resource_line("MemTotal: 100\nMemFree: 50"), "MemTotal: 100"
        )
        self.assertEqual(first_resource_line("x" * 300), "x" * 200)
        self.assertIsNone(first_resource_line(""))
        self.assertIsNone(first_resource_line(None))

    # -- format_execution_report / format_sandbox_detail ------------------

    _SAMPLE_REPORT: ClassVar[dict] = {
        "kernel": "6.9.0",
        "build_date": "2025-01-01 00:00:00 UTC",
        "cves_processed": 1,
        "stats": {
            "total": 10,
            "with_exploits": 3,
            "in_cisa_kev": 2,
            "ransomware_related": 1,
            "critical_count": 4,
            "avg_cvss": 7.5,
            "by_severity": {"CRITICAL": 2, "HIGH": 1},
        },
        "entries": [
            {
                "cve_id": "CVE-2026-0001",
                "description": "Bad exploit demo",
                "cvss_v3_score": 9.8,
                "severity": "CRITICAL",
                "sources": ["LES"],
                "pocs": [
                    {
                        "url": "https://github.com/x/y",
                        "language": "C",
                        "stars": 42,
                        "compile_cmd": "gcc -o x x.c",
                        "test_cmd": "./x",
                        "sandbox": {
                            "mode": "virtme-ng",
                            "returncode": 1,
                            "success": False,
                            "crashed": True,
                            "stdout": "line one\nline two",
                            "stderr": "boom",
                            "logs": {"exploit_hash": "abc123"},
                            "kernel_info": {"uname": "Linux 6.9.0", "date": "d"},
                            "resources": {"meminfo": "MemTotal: 512"},
                            "modules": ["mod_a"],
                            "processes": ["pid 1"],
                            "files": ["/etc/passwd"],
                        },
                    }
                ],
            },
            {
                "cve_id": "CVE-2026-0002",
                "description": "no poc",
                "sources": ["NIST"],
                "pocs": [
                    {
                        "url": "https://g/r",
                        "language": "rust",
                        "stars": 1,
                        "sandbox_error": "compile failed",
                    }
                ],
            },
        ],
    }

    def test_format_execution_report_header_and_stats(self):
        text = format_execution_report(self._SAMPLE_REPORT)
        self.assertIn("=== Execution Report ===", text)
        self.assertIn("Kernel:   6.9.0", text)
        self.assertIn("2025-01-01 00:00:00 UTC", text)
        self.assertIn("Entries:  2", text)
        self.assertIn("avg_cvss:     7.5", text)
        self.assertIn("CRITICAL: 2", text)

    def test_format_execution_report_cve_and_sandbox(self):
        text = format_execution_report(self._SAMPLE_REPORT)
        self.assertIn("CVE-2026-0001", text)
        self.assertIn("CVSS 9.8", text)
        self.assertIn("Bad exploit demo", text)
        self.assertIn("mode=virtme-ng returncode=1 success=False crashed=True", text)
        self.assertIn("abc123", text)
        self.assertIn("line one", text)
        self.assertIn("line two", text)
        self.assertIn("STDERR:", text)
        self.assertIn("boom", text)
        self.assertIn("mod_a", text)
        self.assertIn("pid 1", text)
        self.assertIn("/etc/passwd", text)
        self.assertIn("MemTotal: 512", text)

    def test_format_execution_report_sandbox_error_kept(self):
        text = format_execution_report(self._SAMPLE_REPORT)
        self.assertIn("CVE-2026-0002", text)
        self.assertIn("sandbox error: compile failed", text)

    def test_format_execution_report_empty(self):
        text = format_execution_report({})
        self.assertIn("=== Execution Report ===", text)
        self.assertIn("Entries:  0", text)

    def test_format_sandbox_detail_all_fields_present(self):
        data = {
            "sandbox_platform": "qemu",
            "run_timestamp": "2026-08-14T10:00:00+00:00",
            "exploit_file_hash": "beef",
            "execution_success": True,
            "exit_code": 0,
            "crashed": False,
            "stdout": "OUT\nline2",
            "stderr": "ERR",
            "stdin": "gcc && ./x",
            "open_processes": ["init"],
            "open_files": ["/proc/1/maps"],
            "modules": ["m"],
            "kernel_info": {"uname": "Linux 6.1"},
            "resources": {"meminfo": "MemTotal: 1"},
            "notes": "note here",
        }
        text = format_sandbox_detail(data)
        for needle in (
            "platform:      qemu",
            "beef",
            "success:       True",
            "exit_code:     0",
            "crashed:       False",
            "gcc && ./x",
            "note here",
            "Linux 6.1",
            "MemTotal: 1",
            "OUT",
            "line2",
            "ERR",
        ):
            self.assertIn(needle, text)

    def test_format_sandbox_detail_skips_empty_optional(self):
        text = format_sandbox_detail(
            {
                "sandbox_platform": "host",
                "execution_success": False,
                "exit_code": -1,
                "crashed": False,
            }
        )
        self.assertIn("platform:      host", text)
        self.assertNotIn("command:", text)
        self.assertNotIn("STDOUT:", text)
        self.assertNotIn("kernel_info:", text)



if __name__ == "__main__":
    unittest.main()
