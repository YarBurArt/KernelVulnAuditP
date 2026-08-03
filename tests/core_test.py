"""Tests for core.py - only stdlib (unittest)."""

import tempfile
import unittest
from datetime import UTC, datetime

from core import (
    assign_value_by_key_type,
    calculate_criticality_score,
    chain_get,
    clean_command_string,
    count_by_key,
    dict_to_display_rows,
    ensure_list_in_dict,
    extract_code_block_commands,
    extract_cve_ids,
    extract_cvss,
    extract_english_description,
    extract_section_by_header,
    filter_items_by_date,
    filter_list_by_pred,
    flatten_dict_value,
    format_report,
    format_timestamp,
    group_by_key,
    merge_dicts_by_key,
    norm_sysctl_value,
    parse_date_string,
    parse_key_value_pairs,
    parse_key_with_brackets,
    safe_get_nested,
    strip_ansi_sequences,
    summarize_sandbox,
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


if __name__ == "__main__":
    unittest.main()
