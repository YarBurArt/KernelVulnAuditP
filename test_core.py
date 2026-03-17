#!/usr/bin/env python3
"""Tests for core.py - only stdlib (unittest)."""
import unittest
from datetime import datetime, timezone
from core import (
    parse_date_string, filter_items_by_date, format_timestamp,
    dict_to_display_rows, flatten_dict_value, merge_dicts_by_key,
    safe_get_nested, strip_ansi_sequences, extract_section_by_header,
    extract_code_block_commands, clean_command_string,
    parse_key_with_brackets, ensure_list_in_dict, assign_value_by_key_type,
    parse_key_value_pairs, calculate_criticality_score,
    chain_get, filter_list_by_pred, group_by_key, count_by_key,
)


class TestDateParsing(unittest.TestCase):
    """date parsing tests"""

    def test_parse_iso_format(self):
        dt = parse_date_string('2024-01-15T10:30:00')
        self.assertIsNotNone(dt)
        self.assertEqual(dt.year, 2024)
        self.assertEqual(dt.month, 1)
        self.assertEqual(dt.day, 15)

    def test_parse_iso_with_z(self):
        dt = parse_date_string('2024-01-15T10:30:00Z')
        self.assertIsNotNone(dt)
        self.assertEqual(dt.tzinfo, timezone.utc)

    def test_parse_iso_with_offset(self):
        dt = parse_date_string('2024-01-15T10:30:00+01:00')
        self.assertIsNotNone(dt)
        self.assertEqual(dt.tzinfo, timezone.utc)

    def test_parse_rfc_format(self):
        dt = parse_date_string('Mon Jan 15 10:30:00 2024 +0000')
        self.assertIsNotNone(dt)
        self.assertEqual(dt.year, 2024)
        self.assertEqual(dt.month, 1)

    def test_parse_simple_date(self):
        dt = parse_date_string('2024-01-15')
        self.assertIsNotNone(dt)
        self.assertEqual(dt.year, 2024)
        self.assertEqual(dt.month, 1)
        self.assertEqual(dt.day, 15)

    def test_parse_invalid_date(self):
        dt = parse_date_string('not-a-date')
        self.assertIsNone(dt)

    def test_parse_empty_string(self):
        dt = parse_date_string('')
        self.assertIsNone(dt)

    def test_parse_none(self):
        dt = parse_date_string(None)
        self.assertIsNone(dt)

    def test_filter_items_by_date_no_min(self):
        items = [
            {'cve': {'published': '2024-01-15T00:00:00Z'}},
            {'cve': {'published': '2023-01-15T00:00:00Z'}},
        ]
        result = filter_items_by_date(items, min_timestamp=None)
        self.assertEqual(len(result), 2)

    def test_filter_items_by_date(self):
        min_ts = int(datetime(2024, 1, 1, tzinfo=timezone.utc).timestamp())
        items = [
            {'cve': {'published': '2024-01-15T00:00:00Z'}},
            {'cve': {'published': '2023-01-15T00:00:00Z'}},
        ]
        result = filter_items_by_date(items, min_timestamp=min_ts)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['cve']['published'], '2024-01-15T00:00:00Z')

    def test_filter_items_by_date_top_level(self):
        min_ts = int(datetime(2024, 1, 1, tzinfo=timezone.utc).timestamp())
        items = [
            {'published': '2024-01-15T00:00:00Z'},
            {'published': '2023-01-15T00:00:00Z'},
        ]
        result = filter_items_by_date(
            items, date_field='published', min_timestamp=min_ts)
        self.assertEqual(len(result), 1)

    def test_format_timestamp(self):
        ts = int(datetime(
            2024, 1, 15, 10, 30, tzinfo=timezone.utc).timestamp())
        result = format_timestamp(ts)
        self.assertIsNotNone(result)
        self.assertIn('2024', result)

    def test_format_timestamp_none(self):
        result = format_timestamp(None)
        self.assertIsNone(result)


class TestDictListProcessing(unittest.TestCase):
    """dict/list processing tests"""

    def test_dict_to_display_rows(self):
        data = [{'name': 'Alice', 'age': 30}, {'name': 'Bob', 'age': 25}]
        result = dict_to_display_rows(data)
        self.assertEqual(len(result), 2)
        self.assertIn(['name', 'Alice', 'Bob'], result)

    def test_dict_to_display_rows_empty(self):
        result = dict_to_display_rows([])
        self.assertEqual(result, [])

    def test_flatten_dict_value_dict(self):
        value = {'key1': 'val1', 'key2': 'val2'}
        result = flatten_dict_value(value)
        self.assertIn('key1: val1', result)

    def test_flatten_dict_value_list_of_dicts(self):
        value = [{'id': 1, 'name': 'A'}, {'id': 2, 'name': 'B'}]
        result = flatten_dict_value(value)
        self.assertIn('id: 1', result)

    def test_flatten_dict_value_list(self):
        value = [1, 2, 3]
        result = flatten_dict_value(value)
        self.assertEqual(result, '1, 2, 3')

    def test_flatten_dict_value_primitive(self):
        self.assertEqual(flatten_dict_value('hello'), 'hello')
        self.assertEqual(flatten_dict_value(42), '42')
        self.assertEqual(flatten_dict_value(None), '')

    def test_flatten_dict_value_max_length(self):
        value = {'key': 'x' * 1000}
        result = flatten_dict_value(value, max_length=50)
        self.assertLessEqual(len(result), 50)

    def test_merge_dicts_by_key_all(self):
        target = {'a': 1}
        source = {'b': 2, 'c': 3}
        result = merge_dicts_by_key(target, source)
        self.assertEqual(result, {'a': 1, 'b': 2, 'c': 3})

    def test_merge_dicts_by_key_selected(self):
        target = {'a': 1}
        source = {'b': 2, 'c': 3}
        result = merge_dicts_by_key(target, source, keys=['b'])
        self.assertEqual(result, {'a': 1, 'b': 2})
        self.assertNotIn('c', result)

    def test_safe_get_nested_single(self):
        data = {'a': 1}
        self.assertEqual(safe_get_nested(data, 'a'), 1)

    def test_safe_get_nested_deep(self):
        data = {'a': {'b': {'c': 42}}}
        self.assertEqual(safe_get_nested(data, 'a', 'b', 'c'), 42)

    def test_safe_get_nested_missing(self):
        data = {'a': {'b': 1}}
        self.assertEqual(safe_get_nested(data, 'a', 'c'), None)

    def test_safe_get_nested_default(self):
        data = {'a': 1}
        self.assertEqual(
            safe_get_nested(data, 'b', default='default'), 'default')


class TestTextParsing(unittest.TestCase):
    """text parsing tests"""

    def test_strip_ansi_sequences(self):
        text = '\x1b[31mred\x1b[0m normal'
        result = strip_ansi_sequences(text)
        self.assertEqual(result, 'red normal')

    def test_strip_ansi_multiple(self):
        text = '\x1b[1m\x1b[32mgreen bold\x1b[0m'
        result = strip_ansi_sequences(text)
        self.assertEqual(result, 'green bold')

    def test_extract_section_by_header(self):
        text = "## Requirements\n\nSome requirements here.\n\n## Other"
        patterns = [r'(?:requirements?)[\s:]+([^\n#]+)']
        result = extract_section_by_header(text, patterns)
        self.assertIsNotNone(result)

    def test_extract_section_not_found(self):
        text = "No sections here"
        patterns = [r'requirements']
        result = extract_section_by_header(text, patterns)
        self.assertIsNone(result)

    def test_extract_code_block_commands(self):
        text = "```bash\ngcc -O2 test.c -o test\n```"
        patterns = [r'gcc\s+\S+']
        result = extract_code_block_commands(
            text, patterns, languages=['bash'])
        self.assertGreaterEqual(len(result), 1)
        self.assertIn('gcc', result[0])

    def test_extract_code_block_commands_no_languages(self):
        text = "```\ngcc -O2 test.c -o test\n```"
        patterns = [r'gcc\s+\S+']
        result = extract_code_block_commands(text, patterns, languages=[])
        self.assertGreaterEqual(len(result), 1)

    def test_extract_code_block_commands_no_blocks(self):
        text = "No code blocks here"
        result = extract_code_block_commands(text, [r'gcc'], languages=[])
        self.assertEqual(result, [])

    def test_clean_command_string(self):
        cmd = "```gcc test.c```"
        result = clean_command_string(cmd)
        self.assertEqual(result, 'gcc test.c')

    def test_clean_command_string_multiline(self):
        cmd = "gcc test.c\nother line"
        result = clean_command_string(cmd)
        self.assertEqual(result, 'gcc test.c')


class TestKeyValueParsing(unittest.TestCase):
    """key-value parsing tests"""

    def test_parse_key_with_brackets_simple(self):
        base, inner = parse_key_with_brackets('key')
        self.assertEqual(base, 'key')
        self.assertIsNone(inner)

    def test_parse_key_with_brackets_list(self):
        base, inner = parse_key_with_brackets('key[]')
        self.assertEqual(base, 'key')
        self.assertEqual(inner, '')

    def test_parse_key_with_brackets_dict(self):
        base, inner = parse_key_with_brackets('key[name]')
        self.assertEqual(base, 'key')
        self.assertEqual(inner, 'name')

    def test_ensure_list_in_dict_new(self):
        container = {}
        ensure_list_in_dict(container, 'key', 'value')
        self.assertEqual(container, {'key': ['value']})

    def test_ensure_list_in_dict_existing(self):
        container = {'key': ['value1']}
        ensure_list_in_dict(container, 'key', 'value2')
        self.assertEqual(container, {'key': ['value1', 'value2']})

    def test_ensure_list_in_dict_convert(self):
        container = {'key': 'value1'}
        ensure_list_in_dict(container, 'key', 'value2')
        self.assertEqual(container, {'key': ['value1', 'value2']})

    def test_assign_value_scalar(self):
        results = {}
        assign_value_by_key_type(results, 'key', None, 'value')
        self.assertEqual(results, {'key': 'value'})

    def test_assign_value_list(self):
        results = {}
        assign_value_by_key_type(results, 'key', '', 'value')
        self.assertEqual(results, {'key': ['value']})

    def test_assign_value_dict(self):
        results = {}
        assign_value_by_key_type(results, 'base', 'name', 'value')
        self.assertEqual(results, {'base': {'name': 'value'}})

    def test_assign_value_error(self):
        results = {'base': 'scalar'}
        with self.assertRaises(ValueError):
            assign_value_by_key_type(results, 'base', 'name', 'value')

    def test_parse_key_value_pairs(self):
        blob = "key1:value1;key2:value2"
        result = parse_key_value_pairs(blob)
        self.assertEqual(result, {'key1': 'value1', 'key2': 'value2'})

    def test_parse_key_value_pairs_empty(self):
        result = parse_key_value_pairs("")
        self.assertEqual(result, {})


class TestCriticalityScore(unittest.TestCase):
    """criticality score tests"""

    def test_empty_data(self):
        score = calculate_criticality_score({})
        self.assertEqual(score, 0)

    def test_cisa_kev_only(self):
        data = {'in_cisa_kev': True}
        score = calculate_criticality_score(data)
        self.assertEqual(score, 40)

    def test_cisa_kev_ransomware(self):
        data = {'in_cisa_kev': True, 'known_ransomware': True}
        score = calculate_criticality_score(data)
        self.assertEqual(score, 60)

    def test_exploit_only(self):
        data = {'has_exploit': True}
        score = calculate_criticality_score(data)
        self.assertEqual(score, 25)

    def test_exploit_multiple(self):
        data = {'has_exploit': True, 'exploit_count': 10}
        score = calculate_criticality_score(data)
        self.assertEqual(score, 35)

    def test_cvss_only(self):
        data = {'cvss_v3_score': 9.8}
        score = calculate_criticality_score(data)
        self.assertEqual(score, int(9.8 * 2))

    def test_full_critical(self):
        data = {
            'in_cisa_kev': True, 'known_ransomware': True,
            'has_exploit': True, 'exploit_count': 10,
            'cvss_v3_score': 10.0, 'github_refs': 10, 'exploitdb_refs': 10,
        }
        score = calculate_criticality_score(data)
        self.assertEqual(score, 100)

    def test_max_score_cap(self):
        data = {
            'in_cisa_kev': True, 'known_ransomware': True,
            'has_exploit': True, 'exploit_count': 100,
            'cvss_v3_score': 10.0, 'github_refs': 100, 'exploitdb_refs': 100,
        }
        score = calculate_criticality_score(data)
        self.assertEqual(score, 100)


class TestPipelineUtilities(unittest.TestCase):
    """pipeline utilities tests"""

    def test_chain_get_simple(self):
        data = {'a': 1}
        self.assertEqual(chain_get(data, 'a'), 1)

    def test_chain_get_nested(self):
        data = {'a': {'b': {'c': 42}}}
        self.assertEqual(chain_get(data, 'a.b.c'), 42)

    def test_chain_get_list_index(self):
        data = {'items': [{'name': 'first'}]}
        self.assertEqual(chain_get(data, 'items.0.name'), 'first')

    def test_chain_get_missing(self):
        data = {'a': 1}
        self.assertEqual(chain_get(data, 'b'), None)

    def test_chain_get_default(self):
        data = {'a': 1}
        self.assertEqual(chain_get(data, 'b', default='default'), 'default')

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
            {'category': 'A', 'value': 1},
            {'category': 'B', 'value': 2},
            {'category': 'A', 'value': 3},
        ]
        result = group_by_key(items, 'category')
        self.assertEqual(len(result), 2)
        self.assertEqual(len(result['A']), 2)

    def test_count_by_key(self):
        items = [{'status': 'OK'}, {'status': 'FAIL'}, {'status': 'OK'}]
        result = count_by_key(items, 'status')
        self.assertEqual(result, {'OK': 2, 'FAIL': 1})


if __name__ == '__main__':
    unittest.main()
