"""Tests for lib_tools/peas2json.py - only stdlib (unittest)."""

import tempfile
import unittest
from typing import Any

from lib_tools import peas2json


def _reset_state() -> None:
    """Reset module globals the same way parse_peass does."""
    peas2json.FINAL_JSON = {}
    peas2json.C_SECTION = peas2json.FINAL_JSON
    peas2json.C_MAIN_SECTION = peas2json.FINAL_JSON
    peas2json.C_2_SECTION = peas2json.FINAL_JSON
    peas2json.C_3_SECTION = peas2json.FINAL_JSON


class TestIsSection(unittest.TestCase):
    def test_title1_pattern(self) -> None:
        line = "══════════════╣ User & Groups ╠══════════════"
        self.assertTrue(peas2json.is_section(line, peas2json.TITLE1_PATTERN))

    def test_title2_pattern(self) -> None:
        line = "╔══════════╣ CVEs Checked"
        self.assertTrue(peas2json.is_section(line, peas2json.TITLE2_PATTERN))

    def test_title3_pattern(self) -> None:
        line = "══╣ Check PE"
        self.assertTrue(peas2json.is_section(line, peas2json.TITLE3_PATTERN))

    def test_info_pattern(self) -> None:
        line = "╚ Something interesting"
        self.assertTrue(peas2json.is_section(line, peas2json.INFO_PATTERN))

    def test_no_match(self) -> None:
        self.assertFalse(
            peas2json.is_section("plain text line", peas2json.TITLE1_PATTERN)
        )

    def test_empty_line(self) -> None:
        self.assertFalse(peas2json.is_section("", peas2json.TITLE1_PATTERN))

    def test_title1_also_matches_title2_and_title3(self) -> None:
        # TITLE1 and TITLE2 both contain the TITLE3 marker "══╣"
        line = "╔══════════╣ Some section"
        self.assertTrue(peas2json.is_section(line, peas2json.TITLE3_PATTERN))


class TestGetColors(unittest.TestCase):
    def test_no_colors_returns_empty_dict(self) -> None:
        self.assertEqual(peas2json.get_colors("plain text"), {})

    def test_single_red_string(self) -> None:
        line = "\x1b[1;31mroot\x1b[0m is present"
        colors = peas2json.get_colors(line)
        self.assertIn("RED", colors)
        self.assertIn("root", colors["RED"])

    def test_clean_text_is_uncolored(self) -> None:
        line = "\x1b[1;32mPass\x1b[0m result"
        colors = peas2json.get_colors(line)
        self.assertIn("GREEN", colors)
        self.assertNotIn("\x1b", colors["GREEN"][0])

    def test_same_string_with_two_colors_keeps_first(self) -> None:
        line = "\x1b[1;33mdup\x1b[0m and \x1b[1;36mdup\x1b[0m"
        colors = peas2json.get_colors(line)
        for entries in colors.values():
            self.assertLessEqual(entries.count("dup"), 1)

    def test_empty_string(self) -> None:
        self.assertEqual(peas2json.get_colors(""), {})


class TestCleanTitle(unittest.TestCase):
    def test_removes_title_chars(self) -> None:
        line = "══════════════╣ Kernel Version ╠══════════════"
        self.assertEqual(peas2json.clean_title(line), "Kernel Version")

    def test_strips_surrounding_whitespace(self) -> None:
        self.assertEqual(peas2json.clean_title("   Foo   "), "Foo")

    def test_removes_non_ascii(self) -> None:
        self.assertEqual(peas2json.clean_title("café"), "caf")


class TestCleanColors(unittest.TestCase):
    def test_removes_ansi_codes(self) -> None:
        line = "\x1b[1;31mred\x1b[0m and \x1b[1;32mgreen\x1b[0m"
        self.assertEqual(peas2json.clean_colors(line), "red and green")

    def test_removes_lone_escape_byte(self) -> None:
        self.assertEqual(peas2json.clean_colors("foo\x1b[0m"), "foo")

    def test_color_only_line_cleans_to_empty(self) -> None:
        line = "\x1b[1;31m\x1b[0m"
        self.assertEqual(peas2json.clean_colors(line), "")

    def test_empty_string(self) -> None:
        self.assertEqual(peas2json.clean_colors(""), "")


class TestParseTitle(unittest.TestCase):
    def test_combines_both_cleaners(self) -> None:
        line = "══════════════╣ \x1b[1;36mActive Ports\x1b[0m ╠══"
        self.assertEqual(peas2json.parse_title(line), "Active Ports")


class TestParseLine(unittest.TestCase):
    def setUp(self) -> None:
        _reset_state()

    def test_text_before_any_section_is_ignored(self) -> None:
        peas2json.parse_line("stray text before any section")
        self.assertEqual(peas2json.FINAL_JSON, {})

    def test_info_before_any_section_is_ignored(self) -> None:
        peas2json.parse_line("╚ stray info before any section")
        self.assertEqual(peas2json.FINAL_JSON, {})

    def test_title1_creates_main_section(self) -> None:
        peas2json.parse_line("══════════════╣ System Information ╠══════════════")
        self.assertIn("System Information", peas2json.FINAL_JSON)
        section = peas2json.FINAL_JSON["System Information"]
        self.assertEqual(section["lines"], [])
        self.assertEqual(section["infos"], [])

    def test_text_goes_to_current_main_section(self) -> None:
        peas2json.parse_line("══════════════╣ System Information ╠══════════════")
        peas2json.parse_line("some detail line")
        section = peas2json.FINAL_JSON["System Information"]
        self.assertEqual(len(section["lines"]), 1)
        entry = section["lines"][0]
        self.assertEqual(entry["raw_text"], "some detail line")
        self.assertEqual(entry["clean_text"], "some detail line")
        self.assertEqual(entry["colors"], {})

    def test_title2_nested_under_main_section(self) -> None:
        peas2json.parse_line("══════════════╣ System Information ╠══════════════")
        peas2json.parse_line("╔══════════╣ Installed Tools")
        peas2json.parse_line("tool line")
        main = peas2json.FINAL_JSON["System Information"]
        self.assertIn("Installed Tools", main["sections"])
        self.assertEqual(main["sections"]["Installed Tools"]["lines"][0]["raw_text"], "tool line")

    def test_title3_nested_under_title2(self) -> None:
        peas2json.parse_line("══════════════╣ System Information ╠══════════════")
        peas2json.parse_line("╔══════════╣ Installed Tools")
        peas2json.parse_line("══╣ Check PE")
        peas2json.parse_line("pe line")
        section = peas2json.FINAL_JSON["System Information"]["sections"]["Installed Tools"]
        self.assertIn("Check PE", section["sections"])
        self.assertEqual(section["sections"]["Check PE"]["lines"][0]["raw_text"], "pe line")

    def test_info_appended_to_current_section(self) -> None:
        peas2json.parse_line("══════════════╣ System Information ╠══════════════")
        peas2json.parse_line("╚ something noteworthy")
        section = peas2json.FINAL_JSON["System Information"]
        self.assertIn("something noteworthy", section["infos"])

    def test_title2_before_title1_raises_key_error(self) -> None:
        # Documents current behavior: nesting requires a main section first.
        with self.assertRaises(KeyError):
            peas2json.parse_line("╔══════════╣ Orphan sub section")

    def test_title3_before_title2_raises_key_error(self) -> None:
        # Documents current behavior: TITLE3 requires a TITLE2 section first.
        peas2json.parse_line("══════════════╣ One ╠══════════════")
        with self.assertRaises(KeyError):
            peas2json.parse_line("══╣ Orphan level 3")

    def test_multiple_main_sections_accumulate(self) -> None:
        peas2json.parse_line("══════════════╣ One ╠══════════════")
        peas2json.parse_line("╔══════════╣ 1.2")
        peas2json.parse_line("══╣ 1.3")
        peas2json.parse_line("══════════════╣ Two ╠══════════════")
        peas2json.parse_line("╔══════════╣ 2.2")
        peas2json.parse_line("══╣ 2.3")
        self.assertIn("One", peas2json.FINAL_JSON)
        self.assertIn("Two", peas2json.FINAL_JSON)
        self.assertIn("1.3", peas2json.FINAL_JSON["One"]["sections"]["1.2"]["sections"])
        self.assertIn("2.3", peas2json.FINAL_JSON["Two"]["sections"]["2.2"]["sections"])


class TestParsePeass(unittest.TestCase):
    def _parse(self, content: str) -> dict[str, Any]:
        with tempfile.NamedTemporaryFile("w", encoding="utf8", suffix=".out") as f:
            f.write(content)
            f.flush()
            result = peas2json.parse_peass(f.name)
        self.assertIsNotNone(result)
        return result

    def test_empty_file_returns_empty_dict(self) -> None:
        self.assertEqual(self._parse(""), {})

    def test_blank_and_color_only_lines_are_skipped(self) -> None:
        content = "\n\n\x1b[1;31m\x1b[0m\n══════════════╣ System ╠══\n\n\x1b[0m\n"
        result = self._parse(content)
        self.assertIn("System", result)
        self.assertEqual(result["System"]["lines"], [])

    def test_no_state_leak_between_calls(self) -> None:
        first = self._parse("══════════════╣ First ╠══\nline\n")
        second = self._parse("══════════════╣ Second ╠══\n")
        self.assertNotIn("First", second)
        self.assertEqual(second, {"Second": {"sections": {}, "lines": [], "infos": []}})
        self.assertIn("First", first)

    def test_colored_text_is_parsed_clean(self) -> None:
        content = "══════════════╣ System ╠══\n\x1b[1;33mWarn\x1b[0m message\n"
        result = self._parse(content)
        entry = result["System"]["lines"][0]
        self.assertEqual(entry["clean_text"], "Warn message")
        self.assertIn("YELLOW", entry["colors"])

    def test_non_ascii_title_is_ascii_cleaned(self) -> None:
        content = "══════════════╣ Usuarios café ╠══\n"
        result = self._parse(content)
        self.assertIn("Usuarios caf", result)

    def test_deep_nesting_full_flow(self) -> None:
        content = (
            "══════════════╣ System Information ╠══════════════\n"
            "first line\n"
            "╔══════════╣ Installed Tools\n"
            "tool line\n"
            "══╣ Check PE\n"
            "pe line\n"
            "╚ extra info\n"
            "text after info\n"
        )
        result = self._parse(content)
        main = result["System Information"]
        self.assertEqual(main["lines"][0]["raw_text"], "first line")
        tools = main["sections"]["Installed Tools"]
        self.assertEqual(tools["lines"][0]["raw_text"], "tool line")
        pe = tools["sections"]["Check PE"]
        self.assertEqual(pe["lines"][0]["raw_text"], "pe line")
        self.assertEqual(len(pe["lines"]), 2)
        self.assertEqual(pe["lines"][1]["raw_text"], "text after info")
        self.assertIn("extra info", pe["infos"])

    def test_parse_to_json_file(self) -> None:
        content = "══════════════╣ System ╠══\nline\n"
        with tempfile.NamedTemporaryFile("w", encoding="utf8", suffix=".out") as src:
            src.write(content)
            src.flush()
            with tempfile.NamedTemporaryFile("w", suffix=".json") as dst:
                dst_path = dst.name
                self.assertIsNone(peas2json.parse_peass(src.name, dst_path))
                with open(dst_path) as f:
                    dumped = f.read()
        self.assertIn("System", dumped)
        self.assertIn("line", dumped)


if __name__ == "__main__":
    unittest.main()