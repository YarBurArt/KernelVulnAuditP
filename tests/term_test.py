"""Unit tests for term.py - stdlib-only terminal helpers."""

import io
import sys
import unittest
from unittest import mock

import term


class FakeStream:
    """A stream that can pretend to be (or not be) a TTY."""

    def __init__(self, isatty_result: bool = True, encoding: str = "utf-8"):
        self._isatty = isatty_result
        self.encoding = encoding
        self.written = ""

    def isatty(self) -> bool:
        return self._isatty

    def write(self, text: str) -> None:
        self.written += text

    def flush(self) -> None:
        pass


class TestSupportsColor(unittest.TestCase):
    def test_non_tty_stream_returns_false(self):
        self.assertFalse(term.supports_color(io.StringIO()))

    def test_stream_without_isatty_returns_false(self):
        self.assertFalse(term.supports_color(object()))

    def test_no_color_env_disables(self):
        os_patch = {**term.os.environ, "NO_COLOR": "1"}
        with mock.patch.dict(term.os.environ, os_patch):
            self.assertFalse(term.supports_color(FakeStream(True)))

    def test_dumb_term_disables(self):
        os_patch = {**term.os.environ, "TERM": "dumb"}
        with mock.patch.dict(term.os.environ, os_patch):
            self.assertFalse(term.supports_color(FakeStream(True)))

    def test_xterm_with_tty_enables(self):
        os_patch = {**term.os.environ, "TERM": "xterm-256color"}
        with mock.patch.dict(term.os.environ, os_patch):
            self.assertTrue(term.supports_color(FakeStream(True)))

    def test_default_stream_is_stdout(self):
        with mock.patch.object(term.sys, "stdout", FakeStream(False)):
            self.assertFalse(term.supports_color())


class TestPaint(unittest.TestCase):
    def test_no_color_returns_text_unchanged(self):
        with mock.patch.object(term, "supports_color", return_value=False):
            self.assertEqual(term.paint("hello", term.RED), "hello")

    def test_empty_color_returns_text_unchanged(self):
        self.assertEqual(term.paint("hello"), "hello")

    def test_color_wrapped_with_bold(self):
        with mock.patch.object(term, "supports_color", return_value=True):
            self.assertEqual(
                term.paint("hi", term.RED, bold=True),
                f"{term.BOLD}{term.RED}hi{term.RESET}",
            )

    def test_color_wrapped_plain(self):
        with mock.patch.object(term, "supports_color", return_value=True):
            self.assertEqual(term.paint("hi", term.RED), f"{term.RED}hi{term.RESET}")


class TestIsInteractive(unittest.TestCase):
    def test_both_stdin_and_stdout_tty(self):
        with (
            mock.patch.object(term.sys, "stdin", FakeStream(True)),
            mock.patch.object(term.sys, "stdout", FakeStream(True)),
        ):
            self.assertTrue(term.is_interactive())

    def test_stdin_not_tty(self):
        with (
            mock.patch.object(term.sys, "stdin", FakeStream(False)),
            mock.patch.object(term.sys, "stdout", FakeStream(True)),
        ):
            self.assertFalse(term.is_interactive())

    def test_streams_without_isatty(self):
        with (
            mock.patch.object(term.sys, "stdin", object()),
            mock.patch.object(term.sys, "stdout", object()),
        ):
            self.assertFalse(term.is_interactive())


class TestPager(unittest.TestCase):
    def test_non_interactive_prints_entire_text(self):
        out = io.StringIO()
        with (
            mock.patch.object(term, "is_interactive", return_value=False),
            mock.patch.object(term.sys, "stdout", out),
        ):
            term.pager("a\nb\nc")
        self.assertEqual(out.getvalue(), "a\nb\nc\n")

    def test_shorter_than_page_size_prints_all(self):
        out = io.StringIO()
        with (
            mock.patch.object(term, "is_interactive", return_value=True),
            mock.patch.object(term.sys, "stdout", out),
            mock.patch.object(term.sys, "stdin", FakeStream(True)),
            mock.patch.object(term, "input", lambda prompt="": "q"),
        ):
            term.pager("one\ntwo")
        self.assertEqual(out.getvalue(), "one\ntwo\n")

    def test_quit_on_q(self):
        out = io.StringIO()
        lines = "\n".join(f"line{i}" for i in range(50))
        with (
            mock.patch.object(term, "is_interactive", return_value=True),
            mock.patch.object(term.sys, "stdout", out),
            mock.patch.object(term, "input", lambda prompt="": "q"),
        ):
            term.pager(lines, page_size=10)
        self.assertIn("line0", out.getvalue())
        self.assertNotIn("line49", out.getvalue())

    def test_eof_error_returns(self):
        out = io.StringIO()
        with (
            mock.patch.object(term, "is_interactive", return_value=True),
            mock.patch.object(term.sys, "stdout", out),
            mock.patch.object(
                term, "input", side_effect=EOFError
            ),
        ):
            term.pager("x\ny\nz", page_size=1)
        self.assertIn("x", out.getvalue())

    def test_pages_through_with_enter_then_quit(self):
        out = io.StringIO()
        lines = "\n".join(f"line{i}" for i in range(50))
        answers = iter(["", "q"])
        with (
            mock.patch.object(term, "is_interactive", return_value=True),
            mock.patch.object(term.sys, "stdout", out),
            mock.patch.object(term, "input", lambda prompt="": next(answers)),
        ):
            term.pager(lines, page_size=10)
        self.assertIn("line0", out.getvalue())
        self.assertIn("line10", out.getvalue())
        self.assertNotIn("line20", out.getvalue())

    def test_pager_exits_when_text_is_exact_multiple(self):
        out = io.StringIO()
        lines = "\n".join(f"line{i}" for i in range(10))
        with (
            mock.patch.object(term, "is_interactive", return_value=True),
            mock.patch.object(term.sys, "stdout", out),
            mock.patch.object(term, "input", lambda prompt="": "q"),
        ):
            term.pager(lines, page_size=10)
        self.assertIn("line0", out.getvalue())
        self.assertIn("line9", out.getvalue())

    def test_pager_empty_text(self):
        out = io.StringIO()
        with (
            mock.patch.object(term, "is_interactive", return_value=True),
            mock.patch.object(term.sys, "stdout", out),
            mock.patch.object(term, "input", lambda prompt="": "q"),
        ):
            term.pager("", page_size=10)
        self.assertEqual(out.getvalue(), "")

    def test_keyboard_interrupt_returns(self):
        out = io.StringIO()
        with (
            mock.patch.object(term, "is_interactive", return_value=True),
            mock.patch.object(term.sys, "stdout", out),
            mock.patch.object(
                term, "input", side_effect=KeyboardInterrupt
            ),
        ):
            term.pager("x\ny", page_size=1)
        self.assertIn("x", out.getvalue())


class TestSupportsUnicode(unittest.TestCase):
    def test_dumb_term_returns_false(self):
        os_patch = {**term.os.environ, "TERM": "dumb"}
        with mock.patch.dict(term.os.environ, os_patch):
            self.assertFalse(term.supports_unicode(FakeStream(True)))

    def test_linux_term_returns_false(self):
        os_patch = {**term.os.environ, "TERM": "linux"}
        with mock.patch.dict(term.os.environ, os_patch):
            self.assertFalse(term.supports_unicode(FakeStream(True)))

    def test_vt_term_returns_false(self):
        os_patch = {**term.os.environ, "TERM": "vt100"}
        with mock.patch.dict(term.os.environ, os_patch):
            self.assertFalse(term.supports_unicode(FakeStream(True)))

    def test_non_tty_stream_returns_true(self):
        with mock.patch.dict(term.os.environ, {"TERM": "xterm"}):
            self.assertTrue(term.supports_unicode(FakeStream(False)))

    def test_utf8_tty_returns_true(self):
        os_patch = {**term.os.environ, "TERM": "xterm-256color"}
        with mock.patch.dict(term.os.environ, os_patch):
            self.assertTrue(term.supports_unicode(FakeStream(True, "utf-8")))

    def test_ascii_tty_returns_false(self):
        os_patch = {**term.os.environ, "TERM": "xterm-256color"}
        with mock.patch.dict(term.os.environ, os_patch):
            self.assertFalse(term.supports_unicode(FakeStream(True, "ascii")))

    def test_missing_encoding_falls_back_to_locale(self):
        os_patch = {**term.os.environ, "TERM": "xterm-256color"}
        with mock.patch.dict(term.os.environ, os_patch):
            with mock.patch.object(
                term.locale, "getencoding", return_value="UTF-8"
            ):
                self.assertTrue(
                    term.supports_unicode(FakeStream(True, None))
                )

    def test_locale_encoding_error_falls_back(self):
        os_patch = {**term.os.environ, "TERM": "xterm-256color"}
        with mock.patch.dict(term.os.environ, os_patch):
            with mock.patch.object(
                term.locale, "getencoding", side_effect=AttributeError
            ):
                self.assertFalse(
                    term.supports_unicode(FakeStream(True, None))
                )

    def test_stream_encoding_raises_uses_locale(self):
        class RaisingStream(FakeStream):
            @property
            def encoding(self):
                raise AttributeError

            def __init__(self, isatty_result=True):
                self._isatty = isatty_result

        os_patch = {**term.os.environ, "TERM": "xterm-256color"}
        with mock.patch.dict(term.os.environ, os_patch):
            with mock.patch.object(
                term.locale, "getencoding", return_value="UTF-8"
            ):
                self.assertTrue(
                    term.supports_unicode(RaisingStream(True))
                )


class TestUnicodeGlyph(unittest.TestCase):
    def tearDown(self):
        term._unicode_supported = None

    def test_uses_unicode_when_supported(self):
        with mock.patch.object(term, "supports_unicode", return_value=True):
            self.assertEqual(term.unicode_glyph("✓", "OK"), "✓")

    def test_uses_ascii_when_not_supported(self):
        with mock.patch.object(term, "supports_unicode", return_value=False):
            self.assertEqual(term.unicode_glyph("✓", "OK"), "OK")

    def test_caches_support_flag(self):
        term._unicode_supported = None
        with mock.patch.object(term, "supports_unicode") as mocked:
            term.unicode_glyph("✓", "OK")
            term.unicode_glyph("✓", "OK")
        mocked.assert_called_once()


class TestProgressBar(unittest.TestCase):
    def setUp(self):
        self.stream = FakeStream(False)

    def test_disabled_on_non_tty(self):
        bar = term.ProgressBar(total=10, stream=self.stream)
        self.assertFalse(bar.enabled)
        bar.update(5)
        bar.step()
        bar.finish()
        self.assertEqual(self.stream.written, "")

    def test_enabled_property_reflects_tty(self):
        tty = FakeStream(True)
        bar = term.ProgressBar(total=10, stream=tty)
        self.assertTrue(bar.enabled)

    def test_isatty_raises_disables_bar(self):
        class RaisingStream:
            def isatty(self):
                raise AttributeError

            def write(self, text):
                pass

            def flush(self):
                pass

        bar = term.ProgressBar(total=10, stream=RaisingStream())
        self.assertFalse(bar.enabled)

    def test_draw_writes_progress_line(self):
        tty = FakeStream(True)
        bar = term.ProgressBar(total=10, width=10, label="work", stream=tty)
        bar.update(5)
        self.assertIn("[#####-----]", tty.written)
        self.assertIn("50%", tty.written)
        self.assertIn("work", tty.written)

    def test_draw_with_color_wraps_bar(self):
        tty = FakeStream(True)
        with mock.patch.object(term, "supports_color", return_value=True):
            bar = term.ProgressBar(total=10, width=10, color=term.RED, stream=tty)
        self.assertEqual(bar._color, term.RED)
        bar.update(5)
        self.assertIn(term.RED, tty.written)
        self.assertIn(term.RESET, tty.written)

    def test_step_increments_progress(self):
        tty = FakeStream(True)
        bar = term.ProgressBar(total=4, width=4, stream=tty)
        bar.step()
        bar.step(2)
        self.assertIn("75%", tty.written)

    def test_set_total_and_label(self):
        tty = FakeStream(True)
        bar = term.ProgressBar(total=4, width=4, stream=tty)
        bar.set_total(8, label="new")
        self.assertEqual(bar._total, 8)
        self.assertEqual(bar._label, "new")
        bar.set_total(10)
        self.assertEqual(bar._total, 10)
        self.assertEqual(bar._label, "new")
        bar.set_label("other")
        self.assertEqual(bar._label, "other")

    def test_update_with_label_and_note(self):
        tty = FakeStream(True)
        bar = term.ProgressBar(total=10, width=10, stream=tty)
        bar.update(5, label="done", note="ok")
        self.assertIn("done", tty.written)
        self.assertIn("ok", tty.written)

    def test_detail_rerenders_with_note(self):
        tty = FakeStream(True)
        bar = term.ProgressBar(total=10, width=10, stream=tty)
        bar.detail("step", note="n1")
        self.assertIn("step", tty.written)
        self.assertIn("n1", tty.written)

    def test_finish_completes_bar_and_newline(self):
        tty = FakeStream(True)
        bar = term.ProgressBar(total=10, width=10, stream=tty)
        bar.update(4)
        bar.finish(label="all done")
        self.assertIn("[##########]", tty.written)
        self.assertIn("100%", tty.written)
        self.assertIn("\n", tty.written)

    def test_finish_without_total_shows_count(self):
        tty = FakeStream(True)
        bar = term.ProgressBar(width=10, stream=tty)
        bar.step(3)
        bar.finish()
        self.assertIn("3", tty.written)

    def test_total_zero_draws_no_percent(self):
        tty = FakeStream(True)
        bar = term.ProgressBar(width=10, stream=tty)
        bar.update(2)
        self.assertIn("[", tty.written)
        self.assertNotIn("%", tty.written)

    def test_total_negative_clamped_to_zero(self):
        bar = term.ProgressBar(total=-5, stream=self.stream)
        self.assertEqual(bar._total, 0)

    def test_width_minimum(self):
        bar = term.ProgressBar(total=1, width=1, stream=self.stream)
        self.assertEqual(bar._width, 4)


if __name__ == "__main__":
    unittest.main()