import pytest

from gui.app import GUI_E

pytestmark = pytest.mark.skipif(not GUI_E, reason="GTK4 not available")

GLib = None  # type: ignore[assignment]
Gtk = None  # type: ignore[assignment]
_gui_bar_factory = None  # type: ignore[assignment]

if GUI_E:
    import gi

    gi.require_version("Gtk", "4.0")

    from gi.repository import GLib, Gtk

    from gui.app import _GtkProgressBar  # noqa: E402

    _gui_bar_factory = _GtkProgressBar


@pytest.fixture
def gui():
    class FakeGUI:
        def __init__(self):
            self._progress_box = Gtk.Box()
            self._progress_label = Gtk.Label()
            self._progress_bar = Gtk.ProgressBar()

    return FakeGUI()


def _drain():
    while GLib.MainContext.default().iteration(False):
        pass


def test_gtk_progress_steps_to_fraction(gui):
    bar = _gui_bar_factory(gui, total=5, label="Local recon")
    bar.step(label="lynis")
    _drain()
    assert abs(gui._progress_bar.get_fraction() - 0.2) < 1e-6

    for label in ("linpeas", "les", "selinux/caps", "hardening"):
        bar.step(label=label)
    _drain()
    assert gui._progress_bar.get_fraction() == 1.0
    assert gui._progress_label.get_text() == "hardening"


def test_gtk_progress_finish_sets_full_and_appends_note(gui):
    bar = _gui_bar_factory(gui, total=4, label="Threat feeds")
    bar.step(label="NIST")
    _drain()
    assert abs(gui._progress_bar.get_fraction() - 0.25) < 1e-6

    bar.finish(note="3 findings")
    _drain()
    assert gui._progress_bar.get_fraction() == 1.0
    assert gui._progress_label.get_text() == "NIST 3 findings"


def test_gtk_progress_marshals_from_worker_thread(gui):
    import threading

    bar = _gui_bar_factory(gui, total=2, label="Exec")
    results = []

    def worker():
        bar.step(label="CVE-1")
        bar.step(label="CVE-2")
        results.append("done")

    t = threading.Thread(target=worker)
    t.start()
    t.join()
    _drain()

    assert results == ["done"]
    assert gui._progress_bar.get_fraction() == 1.0
    assert gui._progress_label.get_text() == "CVE-2"


def test_app_services_make_bar_uses_gtk_progress(gui):
    from app_services import AppServices

    svc = AppServices.__new__(AppServices)
    svc.progress = lambda total=0, label="": _gui_bar_factory(
        gui, total=total, label=label
    )
    bar = svc._make_bar(4, "Threat feeds")
    assert isinstance(bar, _gui_bar_factory)
