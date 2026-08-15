"""Tests for the TUI progress adapter (GTK _GtkProgressBar port)."""

import threading

from gui.entities.progress import ProgressAdapter


class FakeTarget:
    """Minimal stand-in for the Textual ProgressBox widget."""

    def __init__(self):
        self.fraction = 0.0
        self.label = ""
        self.visible = False
        self.final = False

    def update(self, fraction, label, visible=True, final=False):
        self.fraction = fraction
        self.label = label
        self.visible = visible
        self.final = final


def test_steps_to_fraction():
    target = FakeTarget()
    bar = ProgressAdapter(target, total=5, label="Local recon")
    bar.step(label="lynis")
    assert abs(target.fraction - 0.2) < 1e-6

    for label in ("linpeas", "les", "selinux/caps", "hardening"):
        bar.step(label=label)
    assert abs(target.fraction - 1.0) < 1e-6
    assert target.label == "hardening"


def test_finish_sets_full_and_appends_note():
    target = FakeTarget()
    bar = ProgressAdapter(target, total=4, label="Threat feeds")
    bar.step(label="NIST")
    assert abs(target.fraction - 0.25) < 1e-6

    bar.finish(note="3 findings")
    assert target.fraction == 1.0
    assert target.label == "NIST 3 findings"
    assert target.final is True


def test_marshals_from_worker_thread():
    target = FakeTarget()
    bar = ProgressAdapter(target, total=2, label="Exec")
    results = []

    def worker():
        bar.step(label="CVE-1")
        bar.step(label="CVE-2")
        results.append("done")

    t = threading.Thread(target=worker)
    t.start()
    t.join()

    assert results == ["done"]
    assert abs(target.fraction - 1.0) < 1e-6
    assert target.label == "CVE-2"


def test_app_services_make_bar_with_sync_factory():
    from app_services import AppServices

    target = FakeTarget()
    svc = AppServices.__new__(AppServices)
    svc.progress = lambda total=0, label="": ProgressAdapter(
        target, total=total, label=label
    )
    bar = svc._make_bar(4, "Threat feeds")
    assert bar._total == 4
    assert target.label == "Threat feeds"


def test_step_with_note_reaches_on_label():
    target = FakeTarget()
    events = []

    def on_label(label, final, note):
        events.append((label, final, note))

    bar = ProgressAdapter(
        target, total=3, label="Local recon", on_label=on_label
    )
    bar.step(label="lynis", note="147 checks")

    assert ("lynis", False, "147 checks") in events
    assert "lynis 147 checks" in target.label


def test_detail_carries_note_without_advancing():
    target = FakeTarget()
    events = []

    def on_label(label, final, note):
        events.append((label, final, note))

    bar = ProgressAdapter(
        target, total=2, label="Executing PoCs", on_label=on_label
    )
    bar.step(label="CVE-2024-1")
    before = bar._n
    bar.detail(label="CVE-2024-1", note="2 PoCs · 1 crashed · qemu")

    assert bar._n == before
    assert ("CVE-2024-1", False, "2 PoCs · 1 crashed · qemu") in events
    assert "2 PoCs · 1 crashed · qemu" in target.label