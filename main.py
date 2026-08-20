import sys

from application.di import build_container
from cli_app import main_cli
from config import DB_BACKEND
from db.db import ThreatDB
from log_conf import setup_logging

try:
    from gui_app import GUI_E, GUIApp
except ImportError:
    GUI_E = False
    GUIApp = None  # type: ignore[misc, assignment]


def main():
    cli_flag = "--cli" in sys.argv

    for flag in ("--cli", "--gui"):
        if flag in sys.argv:
            sys.argv.remove(flag)

    # logs is routed to the "Engine stdout" tab in TUI
    tui_mode = GUI_E and not cli_flag
    setup_logging(console=not tui_mode and not cli_flag)

    if cli_flag or not GUI_E:
        main_cli()
        return

    container = build_container(DB_BACKEND)
    db = container.get(ThreatDB)
    try:
        GUIApp(db=db).run()
    finally:
        db.close()


if __name__ == "__main__":
    main()