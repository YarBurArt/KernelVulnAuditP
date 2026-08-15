import sys

from config import DB_BACKEND
from log_conf import setup_logging

try:
    from gui_app import GUI_E, GUIApp
except ImportError:
    GUI_E = False
    GUIApp = None  # type: ignore[misc, assignment]

from cli_app import main_cli
from db import get_db


def main():
    cli_flag = "--cli" in sys.argv
    gui_flag = "--gui" in sys.argv and GUI_E

    for flag in ("--cli", "--gui"):
        if flag in sys.argv:
            sys.argv.remove(flag)

    # logs is routed to the "Engine stdout" tab in TUI
    tui_mode = GUI_E and not cli_flag
    setup_logging(console=not tui_mode and not cli_flag)

    db = get_db(DB_BACKEND)
    if cli_flag:
        main_cli(db=db)
        return

    if gui_flag and GUI_E:
        try:
            GUIApp(db=db).run()
        finally:
            db.close()
        return

    if GUI_E:
        db = get_db(DB_BACKEND)
        try:
            GUIApp(db=db).run()
        finally:
            db.close()
    else:
        main_cli(db=db)


if __name__ == "__main__":
    main()
