import sys

from config import DB_BACKEND
from log_conf import setup_logging

# In --cli mode we keep writing logs to file but keep the terminal clean.
_CLI_FLAG = "--cli" in sys.argv

setup_logging(console=not _CLI_FLAG)

from cli_app import main_cli
from db import get_db

try:
    from gui_app import GUI_E, GUIApp
except ImportError:
    GUI_E = False
    GUIApp = None  # type: ignore[misc, assignment]


def main():
    cli_flag = "--cli" in sys.argv
    gui_flag = "--gui" in sys.argv and GUI_E

    for flag in ("--cli", "--gui"):
        if flag in sys.argv:
            sys.argv.remove(flag)

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
