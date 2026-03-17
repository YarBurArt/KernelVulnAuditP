import sys

from config import DB_BACKEND
from db import get_db

from cli_app import main_cli
from gui_app import GUIApp, GUI_E


def main():
    cli_flag = "--cli" in sys.argv
    gui_flag = "--gui" in sys.argv and GUI_E

    for flag in ("--cli", "--gui"):
        if flag in sys.argv:
            sys.argv.remove(flag)

    if cli_flag:
        main_cli()
        return

    if gui_flag and GUI_E:
        db = get_db(DB_BACKEND)
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
        main_cli()


if __name__ == "__main__":
    main()
