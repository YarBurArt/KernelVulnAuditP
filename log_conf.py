import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path


LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

LOG_FILE = LOG_DIR / "kernel_audit.log"


def setup_logging(level: int = logging.INFO) -> None:
    root_logger = logging.getLogger()

    if root_logger.handlers:
        return

    root_logger.setLevel(level)

    formatter = logging.Formatter(
        fmt=(
            "%(asctime)s | "
            "[%(levelname)-8s] | "
            "%(name)s | "
            "%(message)s"
        ),
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    file_handler = RotatingFileHandler(
        LOG_FILE, maxBytes= 5 * 1024 * 1024,
        backupCount=5, encoding="utf-8",
    )
    file_handler.setFormatter(formatter)

    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)
