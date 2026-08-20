"""Settings service: read/write the config file from the CLI --settings.

The app treats settings as an application-layer concern; the domain core
never reads config.
"""

import re
from pathlib import Path


def update_config_file(config_path: Path, updates: dict[str, str]) -> None:
    """
    update config by dict of {VAR_NAME: new_value}
    where value includes quotes if needed
    """
    config_path = Path(config_path)
    config_content = config_path.read_text(encoding="utf-8")

    for key, replacement in updates.items():
        if replacement.isdigit() or (
            replacement.startswith("-") and replacement[1:].isdigit()
        ):
            pattern = rf"^{key}\s*=\s*\d+"
        elif replacement in ("True", "False"):
            pattern = rf"^{key}\s*=\s*(True|False)"
        else:
            pattern = rf'^{key}\s*=\s*["\'].*["\']'

        config_content = re.sub(
            pattern, f"{key} = {replacement}", config_content, flags=re.MULTILINE
        )

    config_path.write_text(config_content, encoding="utf-8")


__all__ = ["update_config_file"]