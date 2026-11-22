"""Paths and configuration helpers.

Everything lives on the local machine:
  * bundled defaults  : ngm_panel/data/allowed_targets.json (inside the .exe)
  * user scope/config : %USERPROFILE%\\.ngm-panel\\ (Windows) / ~/.ngm-panel
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict

from . import APP_NAME, __version__

CONFIG_FILENAME = "allowed_targets.json"
SETTINGS_FILENAME = "settings.json"
HISTORY_FILENAME = "history"
LOG_FILENAME = "ngm-panel.log"

SCOPE_FILENAME = CONFIG_FILENAME


def home_dir() -> Path:
    """Override with NGM_PANEL_HOME (handy for portable installs / tests)."""
    override = os.environ.get("NGM_PANEL_HOME")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".ngm-panel"


def ensure_home() -> Path:
    directory = home_dir()
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def user_scope_path() -> Path:
    return home_dir() / CONFIG_FILENAME


def user_settings_path() -> Path:
    return home_dir() / SETTINGS_FILENAME


def history_path() -> Path:
    return home_dir() / HISTORY_FILENAME


def _bundled_file(name: str) -> Path:
    """Locate a file shipped next to the package (also inside a PyInstaller exe)."""
    candidates = [
        Path(__file__).resolve().parent / "data" / name,
        Path(getattr(__import__("sys"), "_MEIPASS", "")) / "ngm_panel" / "data" / name,
        Path(getattr(__import__("sys"), "_MEIPASS", "")) / "data" / name,
    ]
    for candidate in candidates:
        try:
            if candidate.is_file():
                return candidate
        except OSError:
            continue
    return candidates[0]


def read_bundled_scope() -> Dict[str, Any]:
    path = _bundled_file(CONFIG_FILENAME)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"version": 1, "targets": []}


def load_json(path: Path) -> Dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def save_json(path: Path, data: Dict[str, Any]) -> None:
    ensure_home()
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def ensure_user_scope() -> Path:
    """Create the user's scope file from the bundled defaults on first run."""
    path = user_scope_path()
    if not path.exists():
        data = read_bundled_scope()
        save_json(path, data)
    return path


def load_settings() -> Dict[str, Any]:
    return load_json(user_settings_path())


def save_settings(data: Dict[str, Any]) -> None:
    save_json(user_settings_path(), data)


def app_header() -> str:
    return f"{APP_NAME} {__version__}"
