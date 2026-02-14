"""
Low-level config file I/O for Revenant.

Handles reading, writing, and validating the on-disk config.json.
Used by both config.py and credentials.py — shared storage layer
that neither module owns privately.
"""

from __future__ import annotations

__all__ = [
    "CONFIG_DIR",
    "CONFIG_FILE",
    "load_config",
    "load_raw_config",
    "save_config",
]

import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any, TypedDict, cast

from ..constants import MAX_TIMEOUT, MIN_TIMEOUT

_logger = logging.getLogger(__name__)

CONFIG_DIR = Path.home() / ".revenant"
CONFIG_FILE = CONFIG_DIR / "config.json"


class ConfigDict(TypedDict, total=False):
    """Type definition for the config file structure."""

    profile: str
    url: str
    timeout: int
    username: str
    password: str
    name: str
    email: str
    organization: str
    dn: str


def load_raw_config() -> dict[str, object]:
    """Load raw config dict from disk, preserving all keys.

    Used for merge-and-save operations to preserve unknown keys
    (forward-compatibility with newer config versions).
    """
    try:
        data: Any = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return cast("dict[str, object]", data)
    except FileNotFoundError:
        pass
    except json.JSONDecodeError as e:
        _logger.warning("Config file corrupted, ignoring: %s", e)
    except OSError as e:
        _logger.warning("Cannot read config file: %s", e)
    return {}


def _pick_str(data: dict[str, object], key: str) -> str | None:
    """Return data[key] if it's a str, else None."""
    val = data.get(key)
    return val if isinstance(val, str) else None


def _validate_config_dict(data: dict[str, object]) -> ConfigDict:
    """Validate and return config dict, picking only known keys with correct types."""
    result: ConfigDict = {}
    for key in ("profile", "url", "username", "password", "name", "email", "organization", "dn"):
        val = _pick_str(data, key)
        if val is not None:
            result[key] = val  # type: ignore[literal-required]  # dynamic key from known set
    timeout_val = data.get("timeout")
    if isinstance(timeout_val, int):
        if MIN_TIMEOUT <= timeout_val <= MAX_TIMEOUT:
            result["timeout"] = timeout_val
        else:
            _logger.warning(
                "Config timeout=%d out of range [%d, %d], ignoring",
                timeout_val,
                MIN_TIMEOUT,
                MAX_TIMEOUT,
            )
    return result


def load_config() -> ConfigDict:
    """Load config from disk, returning only known typed keys."""
    return _validate_config_dict(load_raw_config())


def save_config(config: dict[str, object]) -> None:
    """Save config to disk with restricted permissions (0600).

    Uses atomic write (temp file + rename) to prevent corruption
    if the process is interrupted mid-write.
    """
    CONFIG_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Enforce directory permissions even if the directory already existed
    if os.name != "nt":
        try:
            CONFIG_DIR.chmod(0o700)
        except OSError:
            _logger.warning("Failed to set restrictive permissions on %s", CONFIG_DIR)
    content = json.dumps(config, indent=2, ensure_ascii=False) + "\n"
    # Write through the fd directly to avoid a window where the file has wrong permissions
    fd, tmp_path = tempfile.mkstemp(dir=CONFIG_DIR, suffix=".tmp")
    tmp = Path(tmp_path)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        fd = -1  # fd is now closed by the context manager
        if os.name != "nt":
            try:
                tmp.chmod(0o600)
            except OSError:
                _logger.exception(
                    "Failed to set restrictive permissions on %s. "
                    "Config file may be readable by other users.",
                    tmp,
                )
        tmp.replace(CONFIG_FILE)  # atomic on POSIX
    except BaseException:
        if fd >= 0:
            os.close(fd)
        tmp.unlink(missing_ok=True)
        raise
