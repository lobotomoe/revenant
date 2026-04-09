# SPDX-License-Identifier: Apache-2.0
"""Shared utilities for .po file parsing."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


def unquote(s: str) -> str:
    """Remove surrounding quotes and unescape basic PO escape sequences.

    Escape order matters: backslash escapes must be resolved first,
    otherwise ``\\\\n`` (literal backslash + n) would be misinterpreted
    as a newline.
    """
    s = s.strip()
    if s.startswith('"') and s.endswith('"'):
        s = s[1:-1]
    return s.replace("\\\\", "\x00").replace("\\n", "\n").replace('\\"', '"').replace("\x00", "\\")


def parse_po_entries(path: Path) -> list[tuple[str, str]]:
    """Parse a .po file and return a list of (msgid, msgstr) pairs.

    Handles multiline strings. Includes the header entry (empty msgid).
    """
    entries: list[tuple[str, str]] = []
    current_id: list[str] = []
    current_str: list[str] = []
    reading = ""  # "id" or "str"

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line.startswith("#"):
            continue
        if line.startswith("msgid "):
            if reading == "str":
                entries.append(("".join(current_id), "".join(current_str)))
            current_id = [unquote(line[6:])]
            current_str = []
            reading = "id"
        elif line.startswith("msgstr "):
            current_str = [unquote(line[7:])]
            reading = "str"
        elif line.startswith('"') and line.endswith('"'):
            if reading == "id":
                current_id.append(unquote(line))
            elif reading == "str":
                current_str.append(unquote(line))

    if reading == "str":
        entries.append(("".join(current_id), "".join(current_str)))

    return entries
