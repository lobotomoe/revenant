#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check translation consistency for the Revenant GUI.

Extracts all _() calls from GUI source files and verifies that every
.po file has a non-empty translation for each string. Exits with code 1
if any translations are missing -- no fallbacks allowed.

Usage:
    python scripts/check_translations.py
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

GUI_DIR = Path(__file__).parent.parent / "src" / "revenant" / "ui" / "gui"
LOCALES_DIR = GUI_DIR / "i18n" / "locales"


def extract_translatable_strings() -> set[str]:
    """Walk all .py files under GUI_DIR and collect _("...") string literals."""
    strings: set[str] = set()
    for py_file in sorted(GUI_DIR.rglob("*.py")):
        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if (
                isinstance(func, ast.Name)
                and func.id == "_"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                strings.add(node.args[0].value)
    return strings


def parse_po_file(path: Path) -> dict[str, str]:
    """Parse a .po file and return {msgid: msgstr} mapping.

    Handles multiline strings. Skips the header entry (empty msgid).
    """
    from _po_common import parse_po_entries

    return {mid: mstr for mid, mstr in parse_po_entries(path) if mid}


def main() -> int:
    source_strings = extract_translatable_strings()
    if not source_strings:
        print("ERROR: No translatable strings found in source code.")
        return 1

    print(f"Found {len(source_strings)} translatable strings in source code.")

    po_files = sorted(p for p in LOCALES_DIR.rglob("*.po") if p.suffix == ".po")
    if not po_files:
        print("ERROR: No .po translation files found.")
        return 1

    errors = 0
    for po_path in po_files:
        locale = po_path.parent.parent.name  # e.g. "ru" from ru/LC_MESSAGES/revenant.po
        translations = parse_po_file(po_path)
        locale_errors = 0

        # Check for missing translations
        for s in sorted(source_strings):
            if s not in translations:
                print(f"  MISSING [{locale}]: {s!r}")
                locale_errors += 1
            elif not translations[s].strip():
                print(f"  EMPTY   [{locale}]: {s!r}")
                locale_errors += 1

        # Check for stale translations (in .po but not in source)
        for s in sorted(translations):
            if s not in source_strings:
                print(f"  STALE   [{locale}]: {s!r}")
                locale_errors += 1

        if locale_errors:
            print(f"  {locale}: {locale_errors} error(s)")
            errors += locale_errors
        else:
            print(f"  {locale}: OK ({len(translations)} translations)")

    if errors:
        print(f"\nFAILED: {errors} translation error(s) found.")
        return 1

    print("\nAll translations consistent.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
