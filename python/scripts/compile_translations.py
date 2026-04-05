#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compile .po translation files to .mo binary format using msgfmt.

Requires GNU gettext ``msgfmt`` command (pre-installed on macOS/Linux,
available via ``choco install gettext`` on Windows).

Usage:
    python scripts/compile_translations.py
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

LOCALES_DIR = (
    Path(__file__).parent.parent / "src" / "revenant" / "ui" / "gui" / "i18n" / "locales"
)


def main() -> int:
    msgfmt = shutil.which("msgfmt")
    if not msgfmt:
        print("ERROR: msgfmt not found. Install gettext.", file=sys.stderr)
        print("  macOS:   brew install gettext")
        print("  Debian:  sudo apt install gettext")
        print("  Windows: choco install gettext")
        return 1

    po_files = sorted(LOCALES_DIR.rglob("*.po"))
    if not po_files:
        print("No .po files found.")
        return 1

    errors = 0
    for po_path in po_files:
        mo_path = po_path.with_suffix(".mo")
        try:
            subprocess.run(
                [msgfmt, "--check", "-o", str(mo_path), str(po_path)],
                capture_output=True,
                text=True,
                timeout=30,
                check=True,
            )
            print(f"  {po_path.relative_to(LOCALES_DIR)} -> .mo")
        except subprocess.CalledProcessError as e:
            print(f"  FAILED: {po_path.relative_to(LOCALES_DIR)}")
            if e.stderr:
                print(f"    {e.stderr.strip()}")
            errors += 1

    if errors:
        print(f"\n{errors} file(s) failed.")
        return 1

    print(f"Compiled {len(po_files)} translation(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
