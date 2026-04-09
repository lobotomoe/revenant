#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compile .po translation files to .mo binary format.

Uses GNU ``msgfmt`` when available, otherwise falls back to a
pure-Python compiler (no external dependencies).

Usage:
    python scripts/compile_translations.py
"""

from __future__ import annotations

import shutil
import struct
import subprocess
import sys
from pathlib import Path

from _po_common import parse_po_entries

LOCALES_DIR = Path(__file__).parent.parent / "src" / "revenant" / "ui" / "gui" / "i18n" / "locales"


def _compile_po_python(po_path: Path, mo_path: Path) -> None:
    """Pure-Python .po -> .mo compiler (GNU gettext binary format)."""
    messages = [(mid.encode(), mstr.encode()) for mid, mstr in parse_po_entries(po_path)]

    messages.sort(key=lambda pair: pair[0])

    # Build .mo (GNU gettext binary format)
    n = len(messages)
    id_table = 28
    str_table = id_table + 8 * n
    data_start = str_table + 8 * n

    ids_blob = b""
    strs_blob = b""
    id_entries: list[tuple[int, int]] = []
    str_entries: list[tuple[int, int]] = []

    for mid, mstr in messages:
        id_entries.append((len(mid), len(ids_blob)))
        ids_blob += mid + b"\0"
        str_entries.append((len(mstr), len(strs_blob)))
        strs_blob += mstr + b"\0"

    strs_start = data_start + len(ids_blob)

    out = bytearray()
    out += struct.pack("Ii", 0x950412DE, 0)
    out += struct.pack("i", n)
    out += struct.pack("i", id_table)
    out += struct.pack("i", str_table)
    out += struct.pack("ii", 0, 0)

    for length, offset in id_entries:
        out += struct.pack("ii", length, data_start + offset)
    for length, offset in str_entries:
        out += struct.pack("ii", length, strs_start + offset)

    out += ids_blob + strs_blob
    mo_path.write_bytes(bytes(out))


def _compile_po_msgfmt(po_path: Path, mo_path: Path) -> None:
    """Compile using system msgfmt command."""
    subprocess.run(
        ["msgfmt", "--check", "-o", str(mo_path), str(po_path)],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )


def main() -> int:
    po_files = sorted(LOCALES_DIR.rglob("*.po"))
    if not po_files:
        print("No .po files found.")
        return 1

    has_msgfmt = shutil.which("msgfmt") is not None
    compile_fn = _compile_po_msgfmt if has_msgfmt else _compile_po_python
    print(f"Using: {'msgfmt' if has_msgfmt else 'built-in compiler'}")

    errors = 0
    for po_path in po_files:
        mo_path = po_path.with_suffix(".mo")
        try:
            compile_fn(po_path, mo_path)
            print(f"  {po_path.relative_to(LOCALES_DIR)} -> .mo")
        except subprocess.CalledProcessError as e:
            print(f"  FAILED: {po_path.relative_to(LOCALES_DIR)}")
            if e.stderr:
                print(f"    {e.stderr.strip()}")
            errors += 1
        except Exception as e:
            print(f"  FAILED: {po_path.relative_to(LOCALES_DIR)}: {e}")
            errors += 1

    if errors:
        print(f"\n{errors} file(s) failed.")
        return 1

    print(f"Compiled {len(po_files)} translation(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
