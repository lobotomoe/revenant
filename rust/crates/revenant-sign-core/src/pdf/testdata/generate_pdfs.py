#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate minimal PDF fixtures for the Rust pdf-module tests.

Produces small, real PDFs (via pikepdf/qpdf) that exercise the reader and the
incremental-update assembly:

  * blank_letter.pdf     -- 1 page, US Letter (612x792), traditional xref table
  * two_page_a4.pdf      -- 2 pages, A4 (595x842), traditional xref table
  * blank_letter_xref_stream.pdf -- 1 page, cross-reference *stream* (PDF 1.5+)

Run from the repo root:
    python/.venv/bin/python \\
        rust/crates/revenant-sign-core/src/pdf/testdata/generate_pdfs.py
"""

from __future__ import annotations

from pathlib import Path

import pikepdf

OUT_DIR = Path(__file__).resolve().parent

LETTER = (612, 792)
A4 = (595, 842)


def _new(pages: list[tuple[int, int]]) -> pikepdf.Pdf:
    pdf = pikepdf.new()
    for size in pages:
        pdf.add_blank_page(page_size=size)
    return pdf


def main() -> None:
    # Traditional xref table (object streams disabled).
    with _new([LETTER]) as pdf:
        pdf.save(
            OUT_DIR / "blank_letter.pdf",
            object_stream_mode=pikepdf.ObjectStreamMode.disable,
            fix_metadata_version=False,
        )

    with _new([A4, A4]) as pdf:
        pdf.save(
            OUT_DIR / "two_page_a4.pdf",
            object_stream_mode=pikepdf.ObjectStreamMode.disable,
            fix_metadata_version=False,
        )

    # Cross-reference stream variant.
    with _new([LETTER]) as pdf:
        pdf.save(
            OUT_DIR / "blank_letter_xref_stream.pdf",
            object_stream_mode=pikepdf.ObjectStreamMode.generate,
            fix_metadata_version=False,
        )

    for name in ("blank_letter.pdf", "two_page_a4.pdf", "blank_letter_xref_stream.pdf"):
        size = (OUT_DIR / name).stat().st_size
        print(f"wrote {name} ({size} bytes)")


if __name__ == "__main__":
    main()
