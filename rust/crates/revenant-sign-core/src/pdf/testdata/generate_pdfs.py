#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate minimal PDF fixtures for the Rust pdf-module tests.

Produces small, real PDFs (via pikepdf/qpdf) that exercise the reader and the
incremental-update assembly:

  * blank_letter.pdf     -- 1 page, US Letter (612x792), traditional xref table
  * two_page_a4.pdf      -- 2 pages, A4 (595x842), traditional xref table
  * blank_letter_xref_stream.pdf -- 1 page, cross-reference *stream* (PDF 1.5+)
  * catalog_gen_1.pdf and catalog_gen_513.pdf -- a nonzero catalog generation
    and an embedded text file, with a traditional xref or a cross-reference stream
  * catalog_two_revisions.pdf -- only the second catalog exposes the attachment
  * page_gen_1.pdf and page_gen_513.pdf -- a nonzero target page generation

Run from the repo root:
    python/.venv/bin/python \\
        rust/crates/revenant-sign-core/src/pdf/testdata/generate_pdfs.py
"""

from __future__ import annotations

import struct
import zlib
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


def _generation_pdf(
    root_gen: int, *, xref_stream: bool, page_gen: int = 0, revise_catalog: bool = False
) -> bytes:
    # qpdf renumbers objects at generation 0 when saving. Write the small
    # fixture directly to control the generations used in references and the xref.
    pdf = bytearray(b"%PDF-1.7\n")
    entries = [(0, 0, 65535)]

    def add_object(body: bytes, gen: int = 0) -> None:
        number = len(entries)
        entries.append((1, len(pdf), gen))
        pdf.extend(f"{number} {gen} obj\n".encode() + body + b"\nendobj\n")

    catalog = b"<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles 4 0 R >> >>"
    add_object(b"<< /Type /Catalog /Pages 2 0 R >>" if revise_catalog else catalog, root_gen)
    add_object(f"<< /Type /Pages /Count 1 /Kids [3 {page_gen} R] >>".encode())
    add_object(
        b"<< /Type /Page /Parent 2 0 R /Resources << >> /MediaBox [0 0 612 792] >>",
        page_gen,
    )
    add_object(b"<< /Names [(note.txt) 5 0 R] >>")
    add_object(b"<< /Type /Filespec /F (note.txt) /EF << /F 6 0 R >> >>")
    note = zlib.compress(b"note\n")
    add_object(
        f"<< /Type /EmbeddedFile /Length {len(note)} /Filter /FlateDecode >>\nstream\n".encode()
        + note
        + b"\nendstream"
    )

    offset = len(pdf)
    root = f"/Root 1 {root_gen} R"
    if xref_stream:
        number = len(entries)
        entries.append((1, offset, 0))
        data = b"".join(struct.pack(">BIH", *entry) for entry in entries)
        pdf.extend(f"{number} 0 obj\n<< /Type /XRef /Size {len(entries)} {root} ".encode())
        pdf.extend(f"/W [1 4 2] /Length {len(data)} >>\nstream\n".encode())
        pdf.extend(data + b"\nendstream\nendobj\n")
    else:
        pdf.extend(f"xref\n0 {len(entries)}\n".encode())
        for kind, position, gen in entries:
            pdf.extend(f"{position:010} {gen:05} {'n' if kind else 'f'}\r\n".encode())
        pdf.extend(f"trailer\n<< /Size {len(entries)} {root} >>\n".encode())
    pdf.extend(f"startxref\n{offset}\n%%EOF\n".encode())
    if revise_catalog:
        number, position = len(entries), len(pdf)
        add_object(catalog)
        xref = len(pdf)
        pdf.extend(f"xref\n{number} 1\n{position:010} 00000 n\r\n".encode())
        # A comment is legal whitespace between the trailer key and its value.
        pdf.extend(f"trailer\n<< /Size {len(entries)} /Prev {offset} /Root % New catalog\n".encode())
        pdf.extend(f"{number} 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
    return bytes(pdf)


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

    (OUT_DIR / "catalog_gen_1.pdf").write_bytes(_generation_pdf(1, xref_stream=False))
    (OUT_DIR / "catalog_gen_513.pdf").write_bytes(_generation_pdf(513, xref_stream=True))
    (OUT_DIR / "catalog_two_revisions.pdf").write_bytes(
        _generation_pdf(1, xref_stream=False, revise_catalog=True)
    )
    (OUT_DIR / "page_gen_1.pdf").write_bytes(_generation_pdf(0, page_gen=1, xref_stream=False))
    (OUT_DIR / "page_gen_513.pdf").write_bytes(_generation_pdf(1, page_gen=513, xref_stream=True))

    for name in (
        "blank_letter.pdf",
        "two_page_a4.pdf",
        "blank_letter_xref_stream.pdf",
        "catalog_gen_1.pdf",
        "catalog_gen_513.pdf",
        "catalog_two_revisions.pdf",
        "page_gen_1.pdf",
        "page_gen_513.pdf",
    ):
        size = (OUT_DIR / name).stat().st_size
        print(f"wrote {name} ({size} bytes)")


if __name__ == "__main__":
    main()
