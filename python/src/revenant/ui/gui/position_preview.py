# SPDX-License-Identifier: Apache-2.0
"""Signature position preview canvas for the sign form."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import tkinter as tk

# Canvas dimensions (A4 aspect ratio)
PREVIEW_W = 80
PREVIEW_H = 113
PREVIEW_MARGIN = 6

# Signature stamp proportions relative to A4 page (595x842pt)
_SIG_W_RATIO = 210 / 595
_SIG_H_RATIO = 70 / 842

_ALIGN: dict[str, tuple[str, str]] = {
    "bottom-left": ("left", "bottom"),
    "bottom-center": ("center", "bottom"),
    "bottom-right": ("right", "bottom"),
    "top-left": ("left", "top"),
    "top-center": ("center", "top"),
    "top-right": ("right", "top"),
}


def draw_position_preview(canvas: tk.Canvas, position: str) -> None:
    """Draw a mini page diagram showing where the signature stamp will land."""
    canvas.delete("all")

    m = PREVIEW_MARGIN
    pw = PREVIEW_W - 2 * m
    ph = PREVIEW_H - 2 * m

    # Page background
    canvas.create_rectangle(m, m, m + pw, m + ph, outline="#999", width=1, fill="white")

    # Fake text lines
    line_m = 6
    line_h = 3
    line_gap = 5
    for i in range(8):
        ly = m + line_m + i * (line_h + line_gap)
        if ly + line_h > m + ph - line_m:
            break
        lw = pw - 2 * line_m
        if i == 0:
            lw = int(lw * 0.6)
        elif i % 3 == 0:
            lw = int(lw * 0.75)
        canvas.create_rectangle(
            m + line_m, ly, m + line_m + lw, ly + line_h, fill="#ddd", outline=""
        )

    # Signature stamp
    sw = int(pw * _SIG_W_RATIO * 2.5)
    sh = int(ph * _SIG_H_RATIO * 2.5)
    sig_m = 4

    halign, valign = _ALIGN.get(position, ("right", "bottom"))

    sx = {"left": m + sig_m, "center": m + (pw - sw) // 2, "right": m + pw - sw - sig_m}[halign]
    sy = {"top": m + sig_m, "center": m + (ph - sh) // 2, "bottom": m + ph - sh - sig_m}[valign]

    canvas.create_rectangle(sx, sy, sx + sw, sy + sh, outline="#e67e22", width=2, fill="#fef3e0")
