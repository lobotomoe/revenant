# SPDX-License-Identifier: Apache-2.0
# pyright: reportUnknownMemberType=false
"""Right-to-left layout support for the GUI.

Tk has no automatic widget mirroring like Qt or GTK, so RTL support is
implemented by right-aligning text in labels, entries and comboboxes through
the Tk option database. This covers the visible bulk of an RTL interface
(label text, message bodies, input fields) without rewriting every form's
grid geometry.

The active locale is fixed for the lifetime of the process (changing it from
Settings prompts a restart), so direction only needs to be applied once, after
the locale is initialized and before any widgets are created.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .i18n import is_rtl

if TYPE_CHECKING:
    import tkinter as tk

# Option-database defaults applied for RTL locales. Both classic Tk and ttk
# widgets fall back to these when neither the call site nor the active style
# sets the option explicitly.
_RTL_OPTION_DEFAULTS: dict[str, str] = {
    "*Label.anchor": "e",
    "*Label.justify": "right",
    "*TLabel.anchor": "e",
    "*TLabel.justify": "right",
    "*Entry.justify": "right",
    "*TEntry.justify": "right",
    "*TCombobox.justify": "right",
}


def apply_layout_direction(root: tk.Tk) -> None:
    """Apply text-direction defaults for the active locale.

    No-op for left-to-right locales. Must be called after ``init_locale`` and
    before widgets are created, since the option database is consulted at
    widget-construction time.
    """
    if not is_rtl():
        return
    for pattern, value in _RTL_OPTION_DEFAULTS.items():
        root.option_add(pattern, value)
