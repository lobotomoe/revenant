"""Entry point for Revenant GUI (PyInstaller and py2app)."""

import os
import sys


def _setup_tcl_tk():
    """Point TCL_LIBRARY/TK_LIBRARY to bundled Tcl/Tk in .app bundle.

    py2app bundles Tcl/Tk scripts into Contents/Resources/lib/,
    but the _tkinter extension still looks in the original homebrew
    path which is blocked by App Sandbox.
    """
    if not getattr(sys, "frozen", False):
        return
    resources = os.path.join(os.path.dirname(os.path.dirname(sys.executable)), "Resources")
    lib_dir = os.path.join(resources, "lib")
    if not os.path.isdir(lib_dir):
        return
    for entry in os.listdir(lib_dir):
        full = os.path.join(lib_dir, entry)
        if not os.path.isdir(full):
            continue
        if entry.startswith("tcl") and "TCL_LIBRARY" not in os.environ:
            os.environ["TCL_LIBRARY"] = full
        elif entry.startswith("tk") and "TK_LIBRARY" not in os.environ:
            os.environ["TK_LIBRARY"] = full


_setup_tcl_tk()

from revenant.ui.gui import main  # noqa: E402

main()
