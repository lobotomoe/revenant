"""Screenshot gallery generator for the Revenant GUI.

Captures the GUI in all locales and configuration states for
documentation, store listings, and visual regression testing.

Renders each screen with mock config data -- no server connection needed.

Usage:
    python python/scripts/screenshot_gallery.py [output_dir]
    python python/scripts/screenshot_gallery.py --dry-run

Requires: tkinter (with display or Xvfb on Linux), Pillow.

On macOS, Screen Recording permission must be granted to the terminal
(System Settings > Privacy & Security > Screen Recording).
CI runners (GitHub Actions) have this by default.
"""

# pyright: reportPrivateUsage=false, reportUnknownMemberType=false
from __future__ import annotations

import argparse
import json
import logging
import platform
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import patch

if TYPE_CHECKING:
    import tkinter as tk

    from revenant.ui.gui.app import RevenantGUI

_LOCALES = ("en", "ru", "hy")

_MOCK_IDENTITY: dict[str, str | None] = {
    "name": "John Smith 12345",
    "email": "john.smith@example.com",
    "organization": "Example Corp",
    "dn": "CN=John Smith 12345, O=Example Corp",
    "not_before": "2025-06-01T00:00:00",
    "not_after": "2027-06-01T00:00:00",
}

# Config data per configuration layer.
# Layer 0: nothing.  Layer 1: server only.  Layer 2: fully configured.
_LAYER_CONFIGS: dict[int, dict[str, object]] = {
    0: {},
    1: {
        "profile": "ekeng",
        "url": "https://ca.gov.am:8080/SAPIWS/DSS.asmx",
        "timeout": 120,
    },
    2: {
        "profile": "ekeng",
        "url": "https://ca.gov.am:8080/SAPIWS/DSS.asmx",
        "timeout": 120,
        "name": _MOCK_IDENTITY["name"],
        "email": _MOCK_IDENTITY["email"],
        "organization": _MOCK_IDENTITY["organization"],
        "not_before": _MOCK_IDENTITY["not_before"],
        "not_after": _MOCK_IDENTITY["not_after"],
    },
}

_logger = logging.getLogger(__name__)


# ── Screenshot capture ───────────────────────────────────────────────

_CAPTURE_SETTLE_MS = 200


def _capture(window: tk.Tk | tk.Toplevel, output: Path, *, dry_run: bool = False) -> None:
    """Capture a tkinter window screenshot.

    Uses ``screencapture`` on macOS (avoids Pillow/Quartz permission quirks)
    and ``Pillow.ImageGrab`` everywhere else.
    """
    # Let the window settle after layout changes
    window.after(_CAPTURE_SETTLE_MS, window.quit)
    window.mainloop()

    w = window.winfo_width()
    h = window.winfo_height()

    if dry_run:
        _logger.info("  [dry-run] %s (%dx%d)", output.name, w, h)
        return

    output.parent.mkdir(parents=True, exist_ok=True)

    if platform.system() == "Darwin":
        _capture_macos(window, output)
    else:
        _capture_imagegrab(window, output)

    _logger.info("  captured: %s (%dx%d)", output.name, w, h)


def _capture_macos(window: tk.Tk | tk.Toplevel, output: Path) -> None:
    """macOS: use ``screencapture -R x,y,w,h`` (region capture)."""
    x = window.winfo_rootx()
    y = window.winfo_rooty()
    w = window.winfo_width()
    h = window.winfo_height()
    region = f"{x},{y},{w},{h}"

    result = subprocess.run(
        ["screencapture", "-x", "-R", region, str(output)],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0 or not output.exists() or output.stat().st_size == 0:
        stderr = result.stderr.strip()
        msg = (
            f"screencapture failed for {output.name}: {stderr}\n"
            "Grant Screen Recording permission to your terminal:\n"
            "  System Settings > Privacy & Security > Screen Recording"
        )
        raise RuntimeError(msg)


def _capture_imagegrab(window: tk.Tk | tk.Toplevel, output: Path) -> None:
    """Linux/Windows: use Pillow ImageGrab."""
    from PIL import ImageGrab

    x = window.winfo_rootx()
    y = window.winfo_rooty()
    w = window.winfo_width()
    h = window.winfo_height()
    img = ImageGrab.grab(bbox=(x, y, x + w, y + h))
    img.save(str(output))


# ── Helpers ──────────────────────────────────────────────────────────


def _write_config(config_dir: Path, data: dict[str, object]) -> None:
    """Write config.json to the isolated config directory."""
    config_dir.mkdir(parents=True, exist_ok=True)
    config_file = config_dir / "config.json"
    config_file.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _destroy_children(root: tk.Tk) -> None:
    """Destroy all child widgets."""
    for child in root.winfo_children():
        child.destroy()


def _find_new_toplevel(
    root: tk.Tk,
    before: frozenset[str],
) -> tk.Toplevel | None:
    """Find a Toplevel created after the *before* snapshot was taken."""
    import tkinter as tk

    for child in root.winfo_children():
        if isinstance(child, tk.Toplevel) and str(child) not in before:
            return child
    return None


# ── Scene captures ───────────────────────────────────────────────────


def _capture_main_window(
    root: tk.Tk, config_dir: Path, layer: int, output: Path, *, dry_run: bool
) -> RevenantGUI:
    """Build main window at the given config layer and screenshot it."""
    _write_config(config_dir, _LAYER_CONFIGS[layer])
    _destroy_children(root)
    from revenant.ui.gui.app import RevenantGUI as _RevenantGUI

    gui = _RevenantGUI(root)
    _capture(root, output, dry_run=dry_run)
    return gui


def _capture_connect_dialog(root: tk.Tk, output: Path, *, dry_run: bool) -> None:
    """Screenshot the server selection dialog."""
    from revenant.ui.gui.connect_dialog import ConnectDialog

    dlg = ConnectDialog(root)
    _capture(dlg._win, output, dry_run=dry_run)
    dlg._win.destroy()


def _capture_login_steps(root: tk.Tk, output_dir: Path, *, dry_run: bool) -> None:
    """Screenshot all three login wizard steps."""
    from revenant.ui.gui.setup import LoginDialog

    # Step 1: credentials form
    with (
        patch("revenant.ui.gui.setup.get_credentials", return_value=(None, None)),
        patch("revenant.ui.gui.setup.is_keyring_available", return_value=False),
    ):
        login = LoginDialog(root)
    _capture(login._win, output_dir / "04-login-credentials.png", dry_run=dry_run)

    # Step 2: identity discovered (mock the server discovery thread)
    with patch("revenant.ui.gui.setup.run_in_thread"):
        login._step = 1
        login._show_step()
    login._identity = dict(_MOCK_IDENTITY)
    login._show_identity(login._identity)
    login._next_btn.configure(state="normal")
    _capture(login._win, output_dir / "05-login-identity.png", dry_run=dry_run)

    # Step 3: save/complete summary
    login._step = 2
    login._username = "demo_user"
    with patch(
        "revenant.ui.gui.setup.get_credential_storage_info",
        return_value="Config file (~/.revenant)",
    ):
        login._show_step()
    _capture(login._win, output_dir / "06-login-complete.png", dry_run=dry_run)

    login._win.destroy()


def _capture_settings_dialog(root: tk.Tk, output: Path, *, dry_run: bool) -> None:
    """Screenshot the settings dialog."""
    before = frozenset(str(c) for c in root.winfo_children())
    from revenant.ui.gui.dialogs import show_settings

    show_settings(root)
    dlg = _find_new_toplevel(root, before)
    if dlg is not None:
        _capture(dlg, output, dry_run=dry_run)
        dlg.destroy()


def _capture_about_dialog(root: tk.Tk, output: Path, *, dry_run: bool) -> None:
    """Screenshot the about dialog."""
    before = frozenset(str(c) for c in root.winfo_children())
    from revenant.ui.gui.dialogs import show_about

    show_about(root)
    dlg = _find_new_toplevel(root, before)
    if dlg is not None:
        _capture(dlg, output, dry_run=dry_run)
        dlg.destroy()


# ── Orchestration ────────────────────────────────────────────────────


def _capture_locale(root: tk.Tk, config_dir: Path, output_dir: Path, *, dry_run: bool) -> None:
    """Capture all screenshots for the current locale."""
    from tkinter import ttk

    _capture_main_window(
        root, config_dir, 0, output_dir / "01-main-unconfigured.png", dry_run=dry_run
    )
    _capture_connect_dialog(root, output_dir / "02-connect-dialog.png", dry_run=dry_run)
    _capture_main_window(
        root, config_dir, 1, output_dir / "03-main-server-only.png", dry_run=dry_run
    )
    _capture_login_steps(root, output_dir, dry_run=dry_run)
    gui = _capture_main_window(
        root, config_dir, 2, output_dir / "07-main-sign.png", dry_run=dry_run
    )

    # Switch to Verify tab
    notebook = gui._sign_tab.master
    if isinstance(notebook, ttk.Notebook):
        notebook.select(1)
    _capture(root, output_dir / "08-main-verify.png", dry_run=dry_run)

    _capture_settings_dialog(root, output_dir / "09-settings.png", dry_run=dry_run)
    _capture_about_dialog(root, output_dir / "10-about.png", dry_run=dry_run)


def run(output_dir: Path, *, dry_run: bool = False) -> None:
    """Generate the full screenshot gallery."""
    import tkinter as tk
    from tkinter import ttk

    from revenant.ui.gui.i18n import init_locale
    from revenant.ui.gui.utils import check_tkinter, enable_dpi_awareness

    ok, err = check_tkinter()
    if not ok:
        print(f"ERROR: {err}", file=sys.stderr)
        sys.exit(1)

    tmp = tempfile.mkdtemp(prefix="revenant-screenshots-")
    config_dir = Path(tmp) / "config"
    config_file = config_dir / "config.json"
    _write_config(config_dir, {})

    try:
        with (
            patch("revenant.config._storage.CONFIG_DIR", config_dir),
            patch("revenant.config._storage.CONFIG_FILE", config_file),
        ):
            enable_dpi_awareness()
            root = tk.Tk()
            root.withdraw()

            style = ttk.Style(root)
            for preferred in ("aqua", "vista", "clam", "default"):
                if preferred in style.theme_names():
                    style.theme_use(preferred)
                    break

            for locale_code in _LOCALES:
                _logger.info("Locale: %s", locale_code)
                init_locale(locale_code)
                locale_dir = output_dir / locale_code
                _capture_locale(root, config_dir, locale_dir, dry_run=dry_run)

            root.destroy()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    total = len(list(output_dir.rglob("*.png")))
    _logger.info("Done: %d screenshots in %s", total, output_dir)


# ── Store image composition ──────────────────────────────────────────

_STORE_SCENES: list[tuple[str, str | None, dict[str, str]]] = [
    (
        "07-main-sign.png",
        None,
        {
            "en": "Cross-platform CoSign client",
            "ru": "CoSign PDF Signer",
            "hy": "CoSign PDF Signer",
        },
    ),
    (
        "08-main-verify.png",
        None,
        {"en": "Verify Signatures", "ru": "Verify Signatures", "hy": "Verify Signatures"},
    ),
    (
        "01-main-unconfigured.png",
        "02-connect-dialog.png",
        {
            "en": "Pre-built EKENG profile",
            "ru": "Pre-built EKENG profile",
            "hy": "Pre-built EKENG profile",
        },
    ),
    (
        "03-main-server-only.png",
        "04-login-credentials.png",
        {
            "en": "Secure Authentication",
            "ru": "Secure Authentication",
            "hy": "Secure Authentication",
        },
    ),
]


def compose_store_images(
    raw_dir: Path,
    background: Path,
    output_dir: Path,
    size: tuple[int, int] | None = None,
) -> None:
    """Compose store-ready images from previously captured raw screenshots."""
    sys.path.insert(0, str(Path(__file__).parent))
    from _store_compose import compose  # type: ignore[import-not-found]

    _logger.info("Composing store images (bg=%s)", background.name)
    store_dir = output_dir / "store"

    for locale_code in _LOCALES:
        locale_raw = raw_dir / locale_code

        for idx, (window_file, overlay_file, titles) in enumerate(_STORE_SCENES, 1):
            window_path = locale_raw / window_file
            if not window_path.exists():
                _logger.warning("  skip: %s (not found)", window_path)
                continue

            overlay_path = locale_raw / overlay_file if overlay_file else None
            if overlay_path is not None and not overlay_path.exists():
                overlay_path = None

            title = titles.get(locale_code, titles["en"])
            out = store_dir / locale_code / f"{idx:02d}-{window_file}"
            compose(background, window_path, title, out, size, overlay_path=overlay_path)


def main() -> None:
    """CLI entry point."""
    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stdout)

    parser = argparse.ArgumentParser(description="Generate Revenant GUI screenshot gallery")
    parser.add_argument("output_dir", nargs="?", default="screenshots", help="Output directory")
    parser.add_argument("--dry-run", action="store_true", help="Build UI without capturing")
    parser.add_argument("--background", type=Path, help="Background image for store composition")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    if output_dir.exists():
        shutil.rmtree(output_dir)

    run(output_dir, dry_run=args.dry_run)

    if args.background is not None and not args.dry_run:
        compose_store_images(output_dir, args.background, output_dir)

    if not args.dry_run:
        zip_path = output_dir.with_suffix(".zip")
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in sorted(output_dir.rglob("*.png")):
                zf.write(f, f.relative_to(output_dir))
        _logger.info("Archive: %s", zip_path)


if __name__ == "__main__":
    main()
