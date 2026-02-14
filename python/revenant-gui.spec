# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for Revenant GUI binary (Linux only).

On macOS, use py2app instead: python scripts/build.py mac
On Windows, Nuitka is used automatically by build.py.

Build:
    pyinstaller revenant-gui.spec

Or via the build script:
    python scripts/build.py gui
"""

import sys
from pathlib import Path

is_windows = sys.platform == "win32"

# Collect all revenant submodules
revenant_modules = [
    "revenant",
    "revenant.errors",
    "revenant.core",
    "revenant.core.appearance",
    "revenant.core.appearance.fields",
    "revenant.core.appearance.font_data",
    "revenant.core.appearance.font_data.noto_sans",
    "revenant.core.appearance.font_data.noto_sans.metrics",
    "revenant.core.appearance.font_data.ghea_mariam",
    "revenant.core.appearance.font_data.ghea_mariam.metrics",
    "revenant.core.appearance.font_data.ghea_grapalat",
    "revenant.core.appearance.font_data.ghea_grapalat.metrics",
    "revenant.core.appearance.fonts",
    "revenant.core.appearance.image",
    "revenant.core.appearance.stream",
    "revenant.core.cert_info",
    "revenant.core.pdf",
    "revenant.core.pdf.asn1",
    "revenant.core.pdf.builder",
    "revenant.core.pdf.cms_extraction",
    "revenant.core.pdf.cms_info",
    "revenant.core.pdf.objects",
    "revenant.core.pdf.position",
    "revenant.core.pdf.render",
    "revenant.core.pdf.incremental",
    "revenant.core.pdf.verify",
    "revenant.constants",
    "revenant.core.signing",
    "revenant.network",
    "revenant.network.discovery",
    "revenant.network.legacy_tls",
    "revenant.network.protocol",
    "revenant.network.soap",
    "revenant.network.soap_envelope",
    "revenant.network.soap_parsers",
    "revenant.network.soap_transport",
    "revenant.network.transport",
    "revenant.config",
    "revenant.config._storage",
    "revenant.config.config",
    "revenant.config.credentials",
    "revenant.config.profiles",
    "revenant.ui",
    "revenant.ui.helpers",
    "revenant.ui.workflows",
    "revenant.ui.cli",
    "revenant.ui.cli.setup",
    "revenant.ui.cli.sign",
    "revenant.ui.cli.verify",
    "revenant.ui.gui",
    "revenant.ui.gui.app",
    "revenant.ui.gui.dialogs",
    "revenant.ui.gui.setup",
    "revenant.ui.gui.sign_form",
    "revenant.ui.gui.sign_worker",
    "revenant.ui.gui.utils",
    "revenant.ui.gui.verify",
    "revenant.ui.gui.verify_dialog",
    "revenant.ui.gui.connect_dialog",
]

# Optional: include pikepdf if available
try:
    import pikepdf  # noqa: F401

    pikepdf_available = True
except ImportError:
    pikepdf_available = False

hidden_imports = list(revenant_modules)
hidden_imports.append("defusedxml")
hidden_imports.append("defusedxml.ElementTree")
if pikepdf_available:
    hidden_imports.append("pikepdf")

# Keyring is imported at runtime in config/credentials.py
try:
    import keyring  # noqa: F401

    hidden_imports.append("keyring")
    hidden_imports.append("keyring.backends")
    if sys.platform == "darwin":
        hidden_imports.append("keyring.backends.macOS")
    elif is_windows:
        hidden_imports.append("keyring.backends.Windows")
    else:
        hidden_imports.append("keyring.backends.SecretService")
except ImportError:
    pass

datas_list = [
    ("src/revenant/core/appearance/font_data/noto_sans/*.ttf",
     "revenant/core/appearance/font_data/noto_sans"),
    ("src/revenant/core/appearance/font_data/ghea_mariam/*.ttf",
     "revenant/core/appearance/font_data/ghea_mariam"),
    ("src/revenant/core/appearance/font_data/ghea_grapalat/*.ttf",
     "revenant/core/appearance/font_data/ghea_grapalat"),
]

# Bundle LICENSE file at the top level of the binary
license_file = Path("..") / "LICENSE"
if license_file.exists():
    datas_list.append((str(license_file), "."))
binaries_list = []

a = Analysis(
    ["scripts/gui_entry.py"],
    pathex=["src"],
    binaries=binaries_list,
    datas=datas_list,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["pyi_splash"],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data)

# Add icon if available
icon_dir = Path("icons")

exe_kwargs = {
    "name": "revenant-gui",
    "debug": False,
    "bootloader_ignore_signals": False,
    "strip": False,
    "upx": True,
    "console": False,  # GUI mode -- no console window
    "disable_windowed_traceback": False,
    "argv_emulation": False,
    "target_arch": None,
    "codesign_identity": None,
    "entitlements_file": None,
}

if is_windows and (icon_dir / "revenant.ico").exists():
    exe_kwargs["icon"] = str(icon_dir / "revenant.ico")

exe = EXE(pyz, a.scripts, a.binaries, a.zipfiles, a.datas, [], **exe_kwargs)
