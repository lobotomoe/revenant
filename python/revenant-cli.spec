# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for Revenant CLI binary (Linux only).

On Windows, Nuitka is used automatically by build.py.

Build:
    pyinstaller revenant-cli.spec

Or via the build script:
    python scripts/build.py cli
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

a = Analysis(
    ["scripts/cli_entry.py"],
    pathex=["src"],
    binaries=[],
    datas=[
        ("src/revenant/core/appearance/font_data/noto_sans/*.ttf",
         "revenant/core/appearance/font_data/noto_sans"),
        ("src/revenant/core/appearance/font_data/ghea_mariam/*.ttf",
         "revenant/core/appearance/font_data/ghea_mariam"),
        ("src/revenant/core/appearance/font_data/ghea_grapalat/*.ttf",
         "revenant/core/appearance/font_data/ghea_grapalat"),
    ] + ([("../LICENSE", ".")] if Path("../LICENSE").exists() else []),
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data)

exe_kwargs = {
    "name": "revenant",
    "debug": False,
    "bootloader_ignore_signals": False,
    "strip": False,
    "upx": True,
    "console": True,  # CLI mode -- keep console
    "disable_windowed_traceback": False,
    "argv_emulation": False,
    "target_arch": None,
    "codesign_identity": None,
    "entitlements_file": None,
}

# Add icon if available (Windows only for CLI)
icon_dir = Path("icons")
if is_windows and (icon_dir / "revenant.ico").exists():
    exe_kwargs["icon"] = str(icon_dir / "revenant.ico")

exe = EXE(pyz, a.scripts, a.binaries, a.zipfiles, a.datas, [], **exe_kwargs)
