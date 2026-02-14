"""
py2app setup for Revenant GUI (macOS only).

Builds a macOS .app bundle compatible with App Sandbox (required for MAS).
PyInstaller can't be used for sandboxed apps — its bootloader uses SysV
semaphores (semctl) which are blocked by App Sandbox.

Usage:
    PYTHONPATH=src python setup_mac.py py2app

The build must run from an isolated directory without pyproject.toml,
because py2app reads install_requires from it and fails. Use the build
script: python scripts/build.py mac
"""

import re
import subprocess
import sys
from pathlib import Path

from setuptools import setup

# Read version from pyproject.toml (single source of truth)
_toml_path = Path("pyproject.toml")
if not _toml_path.exists():
    _toml_path = Path("pyproject_version.toml")
_pyproject = _toml_path.read_text(encoding="utf-8")
_version_match = re.search(r'^version\s*=\s*"([^"]+)"', _pyproject, re.MULTILINE)
VERSION = _version_match.group(1) if _version_match else "0.0.0"

APP = ["scripts/gui_entry.py"]

ICON = "icons/revenant.icns"

# Find Tcl/Tk library directories (must be bundled for sandbox --
# sandboxed apps can't read from /opt/homebrew or /usr/local)
_tcl_lib_dir = subprocess.run(
    [sys.executable, "-c", "import tkinter; r=tkinter.Tk(); print(r.tk.eval('info library')); r.destroy()"],
    capture_output=True,
    text=True,
    timeout=10,
).stdout.strip()
_tcl_base = Path(_tcl_lib_dir).parent if _tcl_lib_dir else None

# Bundle Tcl/Tk script libraries into Resources/lib/
# Detect Tcl/Tk dir names dynamically (e.g. tcl9.0/tk9.0 or tcl8.6/tk8.6)
_data_files = []
if _tcl_base and _tcl_base.exists():
    _tcl_dir_name = Path(_tcl_lib_dir).name  # e.g. "tcl9.0"
    _tk_dir_name = _tcl_dir_name.replace("tcl", "tk", 1)  # e.g. "tk9.0"
    for lib_dir_name in [_tcl_dir_name, _tk_dir_name]:
        lib_dir = _tcl_base / lib_dir_name
        if not lib_dir.exists():
            continue
        for f in lib_dir.rglob("*"):
            if f.is_file():
                rel = f.relative_to(_tcl_base)
                dest = str(Path("lib") / rel.parent)
                _data_files.append((dest, [str(f)]))

OPTIONS = {
    "argv_emulation": False,
    "iconfile": ICON if Path(ICON).exists() else None,
    "packages": [
        "revenant",
        "pikepdf",
        "asn1crypto",
        "tlslite",
        "keyring",
        "defusedxml",
        "PIL",
    ],
    "includes": [
        "keyring.backends",
        "keyring.backends.macOS",
    ],
    "excludes": [
        "pytest",
        "ruff",
        "pyright",
        "pyinstaller",
        "py2app",
        "setuptools",
        "pkg_resources",
        "wheel",
    ],
    "resources": ["PrivacyInfo.xcprivacy"],
    "plist": {
        "CFBundleDisplayName": "Revenant",
        "CFBundleName": "Revenant",
        "CFBundleIdentifier": "io.github.lobotomoe.revenant",
        "CFBundleShortVersionString": VERSION,
        "CFBundleVersion": VERSION,
        "CFBundlePackageType": "APPL",
        "NSHumanReadableCopyright": "Copyright 2026 Aleksandr Kraiz. Apache License 2.0.",
        "NSHighResolutionCapable": True,
        "LSMinimumSystemVersion": "11.0",
        "LSApplicationCategoryType": "public.app-category.productivity",
        # MAS: app uses only exempt encryption (HTTPS/TLS)
        "ITSAppUsesNonExemptEncryption": False,
        "CFBundleDocumentTypes": [
            {
                "CFBundleTypeName": "PDF Document",
                "CFBundleTypeRole": "Editor",
                "LSItemContentTypes": ["com.adobe.pdf"],
                "LSHandlerRank": "Alternate",
            },
            {
                "CFBundleTypeName": "PKCS#7 Signature",
                "CFBundleTypeRole": "Viewer",
                "LSItemContentTypes": ["io.github.lobotomoe.revenant.p7s"],
                "LSHandlerRank": "Alternate",
            },
        ],
        # .p7s has no system UTI — declare a custom one
        "UTExportedTypeDeclarations": [
            {
                "UTTypeIdentifier": "io.github.lobotomoe.revenant.p7s",
                "UTTypeConformsTo": ["public.data"],
                "UTTypeDescription": "PKCS#7 Detached Signature",
                "UTTypeTagSpecification": {
                    "public.filename-extension": ["p7s"],
                    "public.mime-type": ["application/pkcs7-signature"],
                },
            },
        ],
    },
}

setup(
    name="Revenant",
    app=APP,
    data_files=_data_files,
    install_requires=[],
    options={"py2app": OPTIONS},
)
