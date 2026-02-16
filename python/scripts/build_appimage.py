"""
Build AppImage for Revenant GUI on Linux.

Usage:
    python scripts/build_appimage.py

Prerequisites:
    - GUI binary must be built first: python scripts/build.py gui
    - appimagetool must be available in PATH or will be downloaded

Output:
    dist/Revenant-{arch}.AppImage    (e.g. Revenant-x86_64.AppImage, Revenant-aarch64.AppImage)
"""

import hashlib
import os
import platform
import stat
import subprocess
import sys
import urllib.request
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent
DIST_DIR = PROJECT_DIR / "dist"
APPIMAGE_DIR = PROJECT_DIR / "appimage"
APPDIR = DIST_DIR / "AppDir"

# ── Architecture detection ───────────────────────────────────────────

_ARCH_MAP = {"x86_64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}
ARCH = _ARCH_MAP.get(platform.machine(), "")

APPIMAGETOOL_BASE_URL = "https://github.com/AppImage/AppImageKit/releases/download/continuous"
APPIMAGETOOL_MIN_SIZE = 1_000_000  # legitimate appimagetool is > 1 MB
APPIMAGETOOL_DOWNLOAD_TIMEOUT = 120  # seconds

# Pinned SHA-256 hashes for supply chain integrity verification.
# The 'continuous' release is mutable -- these hashes ensure we detect changes.
# To update: download the new binary, verify it manually, then replace the hash.
# Last pinned: 2026-02-16
APPIMAGETOOL_SHA256 = {
    "x86_64": "b90f4a8b18967545fda78a445b27680a1642f1ef9488ced28b65398f2be7add2",
    "aarch64": "a48972e5ae91c944c5a7c80214e7e0a42dd6aa3ae979d8756203512a74ff574d",
}


def _check_platform():
    """Verify we're on Linux with a supported architecture."""
    if sys.platform != "linux":
        print("ERROR: AppImage can only be built on Linux", file=sys.stderr)
        sys.exit(1)
    if not ARCH:
        machine = platform.machine()
        print(f"ERROR: Unsupported architecture: {machine}", file=sys.stderr)
        sys.exit(1)
    print(f"Architecture: {ARCH}")


def _check_binary():
    """Verify GUI binary exists."""
    binary = DIST_DIR / "revenant-gui"
    if not binary.exists():
        print(
            "ERROR: GUI binary not found. Run 'python scripts/build.py gui' first.", file=sys.stderr
        )
        sys.exit(1)
    return binary


def _get_appimagetool():
    """Get appimagetool, downloading if necessary."""
    # Check if already in PATH
    result = subprocess.run(
        ["which", "appimagetool"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode == 0:
        return "appimagetool"

    # Check local copy (verify hash before trusting)
    expected_sha256 = APPIMAGETOOL_SHA256[ARCH]
    local_tool = DIST_DIR / "appimagetool"
    if local_tool.exists():
        local_hash = hashlib.sha256(local_tool.read_bytes()).hexdigest()
        if local_hash == expected_sha256:
            return str(local_tool)
        print(f"Local appimagetool hash mismatch (got {local_hash[:16]}...), re-downloading...")
        local_tool.unlink()

    # Download
    url = f"{APPIMAGETOOL_BASE_URL}/appimagetool-{ARCH}.AppImage"
    print(f"Downloading appimagetool ({ARCH})...")
    DIST_DIR.mkdir(parents=True, exist_ok=True)

    with urllib.request.urlopen(url, timeout=APPIMAGETOOL_DOWNLOAD_TIMEOUT) as resp:
        local_tool.write_bytes(resp.read())

    # Verify downloaded binary is plausible (size + ELF header)
    file_bytes = local_tool.read_bytes()
    file_size = len(file_bytes)
    if file_size < APPIMAGETOOL_MIN_SIZE:
        local_tool.unlink()
        print(
            f"ERROR: Downloaded appimagetool is suspiciously small ({file_size} bytes).",
            file=sys.stderr,
        )
        sys.exit(1)

    if file_bytes[:4] != b"\x7fELF":
        local_tool.unlink()
        print("ERROR: Downloaded appimagetool is not a valid ELF binary.", file=sys.stderr)
        sys.exit(1)

    # Verify SHA-256 hash to prevent supply chain attacks.
    actual_sha256 = hashlib.sha256(file_bytes).hexdigest()
    if actual_sha256 != expected_sha256:
        local_tool.unlink()
        print(
            f"ERROR: SHA-256 hash mismatch for appimagetool.\n"
            f"  Expected: {expected_sha256}\n"
            f"  Got:      {actual_sha256}\n"
            f"The 'continuous' release may have been updated. Verify the new\n"
            f"binary is legitimate, then update APPIMAGETOOL_SHA256 in this script.",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"Downloaded: {local_tool} ({file_size} bytes, sha256={actual_sha256[:16]}...)")

    local_tool.chmod(local_tool.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return str(local_tool)


def _create_appdir(binary):
    """Create AppDir structure."""
    import shutil

    # Clean previous
    if APPDIR.exists():
        shutil.rmtree(APPDIR)

    # Create structure
    usr_bin = APPDIR / "usr" / "bin"
    usr_bin.mkdir(parents=True)

    # Copy binary
    dest_binary = usr_bin / "revenant-gui"
    shutil.copy2(binary, dest_binary)
    dest_binary.chmod(dest_binary.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    # Copy AppRun
    apprun_src = APPIMAGE_DIR / "AppRun"
    apprun_dest = APPDIR / "AppRun"
    shutil.copy2(apprun_src, apprun_dest)
    apprun_dest.chmod(apprun_dest.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    # Copy desktop file to AppDir root (appimagetool requirement)
    desktop_name = "io.github.lobotomoe.revenant.desktop"
    desktop_src = APPIMAGE_DIR / desktop_name
    shutil.copy2(desktop_src, APPDIR / desktop_name)

    # Also install into standard XDG location (appstreamcli validation needs this)
    apps_dir = APPDIR / "usr" / "share" / "applications"
    apps_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(desktop_src, apps_dir / desktop_name)

    # Copy icon (named with app ID for Flathub compatibility)
    icon_name = "io.github.lobotomoe.revenant.png"
    icon_src = APPIMAGE_DIR / icon_name
    shutil.copy2(icon_src, APPDIR / icon_name)

    # Install icon into hicolor theme hierarchy (required by desktop environments)
    for size in ("256x256",):
        hicolor_dir = APPDIR / "usr" / "share" / "icons" / "hicolor" / size / "apps"
        hicolor_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(icon_src, hicolor_dir / icon_name)

    # Create .DirIcon symlink
    dir_icon = APPDIR / ".DirIcon"
    if dir_icon.exists():
        dir_icon.unlink()
    os.symlink(icon_name, dir_icon)

    # Copy AppStream metainfo (required by software centers)
    # appimagetool only searches for *.appdata.xml, so install under that name.
    # The source file uses the modern .metainfo.xml convention for Flathub.
    metainfo_dir = APPDIR / "usr" / "share" / "metainfo"
    metainfo_dir.mkdir(parents=True)
    metainfo_src = APPIMAGE_DIR / "io.github.lobotomoe.revenant.metainfo.xml"
    appdata_name = "io.github.lobotomoe.revenant.appdata.xml"
    if metainfo_src.exists():
        shutil.copy2(metainfo_src, metainfo_dir / appdata_name)

    print(f"Created AppDir: {APPDIR}")


def _build_appimage(appimagetool):
    """Run appimagetool to create AppImage."""
    output = DIST_DIR / f"Revenant-{ARCH}.AppImage"

    # Remove existing
    if output.exists():
        output.unlink()

    print("Building AppImage...")

    # appimagetool needs ARCH env var
    env = os.environ.copy()
    env["ARCH"] = ARCH

    result = subprocess.run(
        [appimagetool, str(APPDIR), str(output)],
        env=env,
        timeout=120,
    )

    if result.returncode != 0:
        print("ERROR: appimagetool failed", file=sys.stderr)
        sys.exit(1)

    size_mb = output.stat().st_size / (1024 * 1024)
    print(f"Created: {output} ({size_mb:.1f} MB)")

    return output


def main():
    """Entry point."""
    print("Revenant AppImage Builder")
    print("=" * 50)

    _check_platform()
    binary = _check_binary()
    appimagetool = _get_appimagetool()
    _create_appdir(binary)
    _build_appimage(appimagetool)

    print("\nDone!")


if __name__ == "__main__":
    main()
