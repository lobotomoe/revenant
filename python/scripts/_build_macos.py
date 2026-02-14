"""macOS build backend: py2app (.app bundle) and DMG creation."""

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from _build_common import DIST_DIR, SPEC_DIR


def has_create_dmg():
    """Check if create-dmg is available."""
    result = subprocess.run(
        ["which", "create-dmg"],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def create_dmg():
    """Create a .dmg file from the macOS .app bundle (macOS only)."""
    if sys.platform != "darwin":
        return

    app_path = DIST_DIR / "Revenant.app"
    if not app_path.exists():
        return

    dmg_path = DIST_DIR / "Revenant.dmg"
    print(f"\nCreating DMG: {dmg_path}")

    # Remove existing DMG
    if dmg_path.exists():
        dmg_path.unlink()

    # Clean up stale temporary DMGs from previous create-dmg runs
    for tmp_dmg in DIST_DIR.glob("rw.*.dmg"):
        tmp_dmg.unlink()

    # Try create-dmg first (fancy DMG with Applications link)
    if has_create_dmg():
        print("Using create-dmg for fancy DMG layout...")
        background = SPEC_DIR / "assets" / "dmg-background.png"
        cmd = [
            "create-dmg",
            "--volname",
            "Revenant Installer",
            "--window-pos",
            "200",
            "120",
            "--window-size",
            "660",
            "400",
            "--icon-size",
            "180",
            "--icon",
            "Revenant.app",
            "180",
            "172",
            "--app-drop-link",
            "480",
            "172",
            "--hide-extension",
            "Revenant.app",
            "--no-internet-enable",
        ]
        if background.exists():
            cmd.extend(["--background", str(background)])
        cmd.extend([str(dmg_path), str(app_path)])
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            print("create-dmg timed out after 120s, falling back to hdiutil", file=sys.stderr)
            result = None
        if result is not None and result.returncode == 0:
            size_mb = dmg_path.stat().st_size / (1024 * 1024)
            print(f"DMG created: {dmg_path} ({size_mb:.1f} MB)")
            return
        else:
            if result is not None:
                print(f"create-dmg failed, falling back to hdiutil: {result.stderr}")
            # Clean up partial temp DMGs left by failed create-dmg
            for tmp_dmg in DIST_DIR.glob("rw.*.dmg"):
                tmp_dmg.unlink()

    # Fallback to simple hdiutil
    try:
        result = subprocess.run(
            [
                "hdiutil",
                "create",
                "-volname",
                "Revenant Installer",
                "-srcfolder",
                str(app_path),
                "-ov",
                "-format",
                "UDZO",
                str(dmg_path),
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        print("WARNING: hdiutil timed out after 120s", file=sys.stderr)
        return

    if result.returncode == 0:
        size_mb = dmg_path.stat().st_size / (1024 * 1024)
        print(f"DMG created: {dmg_path} ({size_mb:.1f} MB)")
    else:
        print(f"WARNING: DMG creation failed: {result.stderr}", file=sys.stderr)


def build_py2app():
    """Build macOS .app bundle with py2app (sandbox-compatible).

    py2app reads pyproject.toml and fails on install_requires, so we
    build from an isolated temp directory with only the files py2app needs.
    """
    if sys.platform != "darwin":
        print("ERROR: py2app builds are macOS-only.", file=sys.stderr)
        sys.exit(1)

    setup_file = SPEC_DIR / "setup_mac.py"
    if not setup_file.exists():
        print(f"ERROR: {setup_file} not found.", file=sys.stderr)
        sys.exit(1)

    print("\nBuilding Revenant GUI with py2app (sandbox-compatible)...")

    with tempfile.TemporaryDirectory(prefix="revenant-py2app-") as tmp:
        tmp_path = Path(tmp)

        # Copy only what py2app needs (NOT pyproject.toml)
        shutil.copy2(setup_file, tmp_path / "setup.py")
        shutil.copytree(SPEC_DIR / "scripts", tmp_path / "scripts")
        shutil.copytree(SPEC_DIR / "icons", tmp_path / "icons")
        # py2app needs version from pyproject.toml -- copy with different name
        shutil.copy2(SPEC_DIR / "pyproject.toml", tmp_path / "pyproject_version.toml")
        # Privacy manifest (required for Mac App Store since May 2024)
        privacy_manifest = SPEC_DIR / "PrivacyInfo.xcprivacy"
        if privacy_manifest.exists():
            shutil.copy2(privacy_manifest, tmp_path / "PrivacyInfo.xcprivacy")

        src_dir = SPEC_DIR / "src"

        result = subprocess.run(
            [sys.executable, "setup.py", "py2app"],
            cwd=str(tmp_path),
            env={**__import__("os").environ, "PYTHONPATH": str(src_dir)},
            timeout=300,
        )

        if result.returncode != 0:
            print("\nERROR: py2app build failed.", file=sys.stderr)
            sys.exit(1)

        # Move .app to project dist/
        DIST_DIR.mkdir(exist_ok=True)
        app_src = tmp_path / "dist" / "Revenant.app"
        app_dst = DIST_DIR / "Revenant.app"
        if app_dst.exists():
            shutil.rmtree(app_dst)
        shutil.copytree(str(app_src), str(app_dst), symlinks=True)

    print("\npy2app build complete.")
