"""
Build MSIX package for Microsoft Store submission.

Usage:
    python scripts/build_msix.py

Prerequisites:
    - Windows SDK (for makeappx.exe)
    - GUI and CLI binaries built: python scripts/build.py all
    - MSIX asset images in msix/Assets/ (see README)

Output:
    dist/Revenant.msix
"""

import re
import shutil
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent
DIST_DIR = PROJECT_DIR / "dist"
STANDALONE_DIR = DIST_DIR / "revenant-standalone"
MSIX_DIR = PROJECT_DIR / "msix"
STAGING_DIR = DIST_DIR / "msix-staging"


def _check_platform():
    """Verify we're on Windows."""
    if sys.platform != "win32":
        print("ERROR: MSIX packaging is Windows-only.", file=sys.stderr)
        sys.exit(1)


def _find_makeappx():
    """Find makeappx.exe in Windows SDK."""
    # Try PATH first
    result = subprocess.run(
        ["where", "makeappx.exe"],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        return result.stdout.strip().split("\n")[0]

    # Search common SDK locations
    sdk_root = Path("C:/Program Files (x86)/Windows Kits/10/bin")
    if sdk_root.exists():
        candidates = sorted(sdk_root.glob("*/x64/makeappx.exe"), reverse=True)
        if candidates:
            return str(candidates[0])

    print(
        "ERROR: makeappx.exe not found.\n"
        "  Install Windows SDK: https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/",
        file=sys.stderr,
    )
    sys.exit(1)


def _check_standalone():
    """Verify the standalone distribution folder and its binaries exist."""
    if not STANDALONE_DIR.exists():
        print(
            f"ERROR: Standalone folder not found: {STANDALONE_DIR}\n"
            "  Build with: python scripts/build.py all",
            file=sys.stderr,
        )
        sys.exit(1)

    missing = []
    if not (STANDALONE_DIR / "revenant-gui.exe").exists():
        missing.append("revenant-gui.exe")
    if not (STANDALONE_DIR / "revenant.exe").exists():
        missing.append("revenant.exe")
    if missing:
        print(
            f"ERROR: Missing in standalone folder: {', '.join(missing)}\n"
            "  Build with: python scripts/build.py all",
            file=sys.stderr,
        )
        sys.exit(1)


def _read_version():
    """Read project version from pyproject.toml."""
    pyproject = (PROJECT_DIR / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.MULTILINE)
    version = match.group(1) if match else "0.0.0"
    # MSIX requires 4-part version
    parts = version.split(".")
    while len(parts) < 4:
        parts.append("0")
    return ".".join(parts[:4])


def _prepare_staging():
    """Create staging directory with all MSIX contents.

    Copies the entire standalone distribution folder (executables plus
    all runtime dependencies) into the MSIX staging area, then adds the
    AppxManifest, LICENSE, and store assets on top.
    """
    if STAGING_DIR.exists():
        shutil.rmtree(STAGING_DIR)

    # Start from the standalone distribution (exes + all DLLs/pyds)
    shutil.copytree(STANDALONE_DIR, STAGING_DIR)

    # Add MSIX manifest with current version
    manifest_src = MSIX_DIR / "AppxManifest.xml"
    if not manifest_src.exists():
        print(f"ERROR: {manifest_src} not found.", file=sys.stderr)
        sys.exit(1)

    version = _read_version()
    manifest_content = manifest_src.read_text(encoding="utf-8")
    manifest_content = re.sub(
        r'Version="[\d.]+"',
        f'Version="{version}"',
        manifest_content,
        count=1,
    )
    (STAGING_DIR / "AppxManifest.xml").write_text(manifest_content, encoding="utf-8")

    # Copy LICENSE
    license_file = PROJECT_DIR.parent / "LICENSE"
    if license_file.exists():
        shutil.copy2(license_file, STAGING_DIR / "LICENSE")

    # Copy assets
    assets_src = MSIX_DIR / "Assets"
    assets_dst = STAGING_DIR / "Assets"
    if assets_src.exists():
        shutil.copytree(assets_src, assets_dst)
    else:
        print(
            "WARNING: msix/Assets/ directory not found.\n"
            "  MSIX requires logo assets. Create placeholder PNGs:\n"
            "  - Assets/StoreLogo.png (50x50)\n"
            "  - Assets/Square44x44Logo.png (44x44)\n"
            "  - Assets/Square150x150Logo.png (150x150)\n"
            "  - Assets/Wide310x150Logo.png (310x150)\n"
            "  - Assets/Square310x310Logo.png (310x310)",
            file=sys.stderr,
        )
        assets_dst.mkdir()

    print(f"Staging directory prepared: {STAGING_DIR}")


def _build_msix(makeappx):
    """Run makeappx to create the MSIX package."""
    output = DIST_DIR / "Revenant.msix"
    if output.exists():
        output.unlink()

    print("Building MSIX package...")
    result = subprocess.run(
        [makeappx, "pack", "/d", str(STAGING_DIR), "/p", str(output), "/o"],
        timeout=120,
    )

    if result.returncode != 0:
        print("ERROR: makeappx failed.", file=sys.stderr)
        sys.exit(1)

    size_mb = output.stat().st_size / (1024 * 1024)
    print(f"Created: {output} ({size_mb:.1f} MB)")

    # Clean up staging
    shutil.rmtree(STAGING_DIR)


def main():
    """Entry point."""
    print("Revenant MSIX Builder")
    print("=" * 50)

    _check_platform()
    _check_standalone()
    makeappx = _find_makeappx()
    _prepare_staging()
    _build_msix(makeappx)

    print("\nDone!")
    print(
        "\nNext steps:\n"
        "  1. Sign with signtool: signtool sign /f cert.pfx /p <password> dist/Revenant.msix\n"
        "  2. Test with WACK: appcert.exe reset && appcert.exe test -appxpackagepath dist/Revenant.msix\n"
        "  3. Upload to Partner Center: https://partner.microsoft.com/dashboard"
    )


if __name__ == "__main__":
    main()
