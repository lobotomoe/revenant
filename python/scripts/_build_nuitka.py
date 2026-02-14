"""Windows build backend using Nuitka (standalone mode).

Produces a ``revenant-standalone/`` folder containing the executables
and all runtime dependencies.  Standalone mode avoids the
extract-to-temp pattern used by ``--onefile``, which triggers
false-positive detections in Windows Defender's ML heuristics.
"""

import shutil
import subprocess
import sys

from _build_common import DIST_DIR, SPEC_DIR, STANDALONE_DIR, read_version


def check_nuitka():
    """Verify Nuitka is installed."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "nuitka", "--version"],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except FileNotFoundError:
        result = None
    except subprocess.TimeoutExpired:
        result = None

    if result is None or result.returncode != 0:
        print(
            "ERROR: Nuitka not found.\n  Install with: pip install 'nuitka>=2.0'",
            file=sys.stderr,
        )
        sys.exit(1)

    version_str = result.stdout.strip().split("\n")[0]
    print(f"Nuitka: {version_str}")


def nuitka_cmd(target):
    """Build the Nuitka command list for a target.

    Args:
        target: "gui" or "cli".

    Returns:
        Command list for subprocess.
    """
    is_gui = target == "gui"
    version = read_version()
    version_quad = f"{version}.0" if version.count(".") == 2 else version

    entry = "scripts/gui_entry.py" if is_gui else "scripts/cli_entry.py"
    output_name = "revenant-gui.exe" if is_gui else "revenant.exe"
    description = "Revenant - PDF Signing Tool" if is_gui else "Revenant - CLI"

    cmd = [
        sys.executable,
        "-m",
        "nuitka",
        "--standalone",
        "--assume-yes-for-downloads",
        "--show-progress",
        "--include-package=revenant",
        "--include-package-data=revenant",
        f"--output-dir={DIST_DIR}",
        f"--output-filename={output_name}",
        # Windows version info
        "--windows-company-name=Aleksandr Kraiz",
        "--windows-product-name=Revenant",
        f"--windows-file-version={version_quad}",
        f"--windows-product-version={version_quad}",
        f"--windows-file-description={description}",
    ]

    # Icon
    icon_path = SPEC_DIR / "icons" / "revenant.ico"
    if icon_path.exists():
        cmd.append(f"--windows-icon-from-ico={icon_path}")

    # GUI-specific flags
    if is_gui:
        cmd.append("--enable-plugin=tk-inter")
        cmd.append("--windows-console-mode=disable")
        # Bundle .ico so tkinter can set the window icon at runtime
        if icon_path.exists():
            cmd.append(f"--include-data-files={icon_path}=icons/revenant.ico")

    cmd.append(entry)
    return cmd


def run_nuitka(target, label):
    """Run Nuitka to build a Windows executable.

    Args:
        target: "gui" or "cli".
        label: Human-readable label for log messages.
    """
    cmd = nuitka_cmd(target)

    print(f"\nBuilding {label} with Nuitka (standalone)...")
    print(f"  Entry: {cmd[-1]}")
    print()

    result = subprocess.run(cmd, cwd=str(SPEC_DIR), timeout=1200)

    if result.returncode != 0:
        print(f"\nERROR: {label} build failed (exit code {result.returncode})", file=sys.stderr)
        sys.exit(1)

    print(f"\n{label} build complete.")


def package_standalone():
    """Merge standalone Nuitka outputs into a single distribution folder.

    Nuitka ``--standalone`` produces ``<entry>.dist/`` folders.  This
    function merges CLI and GUI outputs into a single
    ``revenant-standalone/`` folder so that shared dependencies
    (Python DLLs, .pyd files) are not duplicated.
    """
    if STANDALONE_DIR.exists():
        shutil.rmtree(STANDALONE_DIR)

    dist_dirs = sorted(DIST_DIR.glob("*.dist"))
    if not dist_dirs:
        print("WARNING: No standalone output found.", file=sys.stderr)
        return

    # Use first dist folder as the base
    shutil.copytree(dist_dirs[0], STANDALONE_DIR)
    shutil.rmtree(dist_dirs[0])

    # Merge remaining dist folders (shared DLLs are identical, GUI-only
    # files like _tkinter.pyd get added)
    for src in dist_dirs[1:]:
        shutil.copytree(src, STANDALONE_DIR, dirs_exist_ok=True)
        shutil.rmtree(src)

    # Clean Nuitka build artifacts
    for build_dir in DIST_DIR.glob("*.build"):
        shutil.rmtree(build_dir)

    file_count = sum(1 for f in STANDALONE_DIR.rglob("*") if f.is_file())
    total_bytes = sum(f.stat().st_size for f in STANDALONE_DIR.rglob("*") if f.is_file())
    total_mb = total_bytes / (1024 * 1024)
    print(f"\nStandalone output: {STANDALONE_DIR}")
    print(f"  Files: {file_count}")
    print(f"  Total size: {total_mb:.1f} MB")
