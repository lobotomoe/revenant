"""Shared constants and checks for the build system."""

import re
import sys
from pathlib import Path

MIN_PYINSTALLER_VERSION = (6, 0)

SPEC_DIR = Path(__file__).resolve().parent.parent
DIST_DIR = SPEC_DIR / "dist"
STANDALONE_DIR = DIST_DIR / "revenant-standalone"

GUI_SPEC = SPEC_DIR / "revenant-gui.spec"
CLI_SPEC = SPEC_DIR / "revenant-cli.spec"


def check_python():
    """Verify Python version is 3.10+."""
    major = sys.version_info.major
    minor = sys.version_info.minor
    if major < 3 or (major == 3 and minor < 10):
        print(f"ERROR: Python 3.10+ required, got {major}.{minor}", file=sys.stderr)
        sys.exit(1)
    print(f"Python: {sys.executable} ({major}.{minor})")


def check_tkinter():
    """Verify tkinter is available (needed for GUI build)."""
    try:
        import tkinter  # noqa: F401

        print("tkinter: available")
    except ImportError:
        print(
            "WARNING: tkinter not available. GUI binary will fail at runtime.",
            file=sys.stderr,
        )


def check_pikepdf():
    """Check if pikepdf is available (optional)."""
    try:
        import pikepdf

        print(f"pikepdf: {pikepdf.__version__} (will be included)")
    except ImportError:
        print("pikepdf: not installed (PDF signing will be unavailable in binary)")


def read_version():
    """Read project version from pyproject.toml."""
    pyproject = (SPEC_DIR / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.MULTILINE)
    return match.group(1) if match else "0.0.0"


def print_results():
    """Print build output summary."""
    print("\n" + "=" * 50)
    print("Build output:")
    if not DIST_DIR.exists():
        print("  (no output)")
        return

    for item in sorted(DIST_DIR.iterdir()):
        if item.is_file():
            size_mb = item.stat().st_size / (1024 * 1024)
            print(f"  {item.name}  ({size_mb:.1f} MB)")
        elif item.is_dir() and item.suffix == ".app":
            print(f"  {item.name}/  (macOS app bundle)")
        elif item == STANDALONE_DIR:
            total = sum(f.stat().st_size for f in item.rglob("*") if f.is_file())
            print(f"  {item.name}/  (standalone, {total / (1024 * 1024):.1f} MB)")
