"""
Build script for Revenant binaries.

Usage:
    python scripts/build.py mac     Build macOS .app with App Sandbox (py2app)
    python scripts/build.py gui     Build GUI binary (Nuitka on Windows, PyInstaller on Linux)
    python scripts/build.py cli     Build CLI binary (Nuitka on Windows, PyInstaller on Linux)
    python scripts/build.py all     Build both GUI + CLI

Prerequisites:
    pip install py2app>=0.28              (mac)
    pip install nuitka>=2.0               (Windows)
    pip install pyinstaller>=6.0          (Linux)

Output:
    dist/Revenant.app               macOS app bundle (py2app)
    dist/Revenant.dmg               macOS disk image
    dist/revenant-standalone/       Windows standalone folder (Nuitka)
    dist/revenant-gui               Linux GUI binary (PyInstaller)
    dist/revenant                   Linux CLI binary (PyInstaller)
"""

import sys

from _build_common import (
    CLI_SPEC,
    GUI_SPEC,
    check_pikepdf,
    check_python,
    check_tkinter,
    print_results,
)


def main():
    """Entry point for the build script."""
    valid_targets = ("gui", "cli", "all", "dmg", "mac")
    if len(sys.argv) < 2 or sys.argv[1] not in valid_targets:
        print("Usage: python scripts/build.py <mac|gui|cli|all|dmg> [--no-dmg]")
        print()
        print("  mac        Build macOS .app with App Sandbox (py2app)")
        print("  dmg        Create DMG from existing .app bundle")
        print("  gui        Build GUI binary for Linux/Windows")
        print("  cli        Build CLI binary for Linux/Windows")
        print("  all        Build both GUI + CLI")
        print()
        print("  --no-dmg   Skip DMG creation (for CI: build .app, sign, then 'dmg')")
        sys.exit(1)

    target = sys.argv[1]
    no_dmg = "--no-dmg" in sys.argv[2:]

    # Standalone DMG creation from existing .app
    if target == "dmg":
        from _build_macos import create_dmg

        print("Revenant DMG")
        print("=" * 50)
        create_dmg()
        print_results()
        return

    # py2app build (macOS sandbox-compatible)
    if target == "mac":
        from _build_macos import build_py2app, create_dmg

        print("Revenant Build (py2app)")
        print("=" * 50)
        check_python()
        check_tkinter()
        check_pikepdf()
        build_py2app()
        if not no_dmg:
            create_dmg()
        print_results()
        return

    print("Revenant Build")
    print("=" * 50)

    check_python()

    if sys.platform == "darwin":
        print(
            "NOTE: On macOS, use 'python scripts/build.py mac' for a native .app bundle.\n"
            "      PyInstaller builds are intended for Linux.\n",
            file=sys.stderr,
        )

    build_gui = target in ("gui", "all")
    build_cli = target in ("cli", "all")

    if build_gui:
        check_tkinter()
    check_pikepdf()

    if sys.platform == "win32":
        from _build_nuitka import check_nuitka, package_standalone, run_nuitka

        check_nuitka()
        # Sequential builds on Windows: Nuitka shares a download cache
        # (depends22_x64.zip) that causes PermissionError when accessed
        # by concurrent processes.  Sequential is also better for CI
        # runners with limited vCPUs where CPU-bound compilations don't
        # benefit from parallelism.
        if build_cli:
            run_nuitka("cli", "Revenant CLI")
        if build_gui:
            run_nuitka("gui", "Revenant GUI")
        package_standalone()
    else:
        from _build_pyinstaller import (
            check_pyinstaller,
            pyinstaller_cmd,
            run_parallel,
            run_pyinstaller,
        )

        check_pyinstaller()
        if build_gui and build_cli:
            cli_cmd = pyinstaller_cmd(CLI_SPEC)
            gui_cmd = pyinstaller_cmd(GUI_SPEC)
            run_parallel([(cli_cmd, "CLI"), (gui_cmd, "GUI")])
        elif build_gui:
            run_pyinstaller(GUI_SPEC, "Revenant GUI")
        elif build_cli:
            run_pyinstaller(CLI_SPEC, "Revenant CLI")

    print_results()

    print("\nNote: all network and crypto dependencies are bundled (no system curl needed).")


if __name__ == "__main__":
    main()
