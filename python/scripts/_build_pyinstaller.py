"""Linux build backend using PyInstaller.

Supports parallel CLI + GUI builds with prefixed log output.
"""

import subprocess
import sys
import threading

from _build_common import DIST_DIR, MIN_PYINSTALLER_VERSION, SPEC_DIR


def check_pyinstaller():
    """Verify PyInstaller is installed with sufficient version."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "PyInstaller", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except FileNotFoundError:
        result = None

    if result is None or result.returncode != 0:
        print(
            "ERROR: PyInstaller not found.\n  Install with: pip install 'pyinstaller>=6.0'",
            file=sys.stderr,
        )
        sys.exit(1)

    version_str = result.stdout.strip()
    print(f"PyInstaller: {version_str}")

    parts = version_str.split(".")
    try:
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
        if (major, minor) < MIN_PYINSTALLER_VERSION:
            print(
                f"WARNING: PyInstaller {MIN_PYINSTALLER_VERSION[0]}.{MIN_PYINSTALLER_VERSION[1]}+ "
                f"recommended, got {version_str}",
                file=sys.stderr,
            )
    except ValueError:
        pass


def pyinstaller_cmd(spec_file):
    """Build the PyInstaller command list for a spec file."""
    return [sys.executable, "-m", "PyInstaller", "--clean", "--noconfirm", str(spec_file)]


def run_pyinstaller(spec_file, label):
    """Run PyInstaller with the given spec file."""
    if not spec_file.exists():
        print(f"ERROR: Spec file not found: {spec_file}", file=sys.stderr)
        sys.exit(1)

    print(f"\nBuilding {label}...")
    print(f"  Spec: {spec_file}")
    print(f"  Output: {DIST_DIR}/")
    print()

    result = subprocess.run(
        pyinstaller_cmd(spec_file),
        cwd=str(SPEC_DIR),
        timeout=300,
    )

    if result.returncode != 0:
        print(f"\nERROR: {label} build failed (exit code {result.returncode})", file=sys.stderr)
        sys.exit(1)

    print(f"\n{label} build complete.")


def _stream_with_prefix(stream, prefix):
    """Read lines from a stream and print with a prefix."""
    for line in iter(stream.readline, ""):
        print(f"[{prefix}] {line}", end="", flush=True)


def run_parallel(builds):
    """Run multiple build commands concurrently with prefixed output.

    Args:
        builds: List of (cmd, label) tuples.
    """
    print(f"\nRunning {len(builds)} builds in parallel...")
    for _, label in builds:
        print(f"  - {label}")
    print()

    processes = []
    threads = []

    for cmd, label in builds:
        proc = subprocess.Popen(
            cmd,
            cwd=str(SPEC_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        processes.append((proc, label))

        thread = threading.Thread(
            target=_stream_with_prefix,
            args=(proc.stdout, label),
            daemon=True,
        )
        threads.append(thread)
        thread.start()

    try:
        for thread in threads:
            thread.join(timeout=1200)
    except KeyboardInterrupt:
        for proc, _ in processes:
            proc.kill()
        sys.exit(1)

    failed = []
    for proc, label in processes:
        rc = proc.wait()
        if rc != 0:
            failed.append(f"{label} (exit {rc})")

    if failed:
        print(f"\nERROR: Builds failed: {', '.join(failed)}", file=sys.stderr)
        sys.exit(1)

    print("\nAll parallel builds complete.")
