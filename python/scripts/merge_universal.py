"""Merge two architecture-specific macOS .app bundles into a universal binary.

Walks both bundles in parallel. For every Mach-O file (dylib, .so, framework
binary, main executable) runs ``lipo -create`` to produce a fat binary. Non-
Mach-O files (Python scripts, plists, resources) are copied from the primary
(arm64) bundle.

Usage:
    python merge_universal.py <arm64_app> <x64_app> <output_app>
    python merge_universal.py --cli <arm64_bin> <x64_bin> <output_bin>
"""

import shutil
import struct
import subprocess
import sys
from pathlib import Path

# Mach-O magic numbers (native and swapped byte order)
MACHO_MAGICS = {
    0xFEEDFACE,  # MH_MAGIC (32-bit)
    0xFEEDFACF,  # MH_MAGIC_64 (64-bit)
    0xCEFAEDFE,  # MH_CIGAM (32-bit, swapped)
    0xCFFAEDFE,  # MH_CIGAM_64 (64-bit, swapped)
    0xCAFEBABE,  # FAT_MAGIC (universal)
    0xBEBAFECA,  # FAT_CIGAM (universal, swapped)
    0xCAFEBABF,  # FAT_MAGIC_64
    0xBFBAFECA,  # FAT_CIGAM_64 (swapped)
}

LIPO_TIMEOUT = 30


def is_macho(path: Path) -> bool:
    """Check if a file is a Mach-O binary by reading its magic bytes."""
    try:
        with open(path, "rb") as f:
            magic_bytes = f.read(4)
    except OSError:
        return False
    if len(magic_bytes) < 4:
        return False
    magic = struct.unpack(">I", magic_bytes)[0]
    return magic in MACHO_MAGICS


def lipo_create(arm64: Path, x64: Path, output: Path) -> None:
    """Create a universal binary from arm64 and x64 inputs."""
    result = subprocess.run(
        ["lipo", "-create", str(arm64), str(x64), "-output", str(output)],
        capture_output=True,
        text=True,
        timeout=LIPO_TIMEOUT,
    )
    if result.returncode != 0:
        raise RuntimeError(f"lipo failed for {output.name}: {result.stderr.strip()}")


def merge_app_bundles(arm64_app: Path, x64_app: Path, output_app: Path) -> None:
    """Merge two .app bundles into a universal .app bundle.

    Args:
        arm64_app: Path to the arm64 .app bundle.
        x64_app: Path to the x86_64 .app bundle.
        output_app: Path for the merged universal .app bundle.
    """
    if output_app.exists():
        shutil.rmtree(output_app)

    macho_count = 0
    copied_count = 0

    for arm64_file in sorted(arm64_app.rglob("*")):
        # Handle symlinks first (including directory symlinks in .framework bundles)
        if arm64_file.is_symlink():
            rel = arm64_file.relative_to(arm64_app)
            out_file = output_app / rel
            out_file.parent.mkdir(parents=True, exist_ok=True)
            link_target = arm64_file.readlink()
            out_file.symlink_to(link_target)
            continue

        if arm64_file.is_dir():
            continue

        rel = arm64_file.relative_to(arm64_app)
        x64_file = x64_app / rel
        out_file = output_app / rel
        out_file.parent.mkdir(parents=True, exist_ok=True)

        if is_macho(arm64_file):
            if not x64_file.exists():
                raise RuntimeError(f"Missing x64 counterpart for Mach-O file: {rel}")
            lipo_create(arm64_file, x64_file, out_file)
            out_file.chmod(arm64_file.stat().st_mode)
            macho_count += 1
        else:
            shutil.copy2(arm64_file, out_file)
            copied_count += 1

    # Check for x64-only files (files that exist in x64 but not in arm64)
    for x64_file in x64_app.rglob("*"):
        # Preserve x64-only symlinks (including directory symlinks)
        if x64_file.is_symlink():
            rel = x64_file.relative_to(x64_app)
            if not (output_app / rel).exists():
                out_file = output_app / rel
                out_file.parent.mkdir(parents=True, exist_ok=True)
                out_file.symlink_to(x64_file.readlink())
                print(f"  WARNING: x64-only symlink included: {rel}")
            continue

        if x64_file.is_dir():
            continue
        rel = x64_file.relative_to(x64_app)
        if not (output_app / rel).exists():
            if is_macho(x64_file):
                raise RuntimeError(f"x64-only Mach-O file has no arm64 counterpart: {rel}")
            out_file = output_app / rel
            out_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(x64_file, out_file)
            print(f"  WARNING: x64-only file included: {rel}")

    print(f"\nMerge complete: {macho_count} Mach-O binaries lipo'd, {copied_count} files copied")


def merge_cli_binaries(arm64_bin: Path, x64_bin: Path, output_bin: Path) -> None:
    """Merge two CLI binaries into a universal binary.

    Args:
        arm64_bin: Path to the arm64 CLI binary.
        x64_bin: Path to the x86_64 CLI binary.
        output_bin: Path for the merged universal CLI binary.
    """
    lipo_create(arm64_bin, x64_bin, output_bin)
    output_bin.chmod(arm64_bin.stat().st_mode)
    print(f"CLI merge complete: {output_bin}")


def main() -> None:
    """Entry point."""
    if len(sys.argv) < 4:
        print("Usage:")
        print("  python merge_universal.py <arm64.app> <x64.app> <output.app>")
        print("  python merge_universal.py --cli <arm64_bin> <x64_bin> <output_bin>")
        sys.exit(1)

    if sys.argv[1] == "--cli":
        if len(sys.argv) != 5:
            print("Usage: python merge_universal.py --cli <arm64> <x64> <output>")
            sys.exit(1)
        arm64_bin = Path(sys.argv[2])
        x64_bin = Path(sys.argv[3])
        output_bin = Path(sys.argv[4])
        merge_cli_binaries(arm64_bin, x64_bin, output_bin)
    else:
        arm64_app = Path(sys.argv[1])
        x64_app = Path(sys.argv[2])
        output_app = Path(sys.argv[3])

        if not arm64_app.exists():
            print(f"ERROR: arm64 bundle not found: {arm64_app}", file=sys.stderr)
            sys.exit(1)
        if not x64_app.exists():
            print(f"ERROR: x64 bundle not found: {x64_app}", file=sys.stderr)
            sys.exit(1)

        print(f"Merging: {arm64_app.name} (arm64) + {x64_app.name} (x64)")
        merge_app_bundles(arm64_app, x64_app, output_app)

        # Verify the main executable is universal
        main_exe = output_app / "Contents" / "MacOS" / "Revenant"
        if main_exe.exists():
            result = subprocess.run(
                ["lipo", "-info", str(main_exe)],
                capture_output=True,
                text=True,
                timeout=LIPO_TIMEOUT,
            )
            print(f"Main executable: {result.stdout.strip()}")


if __name__ == "__main__":
    main()
