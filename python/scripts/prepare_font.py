"""Subset and prepare fonts for embedding in PDF signature appearances.

Dev-time script — requires fonttools. NOT a runtime dependency.

Two modes:
  1. Merge mode: combine two TTFs (e.g. NotoSans-Regular + NotoSansArmenian-Regular)
  2. Single mode: subset a single TTF (e.g. GHEAGrapalat-Regular)

Both modes subset to Latin + Armenian + Cyrillic and output:
  1. A subset TTF file for bundling
  2. A Python metrics module with cmap, widths, and PDF-ready data

Usage (merge mode — Noto Sans):
    python scripts/prepare_font.py \\
        --latin /path/to/NotoSans-Regular.ttf \\
        --armenian /path/to/NotoSansArmenian-Regular.ttf

Usage (single mode — GHEA):
    python scripts/prepare_font.py \\
        --input /path/to/GHEAGrapalat-Regular.ttf \\
        --name GHEAGrapalat \\
        --output-ttf src/revenant/core/appearance/font_data/ghea_grapalat/GHEAGrapalat-Subset.ttf \\
        --output-metrics src/revenant/core/appearance/font_data/ghea_grapalat/metrics.py
"""

from __future__ import annotations

import argparse
import sys
import zlib
from pathlib import Path

try:
    from fontTools.merge import Merger
    from fontTools.subset import Options, Subsetter
    from fontTools.ttLib import TTFont
except ImportError:
    print("fonttools is required: pip install fonttools", file=sys.stderr)
    sys.exit(1)


# Unicode ranges to keep in the subset
_UNICODE_RANGES = [
    (0x0020, 0x007F),  # Basic Latin
    (0x00A0, 0x00FF),  # Latin-1 Supplement
    (0x0100, 0x024F),  # Latin Extended-A + B
    (0x0400, 0x04FF),  # Cyrillic
    (0x0530, 0x058F),  # Armenian
    (0x2000, 0x206F),  # General Punctuation
    (0x2010, 0x2027),  # Dashes, quotes (overlap — harmless)
    (0x20AC, 0x20AC),  # Euro sign
]

# Output paths relative to python/ directory (merge mode defaults)
_TTF_OUTPUT = Path("src/revenant/core/appearance/font_data/noto_sans/NotoSans-Subset.ttf")
_METRICS_OUTPUT = Path("src/revenant/core/appearance/font_data/noto_sans/metrics.py")


def _collect_codepoints() -> set[int]:
    """Collect all Unicode codepoints to keep."""
    cps: set[int] = set()
    for start, end in _UNICODE_RANGES:
        cps.update(range(start, end + 1))
    return cps


def _merge_fonts(latin_path: str, armenian_path: str) -> TTFont:
    """Merge Latin and Armenian TTFs into a single font."""
    merger = Merger()
    return merger.merge([latin_path, armenian_path])


def _subset_font(font: TTFont, codepoints: set[int]) -> TTFont:
    """Subset font to only the specified codepoints."""
    options = Options()
    options.layout_features = ["*"]  # keep all OT features
    options.name_IDs = [0, 1, 2, 3, 4, 5, 6]  # keep basic name records
    options.notdef_outline = True
    options.recalc_bounds = True
    options.recalc_average_width = True
    options.drop_tables = ["DSIG", "GPOS", "GSUB", "GDEF"]  # minimal for display

    subsetter = Subsetter(options=options)
    subsetter.populate(unicodes=codepoints)
    subsetter.subset(font)
    return font


def _extract_cmap(font: TTFont) -> dict[int, int]:
    """Extract Unicode codepoint -> glyph ID (integer) mapping."""
    cmap_table = font.getBestCmap()
    if cmap_table is None:
        print("ERROR: No cmap table found in font", file=sys.stderr)
        sys.exit(1)
    # getBestCmap returns dict[int, str] (codepoint -> glyph name).
    # Convert glyph names to integer IDs via getGlyphID.
    glyph_order = font.getGlyphOrder()
    name_to_id = {name: idx for idx, name in enumerate(glyph_order)}
    result: dict[int, int] = {}
    for codepoint, glyph_name in cmap_table.items():
        gid = name_to_id.get(glyph_name)
        if gid is not None:
            result[codepoint] = gid
    return result


def _extract_widths(font: TTFont) -> dict[int, int]:
    """Extract glyph ID -> advance width mapping."""
    hmtx = font["hmtx"]
    glyph_order = font.getGlyphOrder()
    widths: dict[int, int] = {}
    for gid, glyph_name in enumerate(glyph_order):
        if glyph_name in hmtx.metrics:
            advance_width, _lsb = hmtx.metrics[glyph_name]
            widths[gid] = advance_width
    return widths


def _extract_font_descriptor(font: TTFont) -> dict[str, int | tuple[int, ...]]:
    """Extract FontDescriptor values from font tables."""
    head = font["head"]
    os2 = font["OS/2"]
    hhea = font["hhea"]

    return {
        "units_per_em": head.unitsPerEm,
        "ascent": os2.sTypoAscender,
        "descent": os2.sTypoDescender,
        "cap_height": os2.sCapHeight if hasattr(os2, "sCapHeight") else 714,
        "bbox": (head.xMin, head.yMin, head.xMax, head.yMax),
        "stem_v": 90,  # approximate for sans-serif
        "italic_angle": 0,
        "avg_width": os2.xAvgCharWidth,
        "max_width": hhea.advanceWidthMax,
    }


def _build_cid_widths_str(cmap: dict[int, int], widths: dict[int, int]) -> str:
    """Build PDF /W array string for CIDFont.

    Format: [first_gid [w1 w2 ...] ...] for consecutive glyph IDs.
    """
    # Collect used glyph IDs and their widths
    used_gids = sorted(set(cmap.values()))
    if not used_gids:
        return "[]"

    groups: list[str] = []
    current_start = used_gids[0]
    current_widths = [widths.get(used_gids[0], 600)]

    for gid in used_gids[1:]:
        if gid == current_start + len(current_widths):
            # Consecutive
            current_widths.append(widths.get(gid, 600))
        else:
            # Gap — flush current group
            w_str = " ".join(str(w) for w in current_widths)
            groups.append(f"{current_start} [{w_str}]")
            current_start = gid
            current_widths = [widths.get(gid, 600)]

    # Flush last group
    w_str = " ".join(str(w) for w in current_widths)
    groups.append(f"{current_start} [{w_str}]")

    return "[" + " ".join(groups) + "]"


def _build_tounicode_cmap(cmap: dict[int, int]) -> str:
    """Build a ToUnicode CMap string for the font.

    Maps glyph IDs to Unicode codepoints for text selection/copy.
    PDF spec limits beginbfchar to 100 entries per block.
    """
    # Invert: glyph_id -> unicode codepoint
    gid_to_unicode: dict[int, int] = {}
    for cp, gid in cmap.items():
        # Keep the first mapping if multiple codepoints map to same glyph
        if gid not in gid_to_unicode:
            gid_to_unicode[gid] = cp

    entries = sorted(gid_to_unicode.items())

    lines = [
        "/CIDInit /ProcSet findresource begin",
        "12 dict begin",
        "begincmap",
        "/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def",
        "/CMapName /Adobe-Identity-UCS def",
        "/CMapType 2 def",
        "1 begincodespacerange",
        "<0000> <FFFF>",
        "endcodespacerange",
    ]

    # Split into blocks of 100 (PDF spec limit)
    block_size = 100
    for i in range(0, len(entries), block_size):
        block = entries[i : i + block_size]
        lines.append(f"{len(block)} beginbfchar")
        for gid, cp in block:
            lines.append(f"<{gid:04X}> <{cp:04X}>")
        lines.append("endbfchar")

    lines.extend(["endcmap", "CMapEnd"])
    return "\n".join(lines)


def _generate_metrics_module(
    cmap: dict[int, int],
    widths: dict[int, int],
    desc: dict[str, int | tuple[int, ...]],
    cid_widths_str: str,
    tounicode_cmap: str,
    output_path: Path,
    font_name: str = "Noto Sans",
    source_lines: list[str] | None = None,
) -> None:
    """Generate the Python metrics module."""
    bbox = desc["bbox"]

    if source_lines is None:
        source_lines = [
            "  - NotoSans-Regular.ttf (Google Noto Fonts, OFL 1.1)",
            "  - NotoSansArmenian-Regular.ttf (Google Noto Fonts, OFL 1.1)",
        ]

    lines = [
        f'"""Generated {font_name} subset metrics. Do not edit manually.',
        "",
        "Created by scripts/prepare_font.py from:",
        *source_lines,
        '"""',
        "",
        "from __future__ import annotations",
        "",
        f"UNITS_PER_EM = {desc['units_per_em']}",
        f"ASCENT = {desc['ascent']}",
        f"DESCENT = {desc['descent']}",
        f"CAP_HEIGHT = {desc['cap_height']}",
        f"BBOX = ({bbox[0]}, {bbox[1]}, {bbox[2]}, {bbox[3]})",
        f"STEM_V = {desc['stem_v']}",
        f"ITALIC_ANGLE = {desc['italic_angle']}",
        f"DEFAULT_WIDTH = {desc['avg_width']}",
        "",
        "# Unicode codepoint -> glyph ID",
        "CMAP: dict[int, int] = {",
    ]

    # Write cmap in sorted order, ~10 entries per line for compactness
    sorted_cmap = sorted(cmap.items())
    chunk: list[str] = []
    for cp, gid in sorted_cmap:
        chunk.append(f"{cp}: {gid}")
        if len(chunk) >= 10:
            lines.append("    " + ", ".join(chunk) + ",")
            chunk = []
    if chunk:
        lines.append("    " + ", ".join(chunk) + ",")
    lines.append("}")

    lines.append("")
    lines.append("# Glyph ID -> advance width (in font units)")
    lines.append("WIDTHS: dict[int, int] = {")

    sorted_widths = sorted(widths.items())
    chunk = []
    for gid, w in sorted_widths:
        chunk.append(f"{gid}: {w}")
        if len(chunk) >= 10:
            lines.append("    " + ", ".join(chunk) + ",")
            chunk = []
    if chunk:
        lines.append("    " + ", ".join(chunk) + ",")
    lines.append("}")

    lines.append("")
    lines.append("# PDF /W array for CIDFont dict")
    # Split long line
    lines.append(f'CID_WIDTHS_STR = "{cid_widths_str}"')

    lines.append("")
    lines.append("# ToUnicode CMap for text extraction")
    lines.append("TOUNICODE_CMAP = (")
    for cmap_line in tounicode_cmap.split("\n"):
        escaped = cmap_line.replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'    "{escaped}\\n"')
    lines.append(")")
    lines.append("")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines), encoding="utf-8")
    print(
        f"Metrics module: {output_path} ({len(sorted_cmap)} cmap entries, {len(sorted_widths)} widths)"
    )


def _subset_and_generate(
    font: TTFont,
    ttf_path: Path,
    metrics_path: Path,
    font_name: str,
    source_lines: list[str],
) -> None:
    """Common pipeline: subset, save TTF, extract metrics, generate module."""
    codepoints = _collect_codepoints()
    print(f"Subsetting to {len(codepoints)} codepoints...")
    font = _subset_font(font, codepoints)

    # Save subset TTF
    ttf_path.parent.mkdir(parents=True, exist_ok=True)
    font.save(str(ttf_path))
    ttf_size = ttf_path.stat().st_size
    compressed_size = len(zlib.compress(ttf_path.read_bytes()))
    print(f"Subset TTF: {ttf_path} ({ttf_size:,} bytes, {compressed_size:,} compressed)")

    # Re-open for clean glyph ordering
    font = TTFont(str(ttf_path))
    cmap = _extract_cmap(font)
    widths = _extract_widths(font)
    desc = _extract_font_descriptor(font)
    cid_widths_str = _build_cid_widths_str(cmap, widths)
    tounicode_cmap = _build_tounicode_cmap(cmap)

    _generate_metrics_module(
        cmap,
        widths,
        desc,
        cid_widths_str,
        tounicode_cmap,
        metrics_path,
        font_name=font_name,
        source_lines=source_lines,
    )

    print(
        f"\nDone. Font descriptor: units_per_em={desc['units_per_em']}, "
        f"ascent={desc['ascent']}, descent={desc['descent']}, "
        f"cap_height={desc['cap_height']}"
    )
    font.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Subset and prepare fonts for PDF embedding")

    # Merge mode (Noto Sans)
    merge_group = parser.add_argument_group("merge mode (Noto Sans)")
    merge_group.add_argument("--latin", help="Path to NotoSans-Regular.ttf")
    merge_group.add_argument("--armenian", help="Path to NotoSansArmenian-Regular.ttf")

    # Single mode (GHEA fonts)
    single_group = parser.add_argument_group("single mode (GHEA fonts)")
    single_group.add_argument("--input", help="Path to a single TTF file")
    single_group.add_argument("--name", help="Font display name (e.g. 'GHEA Grapalat')")
    single_group.add_argument("--output-ttf", help="Output subset TTF path")
    single_group.add_argument("--output-metrics", help="Output metrics module path")

    # Common
    parser.add_argument("--output-dir", default=".", help="Base directory (default: cwd)")
    args = parser.parse_args()

    is_merge = args.latin or args.armenian
    is_single = args.input

    if is_merge and is_single:
        parser.error("Cannot use --latin/--armenian with --input. Choose one mode.")
    if not is_merge and not is_single:
        parser.error("Specify either --latin + --armenian (merge) or --input (single).")

    if is_merge:
        if not args.latin or not args.armenian:
            parser.error("Merge mode requires both --latin and --armenian.")

        base = Path(args.output_dir)
        ttf_path = base / _TTF_OUTPUT
        metrics_path = base / _METRICS_OUTPUT

        print(f"Merging {args.latin} + {args.armenian}...")
        font = _merge_fonts(args.latin, args.armenian)
        source_lines = [
            "  - NotoSans-Regular.ttf (Google Noto Fonts, OFL 1.1)",
            "  - NotoSansArmenian-Regular.ttf (Google Noto Fonts, OFL 1.1)",
        ]
        _subset_and_generate(font, ttf_path, metrics_path, "Noto Sans", source_lines)

    else:
        if not args.output_ttf or not args.output_metrics or not args.name:
            parser.error("Single mode requires --input, --name, --output-ttf, --output-metrics.")

        input_path = Path(args.input)
        if not input_path.exists():
            print(f"ERROR: {input_path} not found", file=sys.stderr)
            sys.exit(1)

        base = Path(args.output_dir)
        ttf_path = base / Path(args.output_ttf)
        metrics_path = base / Path(args.output_metrics)

        print(f"Loading {input_path}...")
        font = TTFont(str(input_path))
        source_lines = [f"  - {input_path.name}"]
        _subset_and_generate(font, ttf_path, metrics_path, args.name, source_lines)


if __name__ == "__main__":
    main()
