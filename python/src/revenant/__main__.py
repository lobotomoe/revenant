"""
Entry point for `python -m revenant`.

Usage:
    python -m revenant sign document.pdf
    python -m revenant verify document.pdf
    python -m revenant info document.pdf.p7s
"""

from .ui.cli import main

main()
