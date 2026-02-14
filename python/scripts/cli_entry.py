"""PyInstaller entry point for CoSign CLI.

This script exists because PyInstaller runs the entry file as __main__,
which breaks relative imports in cli.py.  Instead we import the module
properly and call its main() function.
"""

from revenant.ui.cli import main

main()
