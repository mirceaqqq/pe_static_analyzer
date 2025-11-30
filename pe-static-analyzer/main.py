"""
Entry point for PE Static Analyzer.
- `python main.py gui` launches the Qt GUI.
- Any other invocation is forwarded to the CLI (see `python main.py --help`).
"""

import sys


def main():
    # Support a lightweight "gui" switch without breaking CLI arguments
    if len(sys.argv) > 1 and sys.argv[1].lower() == "gui":
        # Remove the "gui" argument so Qt doesn't try to parse it
        sys.argv.pop(1)
        from src.gui.main_window import main as gui_main

        gui_main()
        return

    # Default: run CLI entry point (argparse defined inside)
    from src.cli import commands

    commands.main()


if __name__ == "__main__":
    main()
