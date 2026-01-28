"""Main entry point for PrivaseeAI Security application."""

import sys

from privaseeai_security.cli import main as cli_main
from privaseeai_security import __version__


def main():
    """Main entry point - delegate to CLI."""
    # If called with no arguments, show help
    if len(sys.argv) == 1:
        sys.argv.append("--help")
    
    cli_main()


if __name__ == "__main__":
    main()
