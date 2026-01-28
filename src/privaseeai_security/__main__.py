"""Main entry point for PrivaseeAI Security application."""

import sys

from privaseeai_security.cli import main as cli_main
from privaseeai_security.config import Config
from privaseeai_security import __version__


def health_check() -> bool:
    """
    Perform a health check on the application.
    
    Returns:
        bool: True if health check passes, False otherwise
    """
    try:
        config = Config()
        config.validate()
        return True
    except Exception as e:
        print(f"Health check failed: {e}", file=sys.stderr)
        return False


def main():
    """Main entry point - delegate to CLI."""
    # If called with no arguments, show help
    if len(sys.argv) == 1:
        sys.argv.append("--help")
    
    cli_main()


if __name__ == "__main__":
    main()
