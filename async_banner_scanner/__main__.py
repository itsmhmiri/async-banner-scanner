"""Entrypoint module when executed as `python -m async_banner_scanner`."""

import sys
from async_banner_scanner.cli import main

if __name__ == "__main__":
    sys.exit(main())
