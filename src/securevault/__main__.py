"""Module execution entry point for `python -m securevault`."""

import sys
from securevault.cli import main

if __name__ == "__main__":
    sys.exit(main())

