"""Compatibility launcher; installed users may run aegis-server."""

import sys
from pathlib import Path

# Isolated Python omits the script directory; load this checkout explicitly.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import uvicorn as uvicorn  # Retained for launch configuration tooling.

from aegis.server_entry import main

if __name__ == "__main__":
    main()
