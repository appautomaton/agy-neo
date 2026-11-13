#!/usr/bin/env python3
"""Entrypoint for the `consult_gemini` MCP stdio server."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from consult_gemini.mcp_server import main

if __name__ == "__main__":
    raise SystemExit(main())
