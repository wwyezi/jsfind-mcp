"""Frozen entry point for the MCP server.

Same reason as :mod:`entry_cli`: PyInstaller runs the entry script without a
package context, so the real module is imported absolutely from here.
"""

import multiprocessing
import sys

from jsfind_mcp.server import main

if __name__ == "__main__":
    multiprocessing.freeze_support()
    sys.exit(main())
