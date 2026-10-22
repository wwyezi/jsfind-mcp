#!/usr/bin/env bash
# Build jsfind-mcp into Linux binaries.
#
# Produces one onefile executable in dist/:
#   jsfind-mcp   MCP server (stdio)
#
# Playwright is intentionally excluded (see packaging/jsfind_mcp.spec); the frozen
# build reports the browser phase as unavailable rather than failing.
#
# Usage:  packaging/build_linux.sh [--skip-tests] [--skip-venv]

set -euo pipefail

SKIP_TESTS=0
SKIP_VENV=0
for arg in "$@"; do
  case "$arg" in
    --skip-tests) SKIP_TESTS=1 ;;
    --skip-venv)  SKIP_VENV=1 ;;
    -h|--help)    sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

say() { printf '==> %s\n' "$1"; }

# 1. An isolated interpreter, so the build never picks up the user's global
#    packages and never breaks their environment.
VENV="$ROOT/.build-venv"
if [ "$SKIP_VENV" -eq 0 ]; then
  say "creating build virtual environment"
  [ -d "$VENV" ] || python3 -m venv "$VENV"
  PYTHON="$VENV/bin/python"
else
  PYTHON="python3"
fi

say "upgrading build tooling"
"$PYTHON" -m pip install --quiet --upgrade pip setuptools wheel

say "installing runtime + build dependencies"
"$PYTHON" -m pip install --quiet -e .
"$PYTHON" -m pip install --quiet pyinstaller

say "verifying the source imports before freezing"
"$PYTHON" -c 'import jsfind_mcp; print("jsfind-mcp", jsfind_mcp.__version__)'

say "running tests"
if [ "$SKIP_TESTS" -eq 0 ]; then
  "$PYTHON" tests/test_banners.py
fi

say "building executables"
"$PYTHON" -m PyInstaller --clean --noconfirm \
  --distpath dist --workpath build packaging/jsfind_mcp.spec

CLI="dist/jsfind-mcp"
chmod +x "$CLI"
for path in "$CLI"; do
  [ -f "$path" ] || { echo "expected executable missing: $path" >&2; exit 1; }
done

say "smoke-testing the frozen server"
"$CLI" --print-config

say "done"
printf '\n'
printf '  %s  %s MB\n' "$CLI" "$(du -m "$CLI" | cut -f1)"
printf '\nMCP client config:\n'
cat <<JSON
{
  "mcpServers": {
    "jsfind-mcp": {
      "command": "$(pwd)/$CLI"
    }
  }
}
JSON
