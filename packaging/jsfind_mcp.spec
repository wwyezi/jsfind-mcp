# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for jsfind-mcp — Windows .exe and Linux binary from one file.

One executable is produced: ``jsfind-mcp``, the MCP server. The project
has no CLI — every capability is exposed as an MCP tool.

Four things make this project unusually awkward to freeze, each handled below:

1. **Bundled YAML.** ``config.yml`` / ``rules.yml`` / ``banners.yml`` are data,
   not code. PyInstaller does not collect them on its own, and a frozen binary
   cannot find them next to the executable via ``__file__``. They are added as
   ``datas`` and located at runtime by :mod:`jsfind_mcp.resources`, which also
   handles the onefile extraction directory.
2. **tree-sitter native grammars.** ``tree_sitter`` and
   ``tree_sitter_javascript`` ship compiled shared objects (``.pyd`` on
   Windows, ``.so`` on Linux) that must be copied verbatim.
3. **httpx / h2.** The HTTP stack resolves its transport backend at runtime,
   so those modules are hidden imports.

Both shapes are ``EXE`` (onefile). To emit a directory bundle instead, replace
``EXE`` with ``COLLECT`` — a directory starts faster and is easier to inspect.
"""

import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_dynamic_libs


def _find_root():
    """Locate the repository root regardless of the caller's directory.

    PyInstaller's ``SPECPATH``/``SPEC`` globals mean different things across
    versions, so rather than trust either, walk up from the working directory
    (and then from this file's own directory) looking for the package itself.
    """
    marker = Path("src") / "jsfind_mcp" / "server.py"
    starts = [Path.cwd()]
    try:
        starts.append(Path(__file__).resolve().parent)
    except NameError:
        pass
    for start in starts:
        for candidate in [start, *start.parents]:
            if (candidate / marker).exists():
                return candidate
    raise SystemExit(
        "cannot locate the jsfind-mcp package root; run pyinstaller from the "
        "repository root or from packaging/"
    )


ROOT = _find_root()
SRC = ROOT / "src"

sys.path.insert(0, str(SRC))


def data_files():
    """Bundled YAML plus whatever data the dependency tree declares."""
    collected = [(str(SRC / "jsfind_mcp" / "data"), "jsfind_mcp/data")]
    for package in ("tree_sitter_javascript", "certifi"):
        try:
            collected += collect_data_files(package, include_py_files=False)
        except Exception:  # noqa: BLE001 - an absent optional dep is fine
            pass
    return collected


def binaries():
    """Compiled extensions that must be copied verbatim."""
    collected = []
    for package in ("tree_sitter", "tree_sitter_javascript", "_cffi_backend"):
        try:
            collected += collect_dynamic_libs(package)
        except Exception:  # noqa: BLE001 - an absent optional dep is fine
            pass
    # cffi ships a compiled backend that httpx's TLS stack needs. It is a module
    # rather than a package, so it cannot be collected by name above.
    try:
        import _cffi_backend

        origin = Path(getattr(_cffi_backend, "__file__", "") or "")
        if origin.name.startswith("_cffi_backend") and origin.suffix:
            collected.append((str(origin), "."))
    except Exception:  # noqa: BLE001 - absent on non-CPython builds
        pass
    return collected


def hidden_imports():
    """Modules resolved at runtime that static analysis cannot see."""
    return [
        "jsfind_mcp.server",
        "jsfind_mcp.resources",
        "httpx._transports.default",
        "httpx._transports.asgi",
        "httpcore._async.http_proxy",
        "mcp.server.fastmcp",
        "mcp.server.fastmcp.tools",
        "mcp.server.stdio",
        "tree_sitter",
        "tree_sitter_javascript",
        "yaml",
        "regex",
    ]


def excludes():
    """Packages that would bloat the binary without being reachable."""
    return [
        "tkinter",
        "matplotlib",
        "numpy",
        "pandas",
        "scipy",
        "pytest",
        "IPython",
        "notebook",
    ]


# ``console=True`` on purpose: this is a terminal tool whose stdout/stderr are
# its interface, and a windowed binary breaks the MCP stdio transport.
COMMON = dict(
    pathex=[str(SRC)],
    binaries=binaries(),
    datas=data_files(),
    hiddenimports=hidden_imports(),
    hookspath=[],
    runtime_hooks=[],
    excludes=excludes(),
    noarchive=False,
)

server = Analysis([str(ROOT / "packaging" / "entry_server.py")], **COMMON)

exe_server = EXE(
    PYZ(server.pure),
    server.scripts,
    server.binaries,
    server.datas,
    [],
    name="jsfind-mcp",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
