"""Locating bundled data files, from source *and* from a frozen binary.

``Path(__file__).parent / "data"`` works when running from a checkout, but a
PyInstaller bundle is a different animal:

* **onefile** extracts into a temporary directory, so the package lives under
  ``sys._MEIPASS`` rather than next to the executable;
* **onedir** keeps it next to the executable, but the ``__file__`` chain can
  still point somewhere unexpected for zipped submodules.

Rather than guess, this module asks :mod:`importlib.resources` first, then falls
back to ``sys._MEIPASS`` and finally to ``__file__``. Every caller therefore
gets a real, readable path in all three cases — source checkout, ``--onefile``
and ``--onedir``.
"""

from __future__ import annotations

import os
import sys
from functools import lru_cache
from pathlib import Path

#: files this package ships and needs at runtime
DATA_FILES = ("config.yml", "rules.yml", "banners.yml")

_PACKAGE = "jsfind_mcp"


def is_frozen() -> bool:
    """Whether the process is running from a PyInstaller bundle."""
    return getattr(sys, "frozen", False)


def bundle_root() -> Path | None:
    """The directory a frozen bundle unpacks into, or None when not frozen."""
    meipass = getattr(sys, "_MEIPASS", None)
    return Path(meipass) if meipass else None


@lru_cache(maxsize=1)
def data_dir() -> Path:
    """Directory holding the bundled YAML files.

    Raises :class:`FileNotFoundError` when no candidate directory contains them.
    A missing bundle is a build problem the caller must report, not swallow.
    """
    candidates: list[Path] = []

    # 1. importlib.resources — correct for zip-imported and installed packages.
    try:
        from importlib.resources import files

        candidates.append(Path(str(files(_PACKAGE))) / "data")
    except (ImportError, ModuleNotFoundError, TypeError):
        pass

    # 2. the PyInstaller extraction directory (onefile and onedir both).
    root = bundle_root()
    if root is not None:
        candidates.append(root / _PACKAGE / "data")
        candidates.append(root / "data")

    # 3. plain source checkout or site-packages install.
    candidates.append(Path(__file__).resolve().parent / "data")

    for candidate in candidates:
        if (candidate / "rules.yml").exists():
            return candidate

    raise FileNotFoundError(
        "bundled data files not found; looked in "
        + ", ".join(str(path) for path in candidates)
    )


def data_path(name: str) -> Path:
    """Absolute path of one bundled file (``config.yml``, ``rules.yml``…)."""
    if "/" in name or "\\" in name:
        raise ValueError(f"data_path takes a bare file name, got {name!r}")
    return data_dir() / name


def safe_data_path(name: str) -> Path:
    """``data_path`` that never raises at import time.

    Module-level constants are evaluated during import, so letting
    :class:`FileNotFoundError` escape here would turn "the bundle is missing its
    YAML" into a bare ``ImportError`` with no explanation. Instead a plausible
    but non-existent path is returned, and the loader reports the real problem
    as a diagnostic — which is what a user can act on.
    """
    try:
        return data_path(name)
    except FileNotFoundError:
        return Path(__file__).resolve().parent / "data" / name


def user_config_dir() -> Path:
    """Per-user configuration directory. Created on demand by the caller."""
    return Path.home() / ".jsfind-mcp"


def writable_base_dir() -> Path:
    """Directory for reports and downloaded scripts.

    A frozen binary may be launched from a read-only share or from inside
    ``Program Files``, so the executable's own directory is used only when it
    is actually writable; otherwise the user's home is.
    """
    if not is_frozen():
        return Path.cwd()

    exe_dir = Path(sys.executable).resolve().parent
    if _is_writable_dir(exe_dir):
        return exe_dir
    return user_config_dir()


def _is_writable_dir(path: Path) -> bool:
    try:
        return path.is_dir() and os.access(path, os.W_OK)
    except OSError:
        return False


def describe_environment() -> dict:
    """Summary for ``--check`` and for bug reports."""
    info = {
        "frozen": is_frozen(),
        "executable": sys.executable,
        "bundle_root": str(bundle_root() or ""),
    }
    try:
        info["data_dir"] = str(data_dir())
    except FileNotFoundError as exc:
        info["data_dir"] = f"NOT FOUND: {exc}"
    return info
