"""Verify the per-scan js_dir override.

The model chooses where collected JavaScript is written. Checked against the
fixture site: an absolute path is honoured and reported back, a ~ path is
expanded, a relative path becomes absolute, save_js=false writes nothing, and
an unwritable path is reported rather than silently skipped.

Run: python devtools/verify_jsdir.py
"""
from __future__ import annotations

import asyncio
import json
import shutil
import sys
import tempfile
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from localsite import Handler  # noqa: E402

from jsfind_mcp.server import ScanStore, build_server  # noqa: E402

FAILS: list[str] = []


def check(label, ok, detail=""):
    print(f"  {'PASS' if ok else 'FAIL'}  {label}" + (f" — {detail}" if detail else ""))
    if not ok:
        FAILS.append(label)


async def run():
    site = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=site.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{site.server_address[1]}/"
    mcp = build_server(ScanStore())

    async def call(name, **kw):
        r = await mcp.call_tool(name, kw)
        if isinstance(r, dict):
            return r
        for b in r:
            t = b.get("text") if isinstance(b, dict) else getattr(b, "text", None)
            if t:
                return json.loads(t)
        return {}

    chosen = Path(tempfile.mkdtemp(prefix="ai-chose-")) / "recon" / "acme"
    print("\n[1. model passes an absolute path of its own]")
    scan = await call("jsfind_scan", url=base, js_dir=str(chosen))
    sid = scan.get("scan_id", "")
    check("scan ran", bool(sid), sid)
    # The reported directory is the leaf (base + per-target + js), not the base:
    # two targets under one base must not overwrite each other, and the caller
    # wants the exact folder to open, not the folder to derive it from.
    leaf = scan.get("js_dir", "")
    check("leaf directory reported, not the base",
          leaf.lower().startswith(str(chosen).lower())
          and Path(leaf).is_absolute(), leaf)
    check("js_saved true", scan.get("js_saved") is True)
    check("directory created", Path(leaf).is_dir(), leaf)
    written = list(Path(leaf).rglob("*")) if Path(leaf).is_dir() else []
    check("scripts landed there", bool(written), str(len(written)))

    print("\n[2. jsfind_js_files reports the same directory]")
    files = await call("jsfind_js_files", scan_id=sid)
    check("js_files carries the same leaf", files.get("js_dir") == leaf,
          str(files.get("js_dir")))
    check("files sit under it",
          bool(files.get("files"))
          and all(f["local_path"].startswith(leaf) for f in files["files"]),
          str([f["local_path"] for f in files.get("files", [])][:2]))

    print("\n[3. ~ is expanded")
    home = await call("jsfind_scan", url=base, js_dir="~/jsfind-tilde-probe")
    hd = home.get("js_dir", "")
    check("tilde expanded", "~" not in hd and Path(hd).is_absolute(), hd)
    check("tilde dir created", bool(hd) and Path(hd).is_dir(), hd)

    print("\n[4. save_js=false writes nothing")
    dry_dir = Path(tempfile.mkdtemp(prefix="nosave-")) / "empty"
    dry = await call("jsfind_scan", url=base, js_dir=str(dry_dir), save_js=False)
    check("js_dir empty", dry.get("js_dir") == "", str(dry.get("js_dir")))
    check("js_saved false", dry.get("js_saved") is False)
    check("nothing on disk", not dry_dir.exists(), str(dry_dir))

    print("\n[5. relative input resolves to absolute]")
    # Done inside a scratch directory: a relative js_dir resolves against the
    # process cwd, so probing with one would otherwise drop a directory into
    # the repository root on every run of this suite.
    import os
    scratch = tempfile.mkdtemp(prefix="jsfind-relcwd-")
    previous = os.getcwd()
    os.chdir(scratch)
    try:
        rel = await call("jsfind_scan", url=base, js_dir="./rel-probe-dir")
        rd = rel.get("js_dir", "")
        # Assert existence while the scratch tree is still there; it is deleted
        # below, so checking afterwards would only prove the cleanup worked.
        existed = bool(rd) and Path(rd).is_dir()
    finally:
        os.chdir(previous)
        shutil.rmtree(scratch, ignore_errors=True)
    check("became absolute", Path(rd).is_absolute(), rd)
    check("created under the cwd that was current", existed, rd)

    print("\n[6. unwritable path reported, not silently skipped")
    blocked = Path(tempfile.gettempdir()) / "jsfind-blocked-file"
    blocked.write_text("a file, not a directory", encoding="utf-8")
    bad = await call("jsfind_scan", url=base, js_dir=str(blocked))
    check("scan still returns scan_id", bool(bad.get("scan_id")),
          str(bad.get("error"))[:80])
    check("js_saved false", bad.get("js_saved") is False)
    check("reported as issue", any("js_dir" in str(i) for i in bad.get("issues", [])),
          str(bad.get("issues"))[:160])
    check("stated as hint", any("js_dir" in str(h) for h in bad.get("hints", [])),
          str(bad.get("hints"))[:160])

    print("\n[7. diagnostics advertises an absolute default")
    diag = await call("jsfind_diagnostics")
    check("absolute", Path(diag.get("js_dir", "x")).is_absolute(),
          str(diag.get("js_dir")))
    check("overridable per scan", diag.get("js_dir_overridable_per_scan") is True)

    for p in (chosen, Path(hd).parent if hd else None,
              Path(rd) if rd else None, blocked):
        if p is None:
            continue
        try:
            shutil.rmtree(p, ignore_errors=True) if p.is_dir() else p.unlink()
        except OSError:
            pass
    site.shutdown()


asyncio.run(run())
print("\n" + ("ALL PASS" if not FAILS else f"{len(FAILS)} FAILED: {FAILS}"))
sys.exit(1 if FAILS else 0)
