"""Verify the query and overview layers on offline results.

The offline path is the fallback when a target is unavailable, so it has to
answer the same questions the online path does. These checks cover what used
to fail or mislead there: the overview tool raising instead of degrading, the
authorized column being meaningless, and diff mode reporting every known
interface as new.

Run: python devtools/verify_offline.py
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from jsfind_mcp.server import ScanStore, build_server  # noqa: E402

FAILURES: list = []
FIXTURE = ROOT / "tests" / "fixture.js"


def check(label, ok, detail=""):
    print(f"  {'PASS' if ok else 'FAIL'}  {label}" + (f" - {detail}" if detail else ""))
    if not ok:
        FAILURES.append(label)


async def run():
    mcp = build_server(ScanStore())

    async def call(name, **arguments):
        result = await mcp.call_tool(name, arguments)
        if isinstance(result, dict):
            return result
        for block in result:
            text = block.get("text") if isinstance(block, dict) \
                else getattr(block, "text", None)
            if text:
                return json.loads(text)
        return {}

    scratch = tempfile.mkdtemp(prefix="jsfind-verify-offline-")
    previous = os.getcwd()
    os.chdir(scratch)
    try:
        print("\n1. the overview tool works offline instead of raising")
        scan = await call("jsfind_analyze_file", files=[str(FIXTURE)],
                          base_url="https://api.example.com")
        check("analyze_file produced a scan", bool(scan.get("scan_id")),
              str(scan)[:70])
        scan_id = scan.get("scan_id", "")
        if not scan_id:
            return
        view = await call("jsfind_surface", scan_id=scan_id)
        check("surface did not raise", "error" not in view,
              str(view.get("error"))[:80])
        check("surface reported the local mode",
              view.get("summary", {}).get("mode") == "local",
              str(view.get("summary", {}).get("mode")))
        check("surface produced leads", view.get("lead_count", 0) > 0,
              str(view.get("lead_count")))
        check("surface produced caveats",
              len(view.get("coverage", {}).get("caveats", [])) > 0)
        check("surface produced next steps", len(view.get("next_steps", [])) > 0)

        print("\n2. an empty result degrades rather than raising")
        empty = Path(scratch) / "nothing.js"
        empty.write_text("", encoding="utf-8")
        blank = await call("jsfind_analyze_file", files=[str(empty)])
        if blank.get("scan_id"):
            thin = await call("jsfind_surface", scan_id=blank["scan_id"])
            check("empty surface did not raise", "error" not in thin)
            check("empty surface has zero leads", thin.get("lead_count") == 0,
                  str(thin.get("lead_count")))
        else:
            check("empty file reported as skipped", "error" in blank,
                  str(blank)[:70])
        print("\n3. the authorized column means something")
        plain = await call("jsfind_analyze_file", files=[str(FIXTURE)])
        none_in = await call("jsfind_endpoints", scan_id=plain["scan_id"],
                             authorized="true", limit=100)
        check("no base_url means nothing is in scope",
              none_in.get("total") == 0, str(none_in.get("total")))
        inside = await call("jsfind_endpoints", scan_id=scan_id,
                            authorized="true", limit=100)
        outside = await call("jsfind_endpoints", scan_id=scan_id,
                             authorized="false", limit=100)
        check("base_url puts same-origin endpoints in scope",
              inside.get("total", 0) > 0, str(inside.get("total")))
        everything = await call("jsfind_endpoints", scan_id=scan_id, limit=100)
        check("the two sides partition the table",
              inside.get("total", 0) + outside.get("total", 0)
              == everything.get("total", -1),
              f"{inside.get('total')}+{outside.get('total')} vs "
              f"{everything.get('total')}")
        unfiltered = await call("jsfind_endpoints", scan_id=scan_id,
                                authorized="maybe", limit=100)
        check("an unrecognised filter value does not empty the table",
              unfiltered.get("total") == everything.get("total"),
              str(unfiltered.get("total")))

        print("\n4. diff mode finds what the list is missing")
        known = ["/order/submit", "/user/{userId}/detail"]
        report = await call("jsfind_diff", scan_id=scan_id, known=known)
        check("diff produced a report", "error" not in report, str(report)[:70])
        check("new endpoints listed", report.get("new_count", 0) > 0,
              str(report.get("new_count")))
        check("a known path is not reported as new",
              not any(r["path"] == "/order/submit"
                      for r in report.get("new_endpoints", [])))
        strict = await call("jsfind_diff", scan_id=scan_id, known=known,
                            suffix=False)
        check("suffix matching removes false new endpoints",
              report.get("new_count", 99) <= strict.get("new_count", 0),
              f"suffix={report.get('new_count')} strict={strict.get('new_count')}")
        listing = Path(scratch) / "known.txt"
        listing.write_text("# a comment\n/order/submit\n", encoding="utf-8")
        from_file = await call("jsfind_diff", scan_id=scan_id,
                                known_file=str(listing))
        check("a known list can be read from a file",
              from_file.get("known_count") == 1, str(from_file.get("known_count")))

        print("\n5. parameter noise is filtered and the count reported")
        params = await call("jsfind_parameters", scan_id=scan_id, limit=100)
        every = await call("jsfind_parameters", scan_id=scan_id,
                            drop_minified=False, limit=100)
        check("dropped count reported", "dropped_minified" in params,
              str(params.get("dropped_minified")))
        check("filtering never adds rows",
              params.get("count", 0) <= every.get("count", 0),
              f"{params.get('count')} vs {every.get('count')}")
        rows = params.get("parameters", [])
        check("rows are ordered by how actionable they are",
              bool(rows) and rows[0].get("scenarios") != ["variable"],
              str(rows[0].get("scenarios")) if rows else "-")

        print("\n6. results can be exported as JSON")
        target = Path(scratch) / "nested" / "out.json"
        exported = await call("jsfind_analyze_file", files=[str(FIXTURE)],
                              export_json=str(target))
        check("export file written", target.is_file(),
              exported.get("exported_json", "")[:60])
        if target.is_file():
            data = json.loads(target.read_text(encoding="utf-8"))
            check("export holds the endpoints", bool(data.get("endpoints")),
                  str(len(data.get("endpoints", []))))
            check("export holds the findings", "findings" in data)

        print("\n7. probe an offline result against a live target")
        import threading
        from http.server import ThreadingHTTPServer
        sys.path.insert(0, str(ROOT / "tests"))
        from localsite import Handler  # noqa: E402

        site = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=site.serve_forever, daemon=True).start()
        live = f"http://127.0.0.1:{site.server_address[1]}"
        try:
            seed = Path(scratch) / "probe.js"
            seed.write_text('fetch("/api/v1/notify/stream");', encoding="utf-8")
            offline = await call("jsfind_analyze_file", files=[str(seed)],
                                 base_url="https://local.invalid")
            before = await call("jsfind_endpoints", scan_id=offline["scan_id"],
                                limit=50)
            check("offline endpoints start unprobed",
                  all(e.get("signal") == "unprobed"
                      for e in before.get("endpoints", [])),
                  str([e.get("signal") for e in before.get("endpoints", [])]))
            probed = await call("jsfind_probe", scan_id=offline["scan_id"],
                                base_url=live, limit=10)
            check("probe ran", probed.get("probed", 0) > 0,
                  str(probed.get("probed")))
            check("probe reported a signal",
                  bool(probed.get("signals")), str(probed.get("signals")))
            after = await call("jsfind_endpoints", scan_id=offline["scan_id"],
                               limit=50)
            check("signals written back to the endpoint table",
                  all(e.get("signal") != "unprobed"
                      for e in after.get("endpoints", [])),
                  str([e.get("signal") for e in after.get("endpoints", [])]))
            check("placeholder origin replaced by the live one",
                  all(live in e.get("url", "")
                      for e in after.get("endpoints", [])),
                  str([e.get("url") for e in after.get("endpoints", [])]))
        finally:
            site.shutdown()

        print("\n8. a file may name its own origin")
        per_file = await call("jsfind_analyze_file",
                              files=[{"path": str(FIXTURE),
                                      "origin": "https://api.example.com"}])
        check("per-file origin accepted", bool(per_file.get("scan_id")),
              str(per_file)[:70])
        if per_file.get("scan_id"):
            scoped = await call("jsfind_endpoints", scan_id=per_file["scan_id"],
                                authorized="true", limit=100)
            check("per-file origin grants scope", scoped.get("total", 0) > 0,
                  str(scoped.get("total")))
    finally:
        os.chdir(previous)
        shutil.rmtree(scratch, ignore_errors=True)


asyncio.run(run())
print("\n" + ("ALL PASS" if not FAILURES
              else f"{len(FAILURES)} FAILED: {FAILURES}"))
sys.exit(1 if FAILURES else 0)