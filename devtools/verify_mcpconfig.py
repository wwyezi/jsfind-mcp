"""Verify the auto-emitted MCP client configuration.

Two things matter and are easy to get wrong:

* the pasted command must **actually serve** — a config carrying
  ``--print-config`` would print and exit instead of running;
* under stdio, **stdout carries JSON-RPC**, so not one byte of the config may
  land there.

Run: ``python devtools/verify_mcpconfig.py``
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

failures = 0


def check(label: str, ok: bool, detail: str = "") -> None:
    global failures
    if not ok:
        failures += 1
    print(f"  {'PASS' if ok else 'FAIL'}  {label}" + (f": {detail}" if detail else ""))


def child_env() -> dict[str, str]:
    """Environment for spawned servers.

    ``PYTHONIOENCODING`` matters: without it a Windows child writes stderr in
    the console codepage and the Chinese config block arrives as mojibake —
    which is precisely why the generated config sets it.
    """
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def run(args: list[str], **kwargs) -> subprocess.CompletedProcess:
    env = child_env()
    return subprocess.run(args, capture_output=True, text=True, timeout=180,
                          env=env, errors="replace", **kwargs)


def server_argv() -> list[str]:
    return [sys.executable, "-m", "jsfind_mcp.server"]


def first_json(text: str):
    """Return the first balanced JSON object in ``text``."""
    depth = 0
    start = -1
    for index, char in enumerate(text):
        if char == "{":
            if depth == 0:
                start = index
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0 and start >= 0:
                try:
                    return json.loads(text[start:index + 1])
                except json.JSONDecodeError:
                    start = -1
    return None


def main() -> int:
    print("MCP auto-config verification")
    # The server writes mcp.json / MCP-CONFIG.md into the cwd by default, and
    # several checks below depend on that. Run from a scratch directory so the
    # suite leaves nothing behind in the repository.
    scratch = tempfile.mkdtemp(prefix="jsfind-verify-mcpconfig-")
    previous = os.getcwd()
    os.chdir(scratch)
    try:
        return _run_checks()
    finally:
        os.chdir(previous)
        shutil.rmtree(scratch, ignore_errors=True)


def _run_checks() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        cfg_dir = os.path.join(tmp, "cfg")

        print("\n1. --print-config prints to stdout and exits")
        out = run(server_argv() + ["--print-config"])
        check("exit code 0", out.returncode == 0, out.stderr[-200:])
        # Here stdout IS the requested output, so redirection into a file works:
        #   jsfind-mcp-server --print-config > mcp.json
        check("stdout carries the block", "mcpServers" in out.stdout)
        check("block parses as json", first_json(out.stdout) is not None)
        check("no config on stderr", "mcpServers" not in out.stderr,
              out.stderr[:120])

        print("\n2. launcher-only flags are stripped from the config")
        out = run(server_argv() + ["--print-config",
                                   "--write-config", "D:/c"])
        block = out.stdout
        check("--print-config removed", '"--print-config"' not in block)
        check("--write-config removed", '"--write-config"' not in block)
        check("= form also stripped",
              "--print-config=" not in
              run(server_argv() + ["--print-config"]).stdout)

        print("\n3. startup writes config files")
        out = run(server_argv() + ["--write-config", cfg_dir])
        check("exit code 0", out.returncode == 0, out.stderr[-300:])
        check("stdout clean for JSON-RPC", out.stdout.strip() == "",
              repr(out.stdout[:120]))
        check("config block on stderr", "mcpServers" in out.stderr)

        json_path = os.path.join(cfg_dir, "mcp.json")
        md_path = os.path.join(cfg_dir, "MCP-CONFIG.md")
        check("mcp.json written", os.path.isfile(json_path))
        check("MCP-CONFIG.md written", os.path.isfile(md_path))

        entry = {}
        if os.path.isfile(json_path):
            raw = open(json_path, encoding="utf-8").read()
            payload = json.loads(raw)
            check("json has the server key", "jsfind-mcp" in payload.get("mcpServers", {}))
            entry = payload["mcpServers"]["jsfind-mcp"]
            check("json command present", bool(entry.get("command")), str(entry))
            check("json has no launcher flags",
                  "--print-config" not in raw and "--write-config" not in raw)
            check("json sets utf-8 env",
                  entry.get("env", {}).get("PYTHONIOENCODING") == "utf-8")

        print("\n4. the emitted command actually serves")
        if entry.get("command"):
            env = dict(os.environ)
            env.update(entry.get("env", {}))
            probe = subprocess.Popen(
                [entry["command"], *entry.get("args", [])],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, env=env,
                encoding="utf-8", errors="replace",
            )
            try:
                request = json.dumps({
                    "jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "verify", "version": "1"},
                    },
                }) + "\n"
                probe.stdin.write(request)
                probe.stdin.flush()
                line = probe.stdout.readline()
                check("responds over stdio",
                      '"result"' in line or '"serverInfo"' in line, line[:160])
            finally:
                probe.kill()

        print("\n5. http transport emits a url config")
        out = run(server_argv() + ["--print-config", "--transport", "http",
                                   "--port", "9123"])
        check("url present", "http://127.0.0.1:9123/mcp" in out.stdout)
        payload = first_json(out.stdout) or {}
        remote = payload.get("mcpServers", {}).get("jsfind-mcp", {})
        check("remote entry uses url, not command",
              remote.get("url", "").endswith("/mcp") and "command" not in remote,
              str(remote))

    print("\nresult:", "all checks passed" if not failures
          else f"{failures} check(s) failed")
    return 0 if failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
