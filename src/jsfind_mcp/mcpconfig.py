"""Emit a ready-to-paste MCP client configuration.

Starting the server is the moment a user actually needs this file: they have a
working server in front of them and want to wire it into a client without
guessing a path. So the server prints its own configuration at startup.

Two constraints shape the design:

* **stdout carries JSON-RPC.** Under the stdio transport a single stray byte on
  stdout corrupts the protocol stream, so every byte of this module goes to
  stderr — and to files on disk, which is where a user can reliably reach it.
* **the command must actually reproduce this server.** A config saying
  ``jsfind-mcp-server`` is useless to someone who launched a source checkout. The
  launcher therefore records *how it was actually started* (frozen executable,
  console script, or ``python -m``) and emits the matching command line, with
  the same flags it was given.
"""

from __future__ import annotations

import json
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .resources import is_frozen

SERVER_KEY = "jsfind-mcp"

#: The three ways this server can be launched, each needing a different command
#: line in a client config.
SOURCE = "source"            # python -m jsfind_mcp.server
CONSOLE_SCRIPT = "console"   # jsfind-mcp-server on PATH
FROZEN = "frozen"            # the packaged executable itself

_UNIVERSAL_TITLE = "Claude Desktop / Cursor / CodeBuddy / VS Code"
_REMOTE_TITLE = "Claude Desktop / Cursor（远程 HTTP）"

#: every client should get this, so a Windows console does not mangle the
#: report's Chinese text and a shell-less client can still find the runtime
_BASE_ENV = {"PYTHONIOENCODING": "utf-8"}


@dataclass
class ServerSpec:
    """How to start this server, in the form a client config needs."""

    mode: str = SOURCE
    command: str = "python"
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    transport: str = "stdio"
    #: set when transport is http; a client then needs a url, not a command
    url: str = ""

    @property
    def is_remote(self) -> bool:
        return self.transport != "stdio"


def detect(argv: list[str] | None = None, transport: str = "stdio",
           url: str = "", extra_args: list[str] | None = None,
           drop: tuple[tuple[str, int], ...] = ()) -> ServerSpec:
    """Work out the command that reproduces the server as launched.

    Args come from the real command line minus the interpreter and entry
    script, so a client started with ``--output ./reports`` keeps writing
    reports to ``./reports``.

    ``drop`` lists launcher-only flags as ``(flag, arity)``. They are removed
    because a config containing ``--print-config`` would print a config and
    exit instead of serving — the pasted command must actually run the server.
    """
    argv = list(sys.argv[1:] if argv is None else argv)
    args = _strip_launcher(argv) + list(extra_args or [])
    args = _drop_flags(args, drop)
    env = dict(_BASE_ENV)

    if is_frozen():
        # In a onefile bundle sys.executable is the executable itself and the
        # remaining args are already the user's flags.
        return ServerSpec(mode=FROZEN, command=sys.executable, args=args,
                          env=env, transport=transport, url=url)

    # A console script on PATH is the most portable thing to emit: it survives
    # the user moving the checkout, and every client can spawn it.
    if shutil.which("jsfind-mcp-server"):
        return ServerSpec(mode=CONSOLE_SCRIPT, command="jsfind-mcp-server",
                          args=args, env=env, transport=transport, url=url)

    # Source checkout: -m works because jsfind_mcp.server guards its main().
    return ServerSpec(mode=SOURCE, command=sys.executable,
                      args=["-m", "jsfind_mcp.server", *args],
                      env=env, transport=transport, url=url)


def _drop_flags(args: list[str], drop: tuple[tuple[str, int], ...]) -> list[str]:
    """Remove ``drop`` entries, arity values included.

    Also handles ``--flag=value``, which argparse accepts interchangeably with
    the space-separated form.
    """
    if not drop:
        return list(args)
    out: list[str] = []
    index = 0
    while index < len(args):
        token = args[index]
        consumed = False
        for flag, arity in drop:
            if token == flag:
                index += 1 + arity
                consumed = True
                break
            if token.startswith(flag + "="):
                index += 1
                consumed = True
                break
        if not consumed:
            out.append(token)
            index += 1
    return out


def _strip_launcher(argv: list[str]) -> list[str]:
    """Drop the interpreter and entry script, keeping only server flags.

    ``python src/jsfind_mcp/server.py --output x`` and ``jsfind-mcp-server --output x``
    must both reduce to ``--output x``.
    """
    out = list(argv)
    if out and Path(out[0]).stem.lower().startswith("python"):
        out = out[1:]
    if out and out[0] == "-m":
        out = out[1:]
        if out and not out[0].startswith("-"):
            out = out[1:]
    elif out and Path(out[0]).stem in ("server", "jsfind-mcp-server",
                                       "entry_server", "jsfind-mcp-server.exe"):
        out = out[1:]
    return out


def client_entry(spec: ServerSpec) -> dict:
    """The ``jsfind-mcp`` entry as it appears inside an ``mcpServers`` object."""
    if spec.is_remote:
        return {"type": "http", "url": spec.url}
    entry: dict = {"command": spec.command, "args": spec.args}
    if spec.env:
        entry["env"] = spec.env
    return entry


def client_configs(spec: ServerSpec) -> dict[str, dict]:
    """Paste-ready configs, keyed by the client they target.

    The ``mcpServers`` shape is shared by Claude Desktop, Cursor, Windsurf,
    CodeBuddy and VS Code, so one entry serves nearly everyone. The remote form
    differs (a ``url`` instead of a ``command``) and is kept separate.
    """
    entry = client_entry(spec)
    if spec.is_remote:
        return {_REMOTE_TITLE: {"mcpServers": {SERVER_KEY: entry}}}
    return {
        f"{_UNIVERSAL_TITLE}（本地 stdio）": {
            "mcpServers": {SERVER_KEY: entry},
        },
        # For merging into a file that already has an mcpServers block.
        "仅条目（合并进已有 mcpServers）": entry,
    }


def claude_code_command(spec: ServerSpec) -> str:
    """A one-liner for ``claude mcp add``."""
    if spec.is_remote:
        return f"claude mcp add --transport http {SERVER_KEY} {spec.url}"
    parts = ["claude", "mcp", "add", "--scope", "user", SERVER_KEY,
             "--", spec.command, *spec.args]
    return " ".join(_quote(part) for part in parts)


def _quote(value: str) -> str:
    """Quote only when needed, so the common case stays readable."""
    if value and not any(char in value for char in ' \t"\'\\$`'):
        return value
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _mode_label(mode: str) -> str:
    return {
        FROZEN: "已打包二进制",
        CONSOLE_SCRIPT: "已安装的命令行入口（PATH 中的 jsfind-mcp-server）",
        SOURCE: "源码运行（python -m jsfind_mcp.server）",
    }.get(mode, mode)


def render(spec: ServerSpec) -> str:
    """The full paste-ready block, written to stderr at startup."""
    lines: list[str] = [
        "=" * 72,
        " jsfind-mcp MCP 客户端配置（可复制粘贴）",
        "=" * 72,
        "",
        f"启动方式: {_mode_label(spec.mode)}    传输: {spec.transport}",
    ]
    if spec.is_remote:
        lines.append(f"服务地址: {spec.url}")
    else:
        command = " ".join([_quote(spec.command),
                            *(_quote(arg) for arg in spec.args)])
        lines.append(f"命令    : {command}")

    for title, payload in client_configs(spec).items():
        lines.append("")
        lines.append(f"--- {title} " + "-" * max(0, 68 - len(title)))
        lines.append(json.dumps(payload, ensure_ascii=False, indent=2))

    lines.append("")
    lines.append("--- Claude Code 一行命令 " + "-" * 44)
    lines.append(claude_code_command(spec))

    if not spec.is_remote:
        lines += [
            "",
            "提示:",
            "  · stdio 传输下 stdout 用于 JSON-RPC 协议，本段输出走的是 stderr；",
            "    部分客户端只把 stderr 写进日志，请同时取用生成的配置文件。",
            "  · 报告目录默认 ./jsfind-mcp-report（相对客户端工作目录），",
            "    建议在配置里改成绝对路径。",
        ]
    lines.append("=" * 72)
    return "\n".join(lines)


def write_configs(spec: ServerSpec, directory: str | Path) -> list[Path]:
    """Write paste-ready config files into ``directory``.

    Written as well as printed because a stdio client usually captures stderr
    into its own log where the operator will not see it; the file is the copy
    that actually reaches them.
    """
    base = Path(directory)
    base.mkdir(parents=True, exist_ok=True)

    configs = client_configs(spec)
    title = _REMOTE_TITLE if spec.is_remote else \
        f"{_UNIVERSAL_TITLE}（本地 stdio）"
    written: list[Path] = []

    json_path = base / "mcp.json"
    json_path.write_text(
        json.dumps(configs[title], ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    written.append(json_path)

    readme = base / "MCP-CONFIG.md"
    readme.write_text(_render_markdown(spec), encoding="utf-8")
    written.append(readme)
    return written


def _render_markdown(spec: ServerSpec) -> str:
    """A cheat sheet covering every supported client shape."""
    parts = [
        "# jsfind-mcp MCP 客户端配置",
        "",
        "本文件由 `jsfind-mcp-server` 启动时自动生成，"
        "其中的命令与参数即当前运行实例的真实启动方式。",
        "",
        f"- 启动方式：{_mode_label(spec.mode)}",
        f"- 传输方式：{spec.transport}",
    ]
    if spec.is_remote:
        parts.append(f"- 服务地址：{spec.url}")
    parts += [
        "",
        "## 通用配置",
        "",
        "合并进客户端的 MCP 设置文件（Claude Desktop / Cursor / CodeBuddy / "
        "VS Code / Windsurf 均为此结构）：",
        "",
        "```json",
        json.dumps(next(iter(client_configs(spec).values())),
                   ensure_ascii=False, indent=2),
        "```",
        "",
        "## Claude Code",
        "",
        "```bash",
        claude_code_command(spec),
        "```",
    ]
    if not spec.is_remote:
        parts += [
            "",
            "## 排查",
            "",
            "- stdio 传输下 stdout 被 JSON-RPC 协议占用，"
            "不要在该配置里附加任何输出重定向。",
            "- 报告目录默认 `./jsfind-mcp-report`，"
            "相对客户端工作目录，建议改成绝对路径。",
        ]
    parts.append("")
    return "\n".join(parts)


def announce(spec: ServerSpec, directory: str | Path | None = None) -> None:
    """Emit the config to stderr and, when possible, to disk.

    stdout is deliberately untouched: under stdio it carries the protocol.
    """
    print(render(spec), file=sys.stderr, flush=True)
    if directory is None:
        return
    try:
        written = write_configs(spec, directory)
    except OSError as exc:
        print(f"jsfind-mcp: 无法写入 MCP 配置文件: {exc}", file=sys.stderr, flush=True)
        return
    for path in written:
        print(f"jsfind-mcp: 已生成 MCP 配置文件 {path}", file=sys.stderr, flush=True)
