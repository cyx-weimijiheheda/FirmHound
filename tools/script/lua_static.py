"""Static analysis for Lua sources and bytecode in router firmwares.

Modern vendor web stacks move their request handling out of ELF binaries and into
Lua: GL.iNet ships ``nginx`` + ``ngx_lua``, the RPC and auth decision live in
``oui-rpc.lua`` / ``oui-access.lua``, and the CGI shim only forwards JSON. A
firmware pipeline that only reads ELF files is blind to most of that attack
surface, which is exactly what happened on GL.iNet MT3000: ``uhttpd`` and
``nginx`` produced zero candidates while every authorization decision sat in Lua.

This module recovers, per Lua unit, the same shape the ELF triage produces
(``sources`` / ``sinks`` / ``validation_functions`` / ``functions``) so the
existing source-sink rules and candidate generator apply unchanged.

Scope is deliberately narrow and honest:

* Only *text* Lua is parsed. Compiled chunks (``Lua bytecode`` / ``luac``
  output) are recorded with ``status="bytecode"`` and skipped — decompiling them
  is a separate problem and guessing at their contents would be fabrication.
* Function boundaries come from a brace/``end`` depth scan, not a full grammar.
  That is enough to attribute ``os.execute`` to the enclosing function and to
  list the calls it makes; it is not presented as a control-flow graph.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from tools.analysis.source_sink_rules import classify_sink, classify_source

#: Lua chunk magic: 0x1B "Lua" — either source-mode dump or precompiled.
_BYTECODE_MAGIC = b"\x1bLua"

#: ``function [a.b:]name(...)`` / ``local function name(...)``
_FUNC_DEF = re.compile(
    r"^\s*(?P<local>local\s+)?function\s+(?P<name>[A-Za-z_][\w.:]*)\s*\((?P<params>[^)]*)\)",
)
#: ``name = function(...)`` (module field assignment style)
_FUNC_ASSIGN = re.compile(
    r"^\s*(?P<name>[A-Za-z_][\w.:]*)\s*=\s*function\s*\((?P<params>[^)]*)\)",
)
#: ``require 'mod'`` / ``require("mod")``
_REQUIRE = re.compile(r"require\s*\(?\s*['\"]([^'\"]+)['\"]")

#: Lua-side sinks that are not in the C sink table but matter just as much.
_LUA_EXTRA_SINKS: dict[str, str] = {
    "os.execute": "command_execution",
    "io.popen": "command_execution",
    "os.remove": "filesystem",
    "os.rename": "filesystem",
    "io.open": "filesystem",
    "load": "code_eval",
    "loadstring": "code_eval",
    "dofile": "code_eval",
    "require": "code_eval",  # kept separate; only counted when the path is dynamic
    "setfenv": "code_eval",
}

#: Lua arguments that carry attacker-controlled HTTP data.
_LUA_HTTP_SOURCES: tuple[tuple[str, str], ...] = (
    ("ngx.var.arg_", "http_query"),
    ("ngx.var.http_", "http_header"),
    ("ngx.var.cookie_", "http_cookie"),
    ("ngx.var.request_body", "http_param"),
    ("ngx.var.uri", "http_param"),
    ("ngx.req.get_uri_args", "http_query"),
    ("ngx.req.get_post_args", "http_param"),
    ("ngx.req.get_headers", "http_header"),
    ("ngx.req.read_body", "http_param"),
    ("ngx.req.get_body_data", "http_param"),
)

#: Validation idioms that count as sanitising an input before it reaches a sink.
_LUA_VALIDATIONS: tuple[tuple[str, str], ...] = (
    ("tonumber", "type_limit"),
    ("math.floor", "type_limit"),
    ("%d", "type_limit"),
    ("string.match", "whitelist"),
    (":match(", "whitelist"),
    ("string.gsub", "escape"),
    ("tostring", "type_limit"),
)


def _read_text(path: Path) -> str | None:
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if raw.startswith(_BYTECODE_MAGIC):
        return None
    try:
        return raw.decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001 - undecodable chunks degrade, never crash
        return None


def is_lua_bytecode(path: Path) -> bool:
    """Return True when the file is a compiled Lua chunk."""
    try:
        return path.read_bytes()[:4] == _BYTECODE_MAGIC
    except OSError:
        return False


_BLOCK_OPENER = re.compile(r"\b(function|if|for|while|do|repeat)\b")
#: ``for ... do`` / ``while ... do`` open ONE block, but both keywords match
#: ``_BLOCK_OPENER``, so the trailing ``do`` of those constructs must not be
#: counted a second time. Missing this made every function swallow the rest of
#: the file (oui-download.lua reported one 134-line function instead of 8).
_LOOP_DO = re.compile(r"\b(?:for|while)\b[^\n]*?\bdo\b")


def _block_delta(line: str) -> int:
    """Net block depth change contributed by one Lua source line."""
    opens = len(_BLOCK_OPENER.findall(line))
    opens -= len(_LOOP_DO.findall(line))
    closes = len(re.findall(r"\bend\b", line)) + len(re.findall(r"\buntil\b", line))
    # ``elseif`` re-opens after ``if`` already closed it; not a new block.
    opens -= len(re.findall(r"\belseif\b", line))
    return opens - closes


def _function_blocks(lines: list[str]) -> list[dict[str, Any]]:
    """Split Lua source into top-level named function blocks by ``end`` depth.

    Returns blocks with ``name``, ``params``, ``start_line``, ``body``. Anything
    outside a named function (top-level module code) is returned as a synthetic
    ``<chunk>`` block so its sinks are still attributed somewhere honest.
    """
    blocks: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    depth = 0

    for idx, line in enumerate(lines, start=1):
        match = _FUNC_DEF.match(line) or _FUNC_ASSIGN.match(line)
        if match and current is None:
            current = {
                "name": match.group("name"),
                "params": [
                    p.strip() for p in (match.group("params") or "").split(",") if p.strip()
                ],
                "start_line": idx,
                "lines": [],
            }
            depth = 0
        if current is not None:
            current["lines"].append(line)
            depth += _block_delta(line)
            if depth <= 0 and idx > current["start_line"]:
                blocks.append(current)
                current = None
                depth = 0
        else:
            blocks.append(
                {"name": f"<chunk:{idx}>", "params": [], "lines": [line], "start_line": idx}
            )

    if current is not None:
        blocks.append(current)
    return blocks


def _lua_sinks(body: str) -> list[dict[str, str]]:
    """Sinks reachable from a Lua function body."""
    found: list[dict[str, str]] = []
    seen: set[str] = set()
    for api, category in _LUA_EXTRA_SINKS.items():
        if api not in seen and re.search(rf"(?<![\w.]){re.escape(api)}\s*\(", body):
            seen.add(api)
            found.append({"function": api, "type": category})
    # C-library sinks called through Lua (``string.rep``, or a module binding).
    for token in re.findall(r"\b([A-Za-z_][\w.]*)\s*\(", body):
        classified = classify_sink(token)
        if classified and classified["function"] not in seen:
            seen.add(classified["function"])
            found.append(classified)
    return found


def _lua_sources(body: str) -> list[dict[str, Any]]:
    """HTTP/network sources read by a Lua function body."""
    found: list[dict[str, Any]] = []
    seen: set[str] = set()
    for pattern, kind in _LUA_HTTP_SOURCES:
        if pattern in body and pattern not in seen:
            seen.add(pattern)
            found.append({"string": pattern, "type": kind, "name": kind})
    # ``ubus.call("obj", "method")`` carries RPC parameters from the caller.
    if re.search(r"\bubus\.call\s*\(", body) and "ubus.call" not in seen:
        seen.add("ubus.call")
        found.append({"api": "ubus.call", "type": "socket_buffer", "name": "socket_buffer"})
    for token in re.findall(r"\b([A-Za-z_][\w.]*)\s*\(", body):
        classified = classify_source(token)
        if classified and classified.get("api") not in seen:
            key = str(classified.get("api"))
            if key in seen:
                continue
            seen.add(key)
            found.append({"api": token, **classified})
    return found


def _lua_validations(body: str) -> list[dict[str, str]]:
    return [{"api": api, "kind": kind} for api, kind in _LUA_VALIDATIONS if api in body]


def analyze_lua_file(rootfs: Path, relative: str) -> dict[str, Any] | None:
    """Summarize one Lua unit, or return None when it cannot be read as source."""
    path = rootfs / relative
    text = _read_text(path)
    if text is None:
        if is_lua_bytecode(path):
            return {
                "path": relative,
                "status": "bytecode",
                "limitation": "compiled Lua chunk; source-level analysis not attempted",
            }
        return None

    lines = text.splitlines()
    blocks = _function_blocks(lines)

    functions: list[dict[str, Any]] = []
    all_sources: list[dict[str, Any]] = []
    all_sinks: list[dict[str, Any]] = []
    seen_source: set[tuple[str, str]] = set()
    seen_sink: set[tuple[str, str]] = set()

    for block in blocks:
        name = block["name"]
        # Top-level lines become ``<chunk:N>`` blocks. They are kept: a module may
        # open a file or spawn a process before defining any function
        # (``oui-rpc.lua`` reads the request body at module scope), and dropping
        # them hid those call sites from chain attribution.
        body = "\n".join(block["lines"])
        calls = sorted(set(re.findall(r"\b([A-Za-z_][\w.:]*)\s*\(", body)))
        functions.append(
            {
                "name": name,
                "addr": f"lua:{block['start_line']}",
                "callees": calls,
                "strings": block["params"],
            }
        )
        for item in _lua_sources(body):
            key = (str(item.get("type")), str(item.get("api") or item.get("string")))
            if key not in seen_source:
                seen_source.add(key)
                all_sources.append(item)
        for item in _lua_sinks(body):
            key = (str(item.get("function")), str(item.get("type")))
            if key not in seen_sink:
                seen_sink.add(key)
                all_sinks.append(item)

    requires = sorted(set(_REQUIRE.findall(text)))
    # ``match_binary`` reads signals from ``imports``/``exports``/``strings``.
    # Expose the Lua-level calls through those fields so the same source/sink
    # rules and candidate generator apply without a Lua-specific fork.
    call_names = sorted(
        {
            token
            for block in blocks
            for token in re.findall(r"\b([A-Za-z_][\w.:]*)\s*\(", "\n".join(block["lines"]))
        }
    )
    return {
        "path": relative,
        "status": "ok",
        "modules": requires,
        "functions": functions,
        "sources": all_sources,
        "sinks": all_sinks,
        "validations": _lua_validations(text),
        "line_count": len(lines),
        "imports": call_names,
        "exports": [block["name"] for block in blocks if not block["name"].startswith("<chunk:")],
        "string_sample": [],
    }


def iter_lua_paths(rootfs: Path) -> list[str]:
    """Rootfs-relative Lua sources, sorted for reproducible runs."""
    out: list[str] = []
    for path in rootfs.rglob("*"):
        if path.suffix != ".lua" or not path.is_file():
            continue
        out.append(path.relative_to(rootfs).as_posix())
    return sorted(out)


__all__ = [
    "analyze_lua_file",
    "is_lua_bytecode",
    "iter_lua_paths",
]
