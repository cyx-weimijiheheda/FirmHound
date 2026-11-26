"""Tests for Lua source analysis and nginx Lua route recovery."""

from __future__ import annotations

from pathlib import Path

from tools.script.lua_static import analyze_lua_file, is_lua_bytecode, iter_lua_paths
from tools.web.nginx_lua_routes import parse_nginx_lua_routes


def _write(root: Path, relative: str, text: str) -> None:
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


def test_lua_sources_and_sinks_are_recovered(tmp_path: Path) -> None:
    """ngx_lua request reads and shell sinks must be attributed to a function."""
    _write(
        tmp_path,
        "usr/share/gl-ngx/handler.lua",
        """
local cjson = require 'cjson'

local function run_cmd()
    local args = ngx.req.get_uri_args()
    os.execute("echo " .. (args.cmd or ""))
    return true
end

local function safe_reader()
    local body = ngx.req.get_body_data()
    return body
end
""",
    )

    result = analyze_lua_file(tmp_path, "usr/share/gl-ngx/handler.lua")
    assert result is not None
    assert result["status"] == "ok"

    source_types = {item["type"] for item in result["sources"]}
    assert "http_query" in source_types
    assert "http_param" in source_types

    sink_functions = {item["function"] for item in result["sinks"]}
    assert "os.execute" in sink_functions

    names = {func["name"] for func in result["functions"]}
    assert "run_cmd" in names
    assert "safe_reader" in names


def test_lua_bytecode_is_reported_not_guessed(tmp_path: Path) -> None:
    """A compiled chunk is recorded as skipped instead of being fabricated."""
    chunk = tmp_path / "compiled.lua"
    chunk.write_bytes(b"\x1bLuaS\x00\x19\x93\r\n\x1a\n" + b"\x00" * 32)

    assert is_lua_bytecode(chunk) is True
    result = analyze_lua_file(tmp_path, "compiled.lua")
    assert result is not None
    assert result["status"] == "bytecode"
    assert "limitation" in result


def test_iter_lua_paths_is_sorted_and_lua_only(tmp_path: Path) -> None:
    _write(tmp_path, "b.lua", "return 1\n")
    _write(tmp_path, "a.lua", "return 2\n")
    _write(tmp_path, "ignore.txt", "nope\n")

    assert iter_lua_paths(tmp_path) == ["a.lua", "b.lua"]


def test_nginx_lua_routes_bind_handler_and_gate(tmp_path: Path) -> None:
    """``content_by_lua_file`` gives the handler, ``access_by_lua_file`` the gate."""
    _write(
        tmp_path,
        "etc/nginx/conf.d/gl.conf",
        """
server {
    location = /rpc {
        access_by_lua_file /usr/share/gl-ngx/oui-access.lua;
        content_by_lua_file /usr/share/gl-ngx/oui-rpc.lua;
    }

    location = /open {
        content_by_lua_file /usr/share/gl-ngx/portal.lua;
    }

    location /cgi-bin/ {
        access_by_lua_file /usr/share/gl-ngx/oui-access.lua;
        fastcgi_pass unix:/var/run/fcgiwrap.socket;
    }
}
""",
    )

    routes = {item["route"]: item for item in parse_nginx_lua_routes(tmp_path)}

    assert routes["/rpc"]["handler"] == "usr/share/gl-ngx/oui-rpc.lua"
    assert routes["/rpc"]["access_gate"] == ["usr/share/gl-ngx/oui-access.lua"]

    assert routes["/open"]["handler"] == "usr/share/gl-ngx/portal.lua"
    assert routes["/open"]["access_gate"] == []

    # A fastcgi-only location has no Lua handler and must not be claimed as one.
    assert "/cgi-bin/" not in routes or not routes["/cgi-bin/"]["handler"]


def test_lua_function_blocks_respect_loop_do(tmp_path: Path) -> None:
    """``for ... do`` opens one block, not two.

    Regression: counting both ``for`` and its trailing ``do`` inflated depth, so
    ``path_is_allowed`` in ``oui-download.lua`` swallowed the rest of the file
    and every sink was attributed to the first function.
    """
    from tools.script.lua_static import _function_blocks

    source = """
local function first(a)
    for i = 1, 3 do
        if a == i then
            return true
        end
    end
    return false
end

local function second()
    os.execute("id")
end
""".strip().splitlines()

    blocks = {b["name"]: b for b in _function_blocks(source) if not b["name"].startswith("<chunk")}
    assert set(blocks) == {"first", "second"}
    assert len(blocks["first"]["lines"]) == 8
    assert len(blocks["second"]["lines"]) == 3
    assert not any("os.execute" in line for line in blocks["first"]["lines"])


def test_lua_candidate_gets_source_backed_call_chain() -> None:
    """A Lua candidate is upgraded when an enclosing function calls the sink."""
    from tools.audit.static import _enrich_with_lua_chain

    summary = {
        "language": "lua",
        "path": "usr/share/gl-ngx/oui-ws.lua",
        "functions": [
            {
                "name": "on_subscribe",
                "addr": "lua:69",
                "callees": ["dofile", "fs.access", "cjson.encode"],
                "strings": ["name", "mod", "ev"],
            }
        ],
    }
    candidate = {
        "sink": {"function": "dofile", "type": "command_execution"},
        "source": {"string": "ngx.req.get_uri_args", "type": "http_param"},
        "entry": {"handler": "oui-ws.lua", "route": "/ws"},
        "counterevidence": ["call-chain-not-proven"],
        "decisive_missing_fact": "source-to-sink data-flow and call-chain reachability",
    }

    assert _enrich_with_lua_chain(candidate, summary) is True
    chain = candidate["call_chain"]
    assert len(chain) == 2
    assert chain[0]["func"] == "on_subscribe"
    assert chain[1]["func"] == "dofile"
    assert "call-chain-not-proven" not in candidate["counterevidence"]


def test_lua_candidate_without_enclosing_caller_stays_unproven() -> None:
    """No proved chain means the honest counter-evidence stays in place."""
    from tools.audit.static import _enrich_with_lua_chain

    summary = {
        "language": "lua",
        "functions": [{"name": "unrelated", "addr": "lua:9", "callees": ["print"]}],
    }
    candidate = {
        "sink": {"function": "dofile", "type": "command_execution"},
        "source": {"string": "ngx.req.get_uri_args", "type": "http_param"},
        "entry": {},
        "counterevidence": ["call-chain-not-proven"],
    }

    assert _enrich_with_lua_chain(candidate, summary) is False
    assert "call-chain-not-proven" in candidate["counterevidence"]
    assert not candidate.get("call_chain")
